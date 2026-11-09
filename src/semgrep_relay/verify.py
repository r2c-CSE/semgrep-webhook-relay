"""Signature verification for inbound Semgrep webhooks.

Semgrep signs the exact request body with HMAC-SHA256 and sends the hex digest
in ``X-Semgrep-Signature-256``. The signature covers only the body: there is no
timestamp, so a signature alone can't prove a request is fresh. The relay's
dedup store rejects repeats of events it has already seen.

Verifiers are pluggable so a future signature scheme (for example one that
signs a timestamp too) can be added beside this one and picked by header,
without changing the rest of the relay.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

SIGNATURE_HEADER = "x-semgrep-signature-256"


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    scheme: str
    reason: str | None = None


class Verifier(Protocol):
    scheme: str

    def applies(self, headers: Mapping[str, str]) -> bool:
        """Whether this verifier handles a request with these headers."""
        ...

    def verify(self, headers: Mapping[str, str], body: bytes) -> VerificationResult: ...


class BodyHmacSha256Verifier:
    """Semgrep's current scheme: hex HMAC-SHA256 over the raw body.

    Accepts several secrets so you can rotate the secret in Semgrep without
    dropping deliveries in between.
    """

    scheme = "hmac-sha256-body"

    def __init__(self, secrets: Sequence[str]) -> None:
        if not secrets:
            raise ValueError("At least one signing secret is required.")
        self._secrets = [s.encode("utf-8") for s in secrets]

    def applies(self, headers: Mapping[str, str]) -> bool:
        return SIGNATURE_HEADER in headers

    def verify(self, headers: Mapping[str, str], body: bytes) -> VerificationResult:
        provided = headers.get(SIGNATURE_HEADER, "").strip().lower()
        if not provided:
            return VerificationResult(False, self.scheme, "missing signature")
        for secret in self._secrets:
            expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
            if hmac.compare_digest(provided, expected):
                return VerificationResult(True, self.scheme)
        return VerificationResult(False, self.scheme, "signature mismatch")


class SignatureChecker:
    """Picks the first verifier whose header is present.

    With no verifiers configured, every request is accepted. The config layer
    only allows that when ``allow_unsigned`` is set explicitly.
    """

    def __init__(self, verifiers: Sequence[Verifier]) -> None:
        self._verifiers = list(verifiers)

    @property
    def enabled(self) -> bool:
        return bool(self._verifiers)

    def check(self, headers: Mapping[str, str], body: bytes) -> VerificationResult:
        if not self._verifiers:
            return VerificationResult(True, "none")
        lowered = {k.lower(): v for k, v in headers.items()}
        for verifier in self._verifiers:
            if verifier.applies(lowered):
                return verifier.verify(lowered, body)
        return VerificationResult(False, "none", "missing signature")
