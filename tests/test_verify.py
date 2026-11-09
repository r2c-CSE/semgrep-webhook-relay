from __future__ import annotations

from conftest import SECRET, semgrep_body, sign

from semgrep_relay.verify import BodyHmacSha256Verifier, SignatureChecker

BODY = semgrep_body([{"text": "Test Notification", "username": "Semgrep"}])


def checker(*secrets: str) -> SignatureChecker:
    return SignatureChecker([BodyHmacSha256Verifier(list(secrets))])


def test_accepts_valid_signature_with_any_header_casing() -> None:
    result = checker(SECRET).check({"X-Semgrep-Signature-256": sign(BODY)}, BODY)
    assert result.ok
    assert result.scheme == "hmac-sha256-body"


def test_rejects_signature_for_different_body() -> None:
    result = checker(SECRET).check({"x-semgrep-signature-256": sign(BODY)}, BODY + b" ")
    assert not result.ok
    assert result.reason == "signature mismatch"


def test_rejects_missing_signature() -> None:
    result = checker(SECRET).check({}, BODY)
    assert not result.ok
    assert result.reason == "missing signature"


def test_accepts_any_configured_secret_during_rotation() -> None:
    old, new = "old-secret-0123456789", "new-secret-0123456789"
    result = checker(new, old).check({"x-semgrep-signature-256": sign(BODY, old)}, BODY)
    assert result.ok


def test_no_verifiers_accepts_everything() -> None:
    unsigned = SignatureChecker([])
    assert not unsigned.enabled
    assert unsigned.check({}, BODY).ok
