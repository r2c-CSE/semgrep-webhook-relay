"""Fallback for payloads no other decoder recognizes.

Semgrep may add payload types at any time. Unrecognized items are still
accepted and routed as ``unknown.received`` rather than dropped, with the
original item in ``raw``.
"""

from __future__ import annotations

from typing import Any

from semgrep_relay.decoders.base import DecodeContext, Decoded


class UnknownDecoder:
    name = "unknown"

    def matches(self, item: Any) -> bool:
        return True

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        top_level_keys = sorted(item) if isinstance(item, dict) else []
        return Decoded(
            subject="unknown",
            action="received",
            title="Unrecognized Semgrep webhook payload",
            data={"top_level_keys": top_level_keys},
        )
