"""Plain ``{"text": ..., "username": "Semgrep"}`` messages.

Semgrep sends one of these when you click **Test** on a webhook integration, and
a similar one to report an internal failure.
"""

from __future__ import annotations

from typing import Any

from semgrep_relay.decoders.base import DecodeContext, Decoded, as_str, truncate

TEST_TEXT = "Test Notification"
_ALLOWED_KEYS = {"text", "username"}


class SystemMessageDecoder:
    name = "system_message"

    def matches(self, item: Any) -> bool:
        return (
            isinstance(item, dict)
            and isinstance(item.get("text"), str)
            and set(item) <= _ALLOWED_KEYS
        )

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        text = as_str(item.get("text")) or ""
        is_test = text == TEST_TEXT
        return Decoded(
            subject="semgrep",
            action="test" if is_test else "notice",
            # Every click of Test is its own event, so key on the request.
            dedup_key=f"{ctx.delivery_id}:{ctx.index}",
            title="Test notification from Semgrep" if is_test else "Message from Semgrep",
            summary=truncate(text),
            data={"text": text},
        )
