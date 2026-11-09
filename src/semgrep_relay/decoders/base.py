"""Shared types and helpers for payload decoders."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from semgrep_relay.envelope import Severity

SUMMARY_MAX_CHARS = 1000


@dataclass(frozen=True)
class DecodeContext:
    delivery_id: str
    received_at: datetime
    index: int
    batch_size: int


@dataclass
class Decoded:
    """What a decoder extracts from one Semgrep item.

    ``dedup_key`` is a short string of stable IDs that identifies the event, not
    the request. Leave it ``None`` when the item has no stable IDs; the relay
    then hashes the item's content instead.
    """

    subject: str
    action: str
    title: str
    dedup_key: str | None = None
    occurred_at: datetime | None = None
    schema_version: int | None = None
    deployment_id: int | None = None
    repository: str | None = None
    severity: Severity | None = None
    summary: str | None = None
    url: str | None = None
    highlights: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return f"{self.subject}.{self.action}"


class Decoder(Protocol):
    name: str

    def matches(self, item: Any) -> bool: ...

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded: ...


def parse_time(value: Any) -> datetime | None:
    """Parse Semgrep's timestamps. Naive values are UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


_SEVERITY_BY_INT: dict[int, Severity] = {0: "low", 1: "medium", 2: "high", 3: "critical"}
_SEVERITY_BY_NAME: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
}


def normalize_severity(value: Any) -> Severity | None:
    """Map Semgrep's integer and named severities onto one scale.

    Findings use integers (0 low to 3 critical) and older rules use ERROR,
    WARNING and INFO; Semgrep treats ERROR as high and WARNING as medium.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _SEVERITY_BY_INT.get(value)
    if isinstance(value, str):
        return _SEVERITY_BY_NAME.get(value.strip().lower())
    return None


def truncate(text: Any, limit: int = SUMMARY_MAX_CHARS) -> str | None:
    if not isinstance(text, str) or not text:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def wrapped(item: Any, key: str) -> dict[str, Any] | None:
    """Return ``item[key]`` when ``item`` is ``{key: {...}}``."""
    if isinstance(item, dict) and isinstance(item.get(key), dict):
        return item[key]
    return None


def compact(values: dict[str, str | None]) -> dict[str, str]:
    """Drop empty highlight values, keeping insertion order."""
    return {k: v for k, v in values.items() if v}
