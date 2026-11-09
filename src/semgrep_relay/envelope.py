"""The normalized event every connector receives.

Semgrep sends several payload shapes, most of them unversioned. Decoders turn
each one into an ``Envelope`` so connectors never parse raw Semgrep payloads.
The original item is kept in ``raw`` for destinations that want everything.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ENVELOPE_VERSION = 1

Severity = Literal["critical", "high", "medium", "low", "info"]

# Ordered from most to least severe, so the index doubles as a rank.
SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

# Where ``event_id`` came from:
# - "semgrep": an ID Semgrep sent in a header (not sent by Semgrep yet).
# - "derived": built from stable IDs in the payload.
# - "content_hash": a hash of the item, used when it has no stable IDs.
EventIdSource = Literal["semgrep", "derived", "content_hash"]

# Where ``occurred_at`` came from: a time in the payload, or the relay's receive time.
OccurredAtSource = Literal["payload", "received"]


def severity_rank(severity: Severity | None) -> int:
    """Lower is more severe; events without a severity rank last."""
    if severity is None:
        return len(SEVERITY_ORDER)
    return SEVERITY_ORDER.index(severity)


class Envelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    envelope_version: int = ENVELOPE_VERSION

    # Identity. ``event_id`` names the event, so duplicates of it share the ID.
    # ``delivery_id`` names the inbound request, so every request has its own.
    event_id: str
    event_id_source: EventIdSource
    delivery_id: str

    # ``received_at`` is when the relay accepted the request. ``occurred_at`` is
    # the payload's own time when it has one, otherwise ``received_at``.
    received_at: datetime
    occurred_at: datetime
    occurred_at_source: OccurredAtSource

    # ``kind`` is "<subject>.<action>", e.g. "finding.created". Splitting the
    # verb out lets future lifecycle events ("finding.closed") reuse routing.
    kind: str
    subject: str
    action: str
    schema_version: int | None = None

    deployment_id: int | None = None
    repository: str | None = None
    severity: Severity | None = None

    # Human-oriented fields for chat-style destinations.
    title: str
    summary: str | None = None
    url: str | None = None
    highlights: dict[str, str] = Field(default_factory=dict)

    # Normalized, kind-specific fields, and the untouched Semgrep item.
    data: dict[str, Any] = Field(default_factory=dict)
    raw: Any = None
