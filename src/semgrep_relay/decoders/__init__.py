"""Turn a Semgrep webhook body into envelopes.

To support a new payload type, add a decoder module and register it in
``DECODERS`` ahead of ``UnknownDecoder``, which matches everything.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from semgrep_relay.decoders.base import DecodeContext, Decoded, Decoder
from semgrep_relay.decoders.finding import FindingDecoder
from semgrep_relay.decoders.malware_firewall import MalwareFirewallExceptionDecoder
from semgrep_relay.decoders.scan import ScanDecoder
from semgrep_relay.decoders.supply_chain_incident import SupplyChainIncidentDecoder
from semgrep_relay.decoders.system import SystemMessageDecoder
from semgrep_relay.decoders.unknown import UnknownDecoder
from semgrep_relay.decoders.workflow_issue import WorkflowIssueDecoder
from semgrep_relay.envelope import Envelope, EventIdSource

logger = logging.getLogger(__name__)

DECODERS: tuple[Decoder, ...] = (
    FindingDecoder(),
    ScanDecoder(),
    SupplyChainIncidentDecoder(),
    MalwareFirewallExceptionDecoder(),
    WorkflowIssueDecoder(),
    SystemMessageDecoder(),
    UnknownDecoder(),
)

__all__ = ["DECODERS", "DecodeContext", "Decoded", "decode_body", "resolve_event_id"]


def split_items(body: Any) -> list[Any]:
    """Semgrep sends most payloads as a list of items, but scans as one object."""
    return list(body) if isinstance(body, list) else [body]


def content_hash(item: Any) -> str:
    canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_event_id(
    *,
    kind: str,
    dedup_key: str | None,
    item: Any,
    upstream_event_id: str | None,
    index: int,
    batch_size: int,
) -> tuple[str, EventIdSource]:
    """Pick the event ID, preferring the most authoritative source available.

    Semgrep doesn't send an event ID today. If it starts to, pass it as
    ``upstream_event_id`` and it wins. A request can carry several items, so
    each item gets the upstream ID plus its position in that case.
    """
    if upstream_event_id:
        suffix = "" if batch_size == 1 else f":{index}"
        return f"{upstream_event_id}{suffix}", "semgrep"
    if dedup_key:
        return f"{kind}:{dedup_key}", "derived"
    return f"{kind}:sha256:{content_hash(item)}", "content_hash"


def _decode_item(item: Any, ctx: DecodeContext, kind_hint: str | None) -> Decoded:
    # ``kind_hint`` is reserved for an event-type header Semgrep may add later;
    # until then every item is detected from its shape.
    del kind_hint
    for decoder in DECODERS:
        if not decoder.matches(item):
            continue
        try:
            return decoder.decode(item, ctx)
        except Exception as exc:
            # A decoder bug must never lose the event: fall back to unknown.
            logger.warning(
                "decoder failed; routing as unknown",
                extra={"decoder": decoder.name, "error": type(exc).__name__},
            )
            break
    return UnknownDecoder().decode(item, ctx)


def _build_envelope(
    decoded: Decoded, item: Any, ctx: DecodeContext, upstream_event_id: str | None
) -> Envelope:
    event_id, event_id_source = resolve_event_id(
        kind=decoded.kind,
        dedup_key=decoded.dedup_key,
        item=item,
        upstream_event_id=upstream_event_id,
        index=ctx.index,
        batch_size=ctx.batch_size,
    )
    return Envelope(
        event_id=event_id,
        event_id_source=event_id_source,
        delivery_id=ctx.delivery_id,
        received_at=ctx.received_at,
        occurred_at=decoded.occurred_at or ctx.received_at,
        occurred_at_source="payload" if decoded.occurred_at else "received",
        kind=decoded.kind,
        subject=decoded.subject,
        action=decoded.action,
        schema_version=decoded.schema_version,
        deployment_id=decoded.deployment_id,
        repository=decoded.repository,
        severity=decoded.severity,
        title=decoded.title,
        summary=decoded.summary,
        url=decoded.url,
        highlights=decoded.highlights,
        data=decoded.data,
        raw=item,
    )


def decode_body(
    body: Any,
    *,
    delivery_id: str,
    received_at: datetime,
    upstream_event_id: str | None = None,
    kind_hint: str | None = None,
) -> list[Envelope]:
    items = split_items(body)
    envelopes = []
    for index, item in enumerate(items):
        ctx = DecodeContext(
            delivery_id=delivery_id,
            received_at=received_at,
            index=index,
            batch_size=len(items),
        )
        decoded = _decode_item(item, ctx, kind_hint)
        try:
            envelope = _build_envelope(decoded, item, ctx, upstream_event_id)
        except ValueError as exc:
            # A decoder returned something the envelope rejects; keep the event.
            logger.warning(
                "invalid decoder output; routing as unknown",
                extra={"kind": decoded.kind, "error": type(exc).__name__},
            )
            unknown = UnknownDecoder().decode(item, ctx)
            envelope = _build_envelope(unknown, item, ctx, upstream_event_id)
        envelopes.append(envelope)
    return envelopes
