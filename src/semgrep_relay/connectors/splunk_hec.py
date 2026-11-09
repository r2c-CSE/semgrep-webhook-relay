"""Splunk HTTP Event Collector (HEC).

Sends each event as one HEC event, with the envelope as the event body and
``occurred_at`` (or, optionally, ``received_at``) as the event time. Works for
Splunk Enterprise and Splunk Cloud.
"""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field

from semgrep_relay.connectors.base import (
    Connector,
    ConnectorOptions,
    DeliveryResult,
    OutboundRequest,
    tls_client_kwargs,
)
from semgrep_relay.envelope import Envelope

_EVENT_PATH = "/services/collector/event"


class SplunkHecOptions(ConnectorOptions):
    # Either the HEC base URL (https://splunk.example.com:8088) or the full
    # event endpoint (.../services/collector/event).
    url: str = Field(pattern=r"^https?://")
    token: str = Field(min_length=1)
    index: str | None = None
    source: str = "semgrep-webhook-relay"
    sourcetype: str = "semgrep:event"
    host: str | None = None
    # Index events by when they happened ("occurred") or when the relay got
    # them ("received"). "received" keeps late notifications in recent searches.
    timestamp: Literal["occurred", "received"] = "occurred"
    # Include Semgrep's original payload under ``raw``.
    include_raw: bool = True
    verify_tls: bool = True
    ca_bundle: str | None = None


def event_endpoint(url: str) -> str:
    stripped = url.rstrip("/")
    if "/services/collector" in urlsplit(stripped).path:
        return stripped
    return stripped + _EVENT_PATH


class SplunkHecConnector(Connector):
    type_name = "splunk_hec"
    options_model = SplunkHecOptions
    options: SplunkHecOptions

    def client_kwargs(self) -> dict[str, Any]:
        return tls_client_kwargs(self.options.verify_tls, self.options.ca_bundle)

    def build_request(self, envelope: Envelope) -> OutboundRequest:
        opts = self.options
        exclude = None if opts.include_raw else {"raw"}
        event_time = envelope.received_at if opts.timestamp == "received" else envelope.occurred_at
        hec_event: dict[str, Any] = {
            "time": round(event_time.timestamp(), 3),
            "source": opts.source,
            "sourcetype": opts.sourcetype,
            "event": envelope.model_dump(mode="json", exclude=exclude),
        }
        if opts.index:
            hec_event["index"] = opts.index
        if opts.host:
            hec_event["host"] = opts.host
        return OutboundRequest(
            url=event_endpoint(opts.url),
            headers={"Authorization": f"Splunk {opts.token}"},
            json=hec_event,
        )

    def classify(self, response: httpx.Response) -> DeliveryResult:
        result = super().classify(response)
        if result.ok:
            return result
        # HEC explains failures in {"text": ..., "code": ...}, e.g. "Invalid token".
        try:
            body = response.json()
        except ValueError:
            return result
        if isinstance(body, dict) and isinstance(body.get("text"), str):
            detail = f"{result.detail}: {body['text']}"
            return DeliveryResult(
                ok=False,
                retryable=result.retryable,
                detail=detail,
                retry_after=result.retry_after,
            )
        return result
