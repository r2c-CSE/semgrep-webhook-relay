"""The connector interface.

A connector turns an ``Envelope`` into one request for one destination and
says whether a failure is worth retrying. The relay owns everything else:
queueing, retries, backoff, and dead-lettering.
"""

from __future__ import annotations

import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from fnmatch import fnmatchcase
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel, ConfigDict

from semgrep_relay.envelope import Envelope

_RETRYABLE_STATUS = frozenset({408, 425, 429})


@dataclass(frozen=True)
class OutboundRequest:
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    json: Any = None
    content: bytes | None = None


@dataclass(frozen=True)
class DeliveryResult:
    ok: bool
    retryable: bool = False
    detail: str | None = None
    # Seconds the destination asked us to wait, from a Retry-After header.
    retry_after: float | None = None
    # The ID of the record created in the destination, when it returns one.
    # Reserved for stateful connectors; see ``Connector.stateful``.
    external_id: str | None = None


class ConnectorOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Connector(ABC):
    type_name: ClassVar[str]
    options_model: ClassVar[type[ConnectorOptions]]
    # Kind globs this connector can render. Routes to it skip other kinds.
    accepts: ClassVar[tuple[str, ...]] = ("*",)
    # Whether the connector keeps state about what it created in the
    # destination (to update or close it later). Every v1 connector is
    # stateless; a ticketing connector that syncs status would not be.
    stateful: ClassVar[bool] = False

    def __init__(self, name: str, options: ConnectorOptions) -> None:
        self.name = name
        self.options = options

    def accepts_kind(self, kind: str) -> bool:
        return any(fnmatchcase(kind, pattern) for pattern in self.accepts)

    def client_kwargs(self) -> dict[str, Any]:
        """Extra ``httpx.AsyncClient`` arguments, e.g. TLS settings."""
        return {}

    @abstractmethod
    def build_request(self, envelope: Envelope) -> OutboundRequest:
        """Format the envelope for the destination. Must not do any I/O."""

    def classify(self, response: httpx.Response) -> DeliveryResult:
        if response.is_success:
            return DeliveryResult(ok=True)
        retryable = response.status_code in _RETRYABLE_STATUS or response.status_code >= 500
        return DeliveryResult(
            ok=False,
            retryable=retryable,
            detail=f"HTTP {response.status_code}",
            retry_after=retry_after_seconds(response),
        )

    async def deliver(self, envelope: Envelope, client: httpx.AsyncClient) -> DeliveryResult:
        request = self.build_request(envelope)
        try:
            response = await client.request(
                request.method,
                request.url,
                headers=request.headers,
                json=request.json,
                content=request.content,
            )
        except httpx.TimeoutException:
            return DeliveryResult(ok=False, retryable=True, detail="request timed out")
        except httpx.TransportError as exc:
            return DeliveryResult(
                ok=False, retryable=True, detail=f"connection failed: {type(exc).__name__}"
            )
        return self.classify(response)


def retry_after_seconds(response: httpx.Response) -> float | None:
    """Seconds from a Retry-After header, in either delta-seconds or HTTP-date form."""
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=UTC)
    return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())


def tls_client_kwargs(verify_tls: bool, ca_bundle: str | None) -> dict[str, Any]:
    if ca_bundle:
        return {"verify": ssl.create_default_context(cafile=ca_bundle)}
    return {"verify": verify_tls}
