"""The HTTP side: accept Semgrep webhooks and hand them to the delivery worker."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from semgrep_relay.config import RelayConfig
from semgrep_relay.connectors import Connector, build_connectors
from semgrep_relay.decoders import decode_body
from semgrep_relay.router import Router
from semgrep_relay.store import Store
from semgrep_relay.verify import BodyHmacSha256Verifier, SignatureChecker
from semgrep_relay.worker import DeliveryWorker

logger = logging.getLogger(__name__)

# Semgrep doesn't send an event ID or event-type header yet. If it starts to,
# name the headers here and the relay will prefer them over what it derives.
UPSTREAM_EVENT_ID_HEADERS: tuple[str, ...] = ()
UPSTREAM_EVENT_TYPE_HEADERS: tuple[str, ...] = ()


class _BodyTooLarge(Exception):
    pass


def _first_header(headers: Mapping[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = headers.get(name)
        if value:
            return value
    return None


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise _BodyTooLarge
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise _BodyTooLarge
    return bytes(chunks)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class Relay:
    """Wires config, storage, routing and delivery together."""

    def __init__(
        self,
        config: RelayConfig,
        *,
        store: Store | None = None,
        connectors: Mapping[str, Connector] | None = None,
    ) -> None:
        self.config = config
        self.store = store or Store(config.store.path)
        self.connectors = (
            dict(connectors) if connectors is not None else build_connectors(config.connectors)
        )
        self.router = Router(config.routes, self.connectors)
        self.checker = SignatureChecker(
            [BodyHmacSha256Verifier(config.semgrep.signing_secrets)]
            if config.semgrep.signing_secrets
            else []
        )
        self.worker = DeliveryWorker(
            self.store, self.connectors, config.delivery, config.store.retention_days
        )

    async def receive(self, request: Request) -> JSONResponse:
        try:
            body = await _read_body(request, self.config.server.max_body_bytes)
        except _BodyTooLarge:
            return _error(413, "Request body is too large.")

        verification = self.checker.check(request.headers, body)
        if not verification.ok:
            logger.warning(
                "rejected request",
                extra={"reason": verification.reason, "scheme": verification.scheme},
            )
            return _error(401, "Invalid or missing signature.")

        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "Request body must be JSON.")

        delivery_id = str(uuid.uuid4())
        envelopes = decode_body(
            payload,
            delivery_id=delivery_id,
            received_at=datetime.now(UTC),
            upstream_event_id=_first_header(request.headers, UPSTREAM_EVENT_ID_HEADERS),
            kind_hint=_first_header(request.headers, UPSTREAM_EVENT_TYPE_HEADERS),
        )
        routed = [(envelope, self.router.targets(envelope)) for envelope in envelopes]
        try:
            result = await asyncio.to_thread(self.store.accept, routed)
        except Exception:
            logger.exception("could not store events", extra={"delivery_id": delivery_id})
            return _error(503, "The relay could not store this webhook.")
        self.worker.notify()

        logger.info(
            "accepted",
            extra={
                "delivery_id": delivery_id,
                "kinds": sorted({e.kind for e in envelopes}),
                "events": result.new_events,
                "duplicates": result.duplicate_events,
                "deliveries": result.deliveries_created,
                "signature": verification.scheme,
            },
        )
        return JSONResponse(
            {
                "delivery_id": delivery_id,
                "events": result.new_events,
                "duplicates": result.duplicate_events,
                "deliveries": result.deliveries_created,
            }
        )

    async def healthz(self, request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def readyz(self, request: Request) -> JSONResponse:
        try:
            counts = await asyncio.to_thread(self.store.status_counts)
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok", "deliveries": counts})

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        stop = asyncio.Event()
        task = asyncio.create_task(self.worker.run(stop))
        if not self.checker.enabled:
            logger.warning("signature verification is off (semgrep.allow_unsigned is true)")
        logger.info(
            "relay started",
            extra={"connectors": sorted(self.connectors), "routes": len(self.config.routes)},
        )
        try:
            yield
        finally:
            stop.set()
            await task
            self.store.close()

    def asgi(self) -> Starlette:
        return Starlette(
            routes=[
                Route(self.config.server.webhook_path, self.receive, methods=["POST"]),
                Route("/healthz", self.healthz, methods=["GET"]),
                Route("/readyz", self.readyz, methods=["GET"]),
            ],
            lifespan=self.lifespan,
        )


def create_app(config: RelayConfig) -> Starlette:
    return Relay(config).asgi()
