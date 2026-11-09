"""Deliver queued events to connectors, with retries.

Delivery is at-least-once: a crash between a successful send and recording it
re-sends that event after restart.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from collections.abc import Mapping

import httpx

from semgrep_relay.config import DeliverySettings
from semgrep_relay.connectors import Connector, DeliveryResult
from semgrep_relay.store import DeliveryJob, Store

logger = logging.getLogger(__name__)

PRUNE_INTERVAL_SECONDS = 3600.0


def backoff_seconds(attempts: int, settings: DeliverySettings, retry_after: float | None) -> float:
    """Exponential backoff with jitter, never sooner than the destination asked."""
    base = settings.initial_backoff_seconds * (2 ** max(attempts - 1, 0))
    delay = min(settings.max_backoff_seconds, base) * random.uniform(0.8, 1.2)  # noqa: S311
    if retry_after is not None:
        delay = max(delay, min(retry_after, settings.max_backoff_seconds))
    return delay


class DeliveryWorker:
    def __init__(
        self,
        store: Store,
        connectors: Mapping[str, Connector],
        settings: DeliverySettings,
        retention_days: int,
    ) -> None:
        self._store = store
        self._connectors = connectors
        self._settings = settings
        self._retention_seconds = retention_days * 86400
        self._wake = asyncio.Event()
        self._in_flight: dict[int, asyncio.Task[None]] = {}
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._last_prune = 0.0

    def notify(self) -> None:
        """Wake the worker now instead of at the next poll."""
        self._wake.set()

    def _client(self, connector: Connector) -> httpx.AsyncClient:
        client = self._clients.get(connector.name)
        if client is None:
            client = httpx.AsyncClient(
                timeout=self._settings.request_timeout_seconds,
                follow_redirects=False,
                **connector.client_kwargs(),
            )
            self._clients[connector.name] = client
        return client

    async def run(self, stop: asyncio.Event) -> None:
        try:
            while not stop.is_set():
                # Clear before looking for work so a notify() during tick() isn't lost.
                self._wake.clear()
                await self.tick()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._wait_for_wake_or_stop(stop), self._settings.poll_interval_seconds
                    )
        finally:
            if self._in_flight:
                await asyncio.gather(*self._in_flight.values(), return_exceptions=True)
            for client in self._clients.values():
                await client.aclose()

    async def _wait_for_wake_or_stop(self, stop: asyncio.Event) -> None:
        waiters = [asyncio.create_task(self._wake.wait()), asyncio.create_task(stop.wait())]
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()

    async def tick(self) -> None:
        """Start deliveries that are due, up to the concurrency limit."""
        await self._maybe_prune()
        slots = self._settings.concurrency - len(self._in_flight)
        if slots <= 0:
            return
        jobs = await asyncio.to_thread(self._store.due_deliveries, slots, list(self._in_flight))
        for job in jobs:
            task = asyncio.create_task(self._deliver(job))
            self._in_flight[job.id] = task
            task.add_done_callback(lambda _t, job_id=job.id: self._in_flight.pop(job_id, None))

    async def drain(self) -> None:
        """Wait for the deliveries started so far. Used by tests and the CLI."""
        if self._in_flight:
            await asyncio.gather(*self._in_flight.values(), return_exceptions=True)

    async def _deliver(self, job: DeliveryJob) -> None:
        attempts = job.attempts + 1
        log = {
            "event_id": job.event_id,
            "kind": job.envelope.kind,
            "connector": job.connector,
            "attempt": attempts,
        }
        connector = self._connectors.get(job.connector)
        if connector is None:
            await asyncio.to_thread(
                self._store.mark_dead, job.id, attempts, "connector is no longer configured"
            )
            logger.warning("delivery dead: connector removed", extra=log)
            return

        try:
            result = await connector.deliver(job.envelope, self._client(connector))
        except Exception as exc:
            # A connector bug shouldn't kill the worker; retry it like a failure.
            logger.exception("connector raised", extra=log)
            result = DeliveryResult(ok=False, retryable=True, detail=type(exc).__name__)

        if result.ok:
            await asyncio.to_thread(self._store.mark_delivered, job.id, attempts)
            logger.info("delivered", extra=log)
        elif result.retryable and attempts < self._settings.max_attempts:
            delay = backoff_seconds(attempts, self._settings, result.retry_after)
            await asyncio.to_thread(
                self._store.mark_retry, job.id, attempts, time.time() + delay, result.detail
            )
            logger.warning(
                "delivery failed; will retry",
                extra={**log, "detail": result.detail, "retry_in_seconds": round(delay, 1)},
            )
        else:
            await asyncio.to_thread(self._store.mark_dead, job.id, attempts, result.detail)
            logger.error("delivery dead", extra={**log, "detail": result.detail})

    async def _maybe_prune(self) -> None:
        now = time.time()
        if now - self._last_prune < PRUNE_INTERVAL_SECONDS:
            return
        self._last_prune = now
        pruned = await asyncio.to_thread(self._store.prune, now - self._retention_seconds)
        if pruned:
            logger.info("pruned old events", extra={"count": pruned})
