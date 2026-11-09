from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from conftest import envelopes, make_config

from semgrep_relay.config import DeliverySettings
from semgrep_relay.connectors import Connector, DeliveryResult
from semgrep_relay.connectors.base import ConnectorOptions, OutboundRequest
from semgrep_relay.envelope import Envelope
from semgrep_relay.store import Store
from semgrep_relay.worker import DeliveryWorker, backoff_seconds

FINDING = envelopes("finding")[0]


class Scripted(Connector):
    """Returns queued results in order; the last one repeats."""

    type_name = "scripted"
    options_model = ConnectorOptions

    def __init__(self, name: str, results: list[DeliveryResult]) -> None:
        super().__init__(name, ConnectorOptions())
        self.results = results
        self.calls = 0

    def build_request(self, envelope: Envelope) -> OutboundRequest:
        raise NotImplementedError

    async def deliver(self, envelope: Envelope, client: httpx.AsyncClient) -> DeliveryResult:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


async def run_until_settled(worker: DeliveryWorker, store: Store, rounds: int = 50) -> None:
    for _ in range(rounds):
        await worker.tick()
        await worker.drain()
        if store.status_counts()["pending"] == 0:
            return
        await asyncio.sleep(0.02)


def make_worker(tmp_path: Path, connector: Connector, max_attempts: int = 3):
    config = make_config(
        tmp_path,
        delivery={
            "max_attempts": max_attempts,
            "initial_backoff_seconds": 0.01,
            "max_backoff_seconds": 0.02,
        },
    )
    store = Store(config.store.path)
    store.accept([(FINDING, [connector.name])])
    return DeliveryWorker(store, {connector.name: connector}, config.delivery, 30), store


@pytest.mark.anyio
async def test_retries_then_delivers(tmp_path: Path) -> None:
    connector = Scripted(
        "c", [DeliveryResult(ok=False, retryable=True, detail="HTTP 503"), DeliveryResult(ok=True)]
    )
    worker, store = make_worker(tmp_path, connector)
    await run_until_settled(worker, store)
    assert connector.calls == 2
    assert store.status_counts() == {"pending": 0, "delivered": 1, "dead": 0}


@pytest.mark.anyio
async def test_gives_up_after_max_attempts(tmp_path: Path) -> None:
    connector = Scripted("c", [DeliveryResult(ok=False, retryable=True, detail="HTTP 503")])
    worker, store = make_worker(tmp_path, connector, max_attempts=3)
    await run_until_settled(worker, store)
    assert connector.calls == 3
    assert store.status_counts()["dead"] == 1


@pytest.mark.anyio
async def test_permanent_failure_is_not_retried(tmp_path: Path) -> None:
    connector = Scripted("c", [DeliveryResult(ok=False, retryable=False, detail="HTTP 401")])
    worker, store = make_worker(tmp_path, connector)
    await run_until_settled(worker, store)
    assert connector.calls == 1
    assert store.status_counts()["dead"] == 1


@pytest.mark.anyio
async def test_connector_exception_is_retried(tmp_path: Path) -> None:
    class Broken(Scripted):
        async def deliver(self, envelope: Envelope, client: httpx.AsyncClient) -> DeliveryResult:
            self.calls += 1
            raise RuntimeError("bug")

    connector = Broken("c", [])
    worker, store = make_worker(tmp_path, connector, max_attempts=2)
    await run_until_settled(worker, store)
    assert connector.calls == 2
    assert store.status_counts()["dead"] == 1


@pytest.mark.anyio
async def test_removed_connector_is_dead_lettered(tmp_path: Path) -> None:
    worker, store = make_worker(tmp_path, Scripted("c", [DeliveryResult(ok=True)]))
    worker._connectors = {}
    await run_until_settled(worker, store)
    assert store.status_counts()["dead"] == 1


def test_backoff_grows_and_respects_limits() -> None:
    settings = DeliverySettings(initial_backoff_seconds=10, max_backoff_seconds=100)
    assert 8 <= backoff_seconds(1, settings, None) <= 12
    assert 32 <= backoff_seconds(3, settings, None) <= 48
    assert backoff_seconds(10, settings, None) <= 120
    assert backoff_seconds(1, settings, retry_after=60) >= 60
    assert backoff_seconds(1, settings, retry_after=10_000) <= 120
