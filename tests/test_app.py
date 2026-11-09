"""End to end: a signed Semgrep request in, a Splunk HEC request out."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import load_fixture, make_config, semgrep_body, sign
from starlette.testclient import TestClient

from semgrep_relay.app import Relay
from semgrep_relay.connectors.splunk_hec import SplunkHecConnector, SplunkHecOptions

PATH = "/webhooks/semgrep"


class RecordingSplunk(SplunkHecConnector):
    def __init__(self, status: int = 200) -> None:
        super().__init__("siem", SplunkHecOptions(url="https://splunk.example:8088", token="tok"))
        self.requests: list[httpx.Request] = []
        self.status = status
        self.received = threading.Event()

    def client_kwargs(self) -> dict[str, Any]:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            self.received.set()
            return httpx.Response(self.status, json={"text": "Success", "code": 0})

        return {"transport": httpx.MockTransport(handler)}


@pytest.fixture
def splunk() -> RecordingSplunk:
    return RecordingSplunk()


@pytest.fixture
def client(tmp_path: Path, splunk: RecordingSplunk):
    config = make_config(tmp_path, connectors={"siem": {"type": "stdout"}})
    relay = Relay(config, connectors={"siem": splunk})
    with TestClient(relay.asgi()) as test_client:
        yield test_client


def post(client: TestClient, payload: Any, signature: str | None = None) -> httpx.Response:
    body = semgrep_body(payload)
    headers = {"Content-Type": "application/json"}
    headers["X-Semgrep-Signature-256"] = signature if signature is not None else sign(body)
    return client.post(PATH, content=body, headers=headers)


def test_finding_is_relayed_to_splunk(client: TestClient, splunk: RecordingSplunk) -> None:
    response = post(client, load_fixture("finding"))
    assert response.status_code == 200
    assert response.json()["events"] == 1
    assert response.json()["deliveries"] == 1

    assert splunk.received.wait(timeout=5)
    [request] = splunk.requests
    assert request.headers["authorization"] == "Splunk tok"
    event = json.loads(request.content)["event"]
    assert event["kind"] == "finding.created"
    assert event["event_id"] == "finding.created:11301071"
    assert event["delivery_id"] == response.json()["delivery_id"]


def test_duplicate_finding_is_not_relayed_twice(
    client: TestClient, splunk: RecordingSplunk
) -> None:
    post(client, load_fixture("finding"))
    second = post(client, load_fixture("finding"))
    assert second.json() | {"delivery_id": None} == {
        "delivery_id": None,
        "events": 0,
        "duplicates": 1,
        "deliveries": 0,
    }
    assert splunk.received.wait(timeout=5)
    time.sleep(0.2)
    assert len(splunk.requests) == 1


def test_bad_signature_is_rejected(client: TestClient, splunk: RecordingSplunk) -> None:
    response = post(client, load_fixture("finding"), signature="0" * 64)
    assert response.status_code == 401
    assert response.json() == {"error": "Invalid or missing signature."}


def test_missing_signature_is_rejected(client: TestClient) -> None:
    body = semgrep_body(load_fixture("finding"))
    response = client.post(PATH, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 401


def test_non_json_body_is_rejected(client: TestClient) -> None:
    body = b"not json"
    response = client.post(PATH, content=body, headers={"X-Semgrep-Signature-256": sign(body)})
    assert response.status_code == 400


def test_oversized_body_is_rejected(tmp_path: Path, splunk: RecordingSplunk) -> None:
    config = make_config(tmp_path, server={"max_body_bytes": 64})
    with TestClient(Relay(config, connectors={"siem": splunk}).asgi()) as client:
        response = post(client, load_fixture("finding"))
    assert response.status_code == 413


def test_health_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz").json()
    assert ready["status"] == "ok"
    assert set(ready["deliveries"]) == {"pending", "delivered", "dead"}
