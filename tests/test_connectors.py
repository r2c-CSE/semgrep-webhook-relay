from __future__ import annotations

import json

import httpx
import pytest
from conftest import envelopes

from semgrep_relay.connectors.base import retry_after_seconds
from semgrep_relay.connectors.splunk_hec import (
    SplunkHecConnector,
    SplunkHecOptions,
    event_endpoint,
)
from semgrep_relay.connectors.stdout import StdoutConnector, StdoutOptions
from semgrep_relay.connectors.teams import TeamsConnector, TeamsOptions

FINDING = envelopes("finding")[0]
SCAN = envelopes("scan")[0]


def splunk(**options: object) -> SplunkHecConnector:
    return SplunkHecConnector(
        "splunk", SplunkHecOptions(url="https://splunk.example:8088", token="tok", **options)
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://splunk.example:8088", "https://splunk.example:8088/services/collector/event"),
        ("https://splunk.example:8088/", "https://splunk.example:8088/services/collector/event"),
        (
            "https://http-inputs-acme.splunkcloud.com/services/collector/event",
            "https://http-inputs-acme.splunkcloud.com/services/collector/event",
        ),
    ],
)
def test_splunk_endpoint(url: str, expected: str) -> None:
    assert event_endpoint(url) == expected


def test_splunk_request() -> None:
    request = splunk(index="security", host="relay-1").build_request(FINDING)
    assert request.url == "https://splunk.example:8088/services/collector/event"
    assert request.headers == {"Authorization": "Splunk tok"}
    body = request.json
    assert body["time"] == round(FINDING.occurred_at.timestamp(), 3)
    assert body["index"] == "security"
    assert body["host"] == "relay-1"
    assert body["sourcetype"] == "semgrep:event"
    assert body["event"]["kind"] == "finding.created"
    assert body["event"]["raw"]["semgrep_finding"]["numeric_id"] == 11301071
    json.dumps(body)  # must be serializable as-is


def test_splunk_can_index_by_receive_time() -> None:
    body = splunk(timestamp="received").build_request(FINDING).json
    assert body["time"] == round(FINDING.received_at.timestamp(), 3)


def test_splunk_can_omit_raw() -> None:
    body = splunk(include_raw=False).build_request(FINDING).json
    assert "raw" not in body["event"]


def test_splunk_classifies_failures() -> None:
    connector = splunk()
    bad_token = connector.classify(httpx.Response(403, json={"text": "Invalid token", "code": 4}))
    assert not bad_token.ok
    assert not bad_token.retryable
    assert bad_token.detail == "HTTP 403: Invalid token"

    busy = connector.classify(httpx.Response(503, json={"text": "Server is busy", "code": 9}))
    assert busy.retryable

    assert connector.classify(httpx.Response(200, json={"text": "Success", "code": 0})).ok


def test_teams_card() -> None:
    request = TeamsConnector("teams", TeamsOptions(url="https://example.webhook")).build_request(
        FINDING
    )
    attachment = request.json["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    title, summary, facts, footer = card["body"]
    assert title["text"] == FINDING.title
    assert title["color"] == "Attention"
    assert summary["text"] == FINDING.summary
    assert {"title": "Repository", "value": "owasp/juice-shop"} in facts["facts"]
    assert footer["text"].startswith("finding.created")
    assert card["actions"][0]["title"] == "View code change"
    assert card["actions"][0]["url"] == FINDING.url


def test_teams_card_without_link_or_summary() -> None:
    envelope = envelopes("test_notification")[0].model_copy(update={"summary": None})
    card = (
        TeamsConnector("t", TeamsOptions(url="https://example.webhook"))
        .build_request(envelope)
        .json["attachments"][0]["content"]
    )
    assert "actions" not in card
    assert len(card["body"]) == 2


def test_retry_after() -> None:
    assert retry_after_seconds(httpx.Response(429, headers={"retry-after": "30"})) == 30
    assert retry_after_seconds(httpx.Response(429)) is None
    past = "Wed, 21 Oct 2015 07:28:00 GMT"
    assert retry_after_seconds(httpx.Response(429, headers={"retry-after": past})) == 0


@pytest.mark.anyio
async def test_transport_errors_are_retryable() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(fail)) as client:
        result = await splunk().deliver(SCAN, client)
    assert not result.ok
    assert result.retryable
    assert result.detail == "connection failed: ConnectError"


@pytest.mark.anyio
async def test_stdout_writes_one_json_line(capsys: pytest.CaptureFixture[str]) -> None:
    async with httpx.AsyncClient() as client:
        result = await StdoutConnector("out", StdoutOptions()).deliver(FINDING, client)
    assert result.ok
    line = json.loads(capsys.readouterr().out)
    assert line["event_id"] == FINDING.event_id
    assert "raw" not in line
