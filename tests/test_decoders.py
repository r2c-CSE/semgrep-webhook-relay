from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import RECEIVED_AT, envelopes, load_fixture

from semgrep_relay import decoders
from semgrep_relay.decoders import decode_body, resolve_event_id
from semgrep_relay.decoders.base import normalize_severity, parse_time


def decode(payload: Any, delivery_id: str = "d-1"):
    return decode_body(payload, delivery_id=delivery_id, received_at=RECEIVED_AT)


def test_finding() -> None:
    [env] = envelopes("finding")
    assert env.kind == "finding.created"
    assert env.event_id == "finding.created:11301071"
    assert env.event_id_source == "derived"
    assert env.severity == "high"
    assert env.repository == "owasp/juice-shop"
    assert env.occurred_at == datetime(2023, 2, 12, 0, 50, 21, 552606, tzinfo=UTC)
    assert env.occurred_at_source == "payload"
    assert env.url and env.url.startswith("https://github.com/owasp/juice-shop/commit/")
    assert env.highlights["Location"] == "data/static/codefixes/unionSqlInjectionChallenge_3.ts:10"
    assert env.data["policy_name"] == "Rule Board - PR Comments column"
    assert env.raw == load_fixture("finding")[0]


def test_scan_is_a_single_object_not_a_list() -> None:
    [env] = envelopes("scan")
    assert env.kind == "scan.completed"
    assert env.event_id == "scan.completed:27714135"
    assert env.deployment_id == 1
    assert env.data["outcome"] == "succeeded"
    assert env.title == "Scan completed: owasp/juice-shop"
    assert env.highlights["Full scan"] == "No"


def test_scan_with_error_exit_code_is_failed() -> None:
    payload = load_fixture("scan")
    payload["semgrep_scan"]["exit_code"] = 2
    [env] = decode(payload)
    assert env.data["outcome"] == "failed"
    assert env.title.startswith("Scan failed")


def test_scan_without_completed_at_falls_back_to_received_time() -> None:
    payload = load_fixture("scan")
    payload["semgrep_scan"]["completed_at"] = None
    [env] = decode(payload)
    assert env.occurred_at == RECEIVED_AT
    assert env.occurred_at_source == "received"


def test_supply_chain_incident() -> None:
    [env] = envelopes("supply_chain_incident")
    assert env.kind == "supply_chain_incident.declared"
    assert env.event_id == "supply_chain_incident.declared:67"
    assert env.schema_version == 1
    assert env.data["is_affected"] is True
    assert env.highlights["Packages"].endswith("and 1 more")
    assert env.highlights["Matching projects"] == "2"
    assert env.url and "advisories" in env.url


def test_demo_incident_uses_content_hash() -> None:
    payload = load_fixture("supply_chain_incident")
    payload[0]["semgrep_supply_chain_incident"].update(incident_id=None, metadata={"is_demo": True})
    [env] = decode(payload)
    assert env.event_id_source == "content_hash"
    assert env.title.endswith("(demo)")


def test_malware_firewall_exception() -> None:
    [env] = envelopes("malware_firewall_exception")
    assert env.kind == "malware_firewall_exception.requested"
    assert env.event_id == "malware_firewall_exception.requested:42"
    assert env.highlights["Package"] == "npm/left-pad@9.9.9"
    assert env.summary and env.summary.startswith("Needed for a build tool")


def test_workflow_issues() -> None:
    detected, triaged = envelopes("workflow_issues")
    assert detected.kind == "workflow_issue.detected"
    assert detected.severity == "critical"
    assert detected.highlights["Workflow"] == "Broad web security"
    assert triaged.kind == "workflow_issue.triaged"
    assert triaged.occurred_at == datetime(2026, 10, 3, 9, 0, tzinfo=UTC)
    assert detected.event_id != triaged.event_id


def test_test_notifications_are_never_duplicates_of_each_other() -> None:
    [first] = decode(load_fixture("test_notification"), delivery_id="a")
    [second] = decode(load_fixture("test_notification"), delivery_id="b")
    assert first.kind == "semgrep.test"
    assert first.event_id != second.event_id


def test_batch_yields_one_envelope_per_item() -> None:
    payload = load_fixture("finding") + load_fixture("malware_firewall_exception")
    kinds = [env.kind for env in decode(payload)]
    assert kinds == ["finding.created", "malware_firewall_exception.requested"]


def test_unknown_payload_is_kept_not_dropped() -> None:
    [env] = decode([{"semgrep_something_new": {"x": 1}}])
    assert env.kind == "unknown.received"
    assert env.event_id_source == "content_hash"
    assert env.data["top_level_keys"] == ["semgrep_something_new"]
    assert env.raw == {"semgrep_something_new": {"x": 1}}


def test_same_unknown_item_gets_same_event_id() -> None:
    [a] = decode([{"new": 1}], delivery_id="a")
    [b] = decode([{"new": 1}], delivery_id="b")
    assert a.event_id == b.event_id


def test_decoder_bug_falls_back_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    finding_decoder = decoders.DECODERS[0]

    def boom(*args: Any) -> Any:
        raise KeyError("bug")

    monkeypatch.setattr(finding_decoder, "decode", boom)
    [env] = envelopes("finding")
    assert env.kind == "unknown.received"


def test_invalid_decoder_output_falls_back_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    finding_decoder = decoders.DECODERS[0]
    original = finding_decoder.decode

    def bad_severity(item: Any, ctx: Any) -> Any:
        decoded = original(item, ctx)
        decoded.severity = "apocalyptic"
        return decoded

    monkeypatch.setattr(finding_decoder, "decode", bad_severity)
    [env] = envelopes("finding")
    assert env.kind == "unknown.received"


def test_upstream_event_id_wins_when_present() -> None:
    assert resolve_event_id(
        kind="finding.created",
        dedup_key="1",
        item={},
        upstream_event_id="evt_9",
        index=0,
        batch_size=1,
    ) == ("evt_9", "semgrep")
    assert resolve_event_id(
        kind="finding.created",
        dedup_key="1",
        item={},
        upstream_event_id="evt_9",
        index=2,
        batch_size=3,
    ) == ("evt_9:2", "semgrep")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (0, "low"),
        (1, "medium"),
        (2, "high"),
        (3, "critical"),
        ("ERROR", "high"),
        ("WARNING", "medium"),
        ("info", "info"),
        ("Critical", "critical"),
        (True, None),
        (9, None),
        (None, None),
    ],
)
def test_normalize_severity(raw: Any, expected: str | None) -> None:
    assert normalize_severity(raw) == expected


def test_parse_time_treats_naive_values_as_utc() -> None:
    assert parse_time("2024-06-11T20:39:36") == datetime(2024, 6, 11, 20, 39, 36, tzinfo=UTC)
    assert parse_time("not a time") is None
