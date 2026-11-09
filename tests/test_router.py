from __future__ import annotations

from typing import Any

from conftest import envelopes

from semgrep_relay.config import RouteConfig, RouteMatch
from semgrep_relay.connectors import Connector
from semgrep_relay.connectors.stdout import StdoutConnector, StdoutOptions
from semgrep_relay.router import Router, route_matches

FINDING = envelopes("finding")[0]
SCAN = envelopes("scan")[0]
INCIDENT = envelopes("supply_chain_incident")[0]
TEST = envelopes("test_notification")[0]


def matches(envelope: Any, **match: Any) -> bool:
    return route_matches(RouteMatch(**match), envelope)


def test_default_match_is_everything_except_tests() -> None:
    assert matches(FINDING)
    assert matches(SCAN)
    assert not matches(TEST)


def test_test_notifications_need_an_exact_kind() -> None:
    assert matches(TEST, kinds=["semgrep.test"])
    assert not matches(TEST, kinds=["semgrep.*"])


def test_kind_globs() -> None:
    assert matches(FINDING, kinds=["finding.*"])
    assert not matches(SCAN, kinds=["finding.*"])


def test_min_severity() -> None:
    assert matches(FINDING, min_severity="high")
    assert matches(FINDING, min_severity="medium")
    assert not matches(FINDING, min_severity="critical")
    # Scans have no severity, so a severity filter excludes them.
    assert not matches(SCAN, min_severity="low")


def test_repositories() -> None:
    assert matches(FINDING, repositories=["owasp/*"])
    assert not matches(FINDING, repositories=["acme/*"])
    assert not matches(INCIDENT, repositories=["*"])


def test_where_matches_data_fields() -> None:
    assert matches(INCIDENT, where={"is_affected": True})
    assert not matches(INCIDENT, where={"is_affected": False})


class FindingsOnly(StdoutConnector):
    accepts = ("finding.*",)


def test_router_dedupes_and_respects_connector_accepts() -> None:
    connectors: dict[str, Connector] = {
        "a": StdoutConnector("a", StdoutOptions()),
        "findings": FindingsOnly("findings", StdoutOptions()),
    }
    router = Router(
        [
            RouteConfig(name="one", connectors=["a", "findings"]),
            RouteConfig(name="two", connectors=["a"]),
        ],
        connectors,
    )
    assert router.targets(FINDING) == ["a", "findings"]
    assert router.targets(SCAN) == ["a"]
