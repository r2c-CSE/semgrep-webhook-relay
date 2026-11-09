"""Decide which connectors receive an event."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase

from semgrep_relay.config import RouteConfig, RouteMatch
from semgrep_relay.connectors import Connector
from semgrep_relay.envelope import Envelope, severity_rank

TEST_KIND = "semgrep.test"


def route_matches(match: RouteMatch, envelope: Envelope) -> bool:
    if envelope.kind == TEST_KIND:
        # Test notifications reach only routes that ask for them by name, so a
        # catch-all route doesn't post "Test Notification" into a SIEM.
        if TEST_KIND not in match.kinds:
            return False
    elif not any(fnmatchcase(envelope.kind, pattern) for pattern in match.kinds):
        return False

    if match.min_severity is not None and (
        envelope.severity is None
        or severity_rank(envelope.severity) > severity_rank(match.min_severity)
    ):
        return False

    if match.repositories is not None and (
        envelope.repository is None
        or not any(fnmatchcase(envelope.repository, p) for p in match.repositories)
    ):
        return False

    return all(envelope.data.get(field) == expected for field, expected in match.where.items())


class Router:
    def __init__(self, routes: Sequence[RouteConfig], connectors: Mapping[str, Connector]) -> None:
        self._routes = list(routes)
        self._connectors = connectors

    def targets(self, envelope: Envelope) -> list[str]:
        """Connector names for this event, in route order, without repeats."""
        names: list[str] = []
        for route in self._routes:
            if not route_matches(route.match, envelope):
                continue
            for name in route.connectors:
                if name not in names and self._connectors[name].accepts_kind(envelope.kind):
                    names.append(name)
        return names
