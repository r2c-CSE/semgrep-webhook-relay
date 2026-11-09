"""Connector registry.

To add a destination, subclass ``Connector`` in a new module and add it to
``CONNECTOR_TYPES``. Its ``type_name`` is what configs use as ``type``.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import ValidationError

from semgrep_relay.config import ConfigError, ConnectorConfig
from semgrep_relay.connectors.base import Connector, DeliveryResult, OutboundRequest
from semgrep_relay.connectors.splunk_hec import SplunkHecConnector
from semgrep_relay.connectors.stdout import StdoutConnector
from semgrep_relay.connectors.teams import TeamsConnector

CONNECTOR_TYPES: dict[str, type[Connector]] = {
    cls.type_name: cls for cls in (SplunkHecConnector, TeamsConnector, StdoutConnector)
}

__all__ = [
    "CONNECTOR_TYPES",
    "Connector",
    "DeliveryResult",
    "OutboundRequest",
    "build_connectors",
]


def build_connectors(configs: Mapping[str, ConnectorConfig]) -> dict[str, Connector]:
    connectors: dict[str, Connector] = {}
    for name, config in configs.items():
        cls = CONNECTOR_TYPES.get(config.type)
        if cls is None:
            known = ", ".join(sorted(CONNECTOR_TYPES))
            raise ConfigError(
                f"Connector {name!r} has unknown type {config.type!r}. Known types: {known}."
            )
        try:
            options = cls.options_model.model_validate(config.options())
        except ValidationError as exc:
            # Never echo option values: they include tokens and signed URLs.
            problems = "; ".join(
                f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
            )
            raise ConfigError(f"Connector {name!r} has invalid options: {problems}") from None
        connectors[name] = cls(name, options)
    return connectors
