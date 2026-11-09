"""Load and validate the relay's YAML config.

String values may reference environment variables as ``${NAME}`` or
``${NAME:-default}``, so secrets never have to live in the file itself.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from semgrep_relay.envelope import Severity

DEFAULT_CONFIG_PATH = "/config/relay.yaml"
CONFIG_PATH_ENV = "RELAY_CONFIG"

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerSettings(_Strict):
    host: str = "0.0.0.0"  # noqa: S104 - the relay runs in a container behind your network edge
    port: int = 8080
    webhook_path: str = "/webhooks/semgrep"
    max_body_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    # Optional: terminate TLS in the relay itself instead of at a load balancer.
    tls_cert_file: str | None = None
    tls_key_file: str | None = None

    @model_validator(mode="after")
    def _tls_pair(self) -> ServerSettings:
        if bool(self.tls_cert_file) != bool(self.tls_key_file):
            raise ValueError("Set both tls_cert_file and tls_key_file, or neither.")
        return self


class SemgrepSettings(_Strict):
    # The "Signature secret" set on the webhook integration in Semgrep. List
    # more than one while rotating it.
    signing_secrets: list[str] = Field(default_factory=list)
    # Accept requests without a signature. Only for local testing.
    allow_unsigned: bool = False

    @field_validator("signing_secrets")
    @classmethod
    def _drop_empty(cls, secrets: list[str]) -> list[str]:
        return [s for s in secrets if s]

    @model_validator(mode="after")
    def _require_secret(self) -> SemgrepSettings:
        if not self.signing_secrets and not self.allow_unsigned:
            raise ValueError(
                "Set semgrep.signing_secrets to your webhook's signature secret, "
                "or set semgrep.allow_unsigned: true for local testing."
            )
        return self


class StoreSettings(_Strict):
    path: str = "/data/relay.db"
    # How long events are kept. This is also the duplicate-detection window.
    retention_days: int = Field(default=30, gt=0)


class DeliverySettings(_Strict):
    max_attempts: int = Field(default=10, gt=0)
    initial_backoff_seconds: float = Field(default=5.0, gt=0)
    max_backoff_seconds: float = Field(default=900.0, gt=0)
    concurrency: int = Field(default=4, gt=0)
    request_timeout_seconds: float = Field(default=15.0, gt=0)
    poll_interval_seconds: float = Field(default=1.0, gt=0)


class ConnectorConfig(BaseModel):
    """``type`` picks the connector; every other key is that connector's options."""

    model_config = ConfigDict(extra="allow")

    type: str

    def options(self) -> dict[str, Any]:
        return dict(self.model_extra or {})


class RouteMatch(_Strict):
    # Globs over event kinds, e.g. "finding.*". Test notifications
    # ("semgrep.test") only match a route that names them exactly.
    kinds: list[str] = Field(default_factory=lambda: ["*"])
    # Events at this severity or above. Events without a severity never match.
    min_severity: Severity | None = None
    # Globs over repository names, e.g. "acme/*". Events without a repository
    # never match when this is set.
    repositories: list[str] | None = None
    # Exact matches against the envelope's ``data`` fields, e.g. {is_affected: true}.
    where: dict[str, Any] = Field(default_factory=dict)


class RouteConfig(_Strict):
    name: str
    match: RouteMatch = Field(default_factory=RouteMatch)
    connectors: list[str] = Field(min_length=1)


class RelayConfig(_Strict):
    server: ServerSettings = Field(default_factory=ServerSettings)
    semgrep: SemgrepSettings
    store: StoreSettings = Field(default_factory=StoreSettings)
    delivery: DeliverySettings = Field(default_factory=DeliverySettings)
    connectors: dict[str, ConnectorConfig] = Field(default_factory=dict)
    routes: list[RouteConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _routes_reference_connectors(self) -> RelayConfig:
        for route in self.routes:
            missing = [c for c in route.connectors if c not in self.connectors]
            if missing:
                raise ValueError(
                    f"Route {route.name!r} uses unknown connectors: {', '.join(missing)}"
                )
        return self


def _interpolate(value: Any, path: str = "") -> Any:
    if isinstance(value, dict):
        return {k: _interpolate(v, f"{path}.{k}" if path else str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        resolved = os.environ.get(name)
        if resolved is not None:
            return resolved
        if default is not None:
            return default
        raise ConfigError(f"Environment variable {name} is not set (used by {path}).")

    return _ENV_PATTERN.sub(replace, value)


def parse_config(raw: Any) -> RelayConfig:
    if not isinstance(raw, dict):
        raise ConfigError("The config file must be a YAML mapping.")
    try:
        return RelayConfig.model_validate(_interpolate(raw))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def load_config(path: str | None = None) -> RelayConfig:
    config_path = Path(path or os.environ.get(CONFIG_PATH_ENV) or DEFAULT_CONFIG_PATH)
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file {config_path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {config_path} is not valid YAML: {exc}") from exc
    return parse_config(raw)
