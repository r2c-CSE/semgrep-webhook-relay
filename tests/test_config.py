from __future__ import annotations

from pathlib import Path

import pytest
from conftest import make_config

from semgrep_relay.config import ConfigError, load_config, parse_config
from semgrep_relay.connectors import build_connectors


def test_interpolates_environment_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SEMGREP_SECRET", "from-the-environment")
    path = tmp_path / "relay.yaml"
    path.write_text(
        "semgrep:\n"
        "  signing_secrets: ['${SEMGREP_SECRET}']\n"
        "store:\n"
        "  path: '${DATA_DIR:-/tmp}/relay.db'\n"
    )
    config = load_config(str(path))
    assert config.semgrep.signing_secrets == ["from-the-environment"]
    assert config.store.path == "/tmp/relay.db"


def test_missing_environment_variable_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    with pytest.raises(ConfigError, match="NOT_SET_ANYWHERE"):
        parse_config({"semgrep": {"signing_secrets": ["${NOT_SET_ANYWHERE}"]}})


def test_requires_a_secret_unless_unsigned_is_allowed() -> None:
    with pytest.raises(ConfigError, match="signing_secrets"):
        parse_config({"semgrep": {"signing_secrets": [""]}})
    assert parse_config({"semgrep": {"allow_unsigned": True}}).semgrep.allow_unsigned


def test_routes_must_reference_configured_connectors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown connectors: nowhere"):
        make_config(tmp_path, routes=[{"name": "r", "connectors": ["nowhere"]}])


def test_rejects_unknown_keys(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        make_config(tmp_path, delivery={"max_attempt": 3})


def test_tls_settings_must_come_in_pairs(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="tls_cert_file"):
        make_config(tmp_path, server={"tls_cert_file": "/certs/cert.pem"})


def test_unknown_connector_type(tmp_path: Path) -> None:
    config = make_config(tmp_path, connectors={"x": {"type": "carrier_pigeon"}}, routes=[])
    with pytest.raises(ConfigError, match="unknown type 'carrier_pigeon'"):
        build_connectors(config.connectors)


def test_invalid_connector_options_never_echo_values(tmp_path: Path) -> None:
    secret_url = "http://not-https.example/with-a-signature-in-it"
    config = make_config(
        tmp_path, connectors={"teams": {"type": "teams", "url": secret_url}}, routes=[]
    )
    with pytest.raises(ConfigError) as excinfo:
        build_connectors(config.connectors)
    assert "url" in str(excinfo.value)
    assert secret_url not in str(excinfo.value)
