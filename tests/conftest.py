from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from semgrep_relay.config import RelayConfig, parse_config
from semgrep_relay.decoders import decode_body
from semgrep_relay.envelope import Envelope

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "a-signing-secret-of-decent-length"
RECEIVED_AT = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def semgrep_body(payload: Any) -> bytes:
    """Serialize the way Semgrep does: compact JSON, UTF-8."""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def sign(body: bytes, secret: str = SECRET) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def envelopes(name: str, delivery_id: str = "delivery-1") -> list[Envelope]:
    return decode_body(load_fixture(name), delivery_id=delivery_id, received_at=RECEIVED_AT)


def make_config(tmp_path: Path, **overrides: Any) -> RelayConfig:
    raw: dict[str, Any] = {
        "semgrep": {"signing_secrets": [SECRET]},
        "store": {"path": str(tmp_path / "relay.db")},
        "delivery": {
            "initial_backoff_seconds": 0.01,
            "max_backoff_seconds": 0.05,
            "poll_interval_seconds": 0.02,
        },
        "connectors": {"siem": {"type": "stdout"}},
        "routes": [{"name": "all", "connectors": ["siem"]}],
    }
    raw.update(overrides)
    return parse_config(raw)
