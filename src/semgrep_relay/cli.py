"""Command line entry point: ``semgrep-webhook-relay [serve|check-config|retry-dead|stats]``."""

from __future__ import annotations

import argparse
import json
import os
import sys

from semgrep_relay.config import ConfigError, RelayConfig, load_config
from semgrep_relay.connectors import build_connectors
from semgrep_relay.logs import configure_logging
from semgrep_relay.store import Store


def _load(path: str | None) -> RelayConfig:
    try:
        config = load_config(path)
        build_connectors(config.connectors)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    return config


def _serve(config: RelayConfig) -> None:
    import uvicorn

    from semgrep_relay.app import create_app

    server = config.server
    uvicorn.run(
        create_app(config),
        host=server.host,
        port=server.port,
        ssl_certfile=server.tls_cert_file,
        ssl_keyfile=server.tls_key_file,
        log_config=None,
        access_log=False,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="semgrep-webhook-relay",
        description="Unofficial, experimental relay for Semgrep webhooks.",
    )
    parser.add_argument("--config", help="Path to the config file (default: $RELAY_CONFIG).")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="Run the relay (default).")
    commands.add_parser("check-config", help="Validate the config and exit.")
    retry = commands.add_parser("retry-dead", help="Requeue deliveries that ran out of retries.")
    retry.add_argument("--connector", help="Only requeue deliveries for this connector.")
    commands.add_parser("stats", help="Print delivery counts by status.")
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("RELAY_LOG_LEVEL", "INFO"))
    config = _load(args.config)

    match args.command:
        case "check-config":
            print(f"Config OK: {len(config.connectors)} connectors, {len(config.routes)} routes.")
        case "retry-dead":
            store = Store(config.store.path)
            print(f"Requeued {store.retry_dead(args.connector)} deliveries.")
            store.close()
        case "stats":
            store = Store(config.store.path)
            print(json.dumps(store.status_counts()))
            store.close()
        case _:
            _serve(config)


if __name__ == "__main__":
    main()
