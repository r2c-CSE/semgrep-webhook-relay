"""Write each envelope as one JSON line to stdout.

Useful for trying the relay out, and for log pipelines that already collect
container output. Event content, including finding messages and file paths,
ends up in those logs.
"""

from __future__ import annotations

import sys

import httpx

from semgrep_relay.connectors.base import (
    Connector,
    ConnectorOptions,
    DeliveryResult,
    OutboundRequest,
)
from semgrep_relay.envelope import Envelope


class StdoutOptions(ConnectorOptions):
    include_raw: bool = False


class StdoutConnector(Connector):
    type_name = "stdout"
    options_model = StdoutOptions
    options: StdoutOptions

    def build_request(self, envelope: Envelope) -> OutboundRequest:
        raise NotImplementedError("The stdout connector doesn't make HTTP requests.")

    def render(self, envelope: Envelope) -> str:
        exclude = None if self.options.include_raw else {"raw"}
        return envelope.model_dump_json(exclude=exclude)

    async def deliver(self, envelope: Envelope, client: httpx.AsyncClient) -> DeliveryResult:
        sys.stdout.write(self.render(envelope) + "\n")
        sys.stdout.flush()
        return DeliveryResult(ok=True)
