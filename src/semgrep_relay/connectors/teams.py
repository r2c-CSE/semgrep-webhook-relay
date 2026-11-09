"""Microsoft Teams, through a Teams workflow webhook.

In Teams, create a workflow from the "Post to a channel when a webhook request
is received" template and use the URL it gives you. The relay posts an
Adaptive Card. (Office 365 connector webhooks are being retired by Microsoft,
so this targets workflow webhooks.)
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from semgrep_relay.connectors.base import Connector, ConnectorOptions, OutboundRequest
from semgrep_relay.envelope import Envelope

_ADAPTIVE_CARD = "application/vnd.microsoft.card.adaptive"
_CARD_VERSION = "1.4"

_COLOR_BY_SEVERITY = {
    "critical": "Attention",
    "high": "Attention",
    "medium": "Warning",
}

_LINK_LABEL_BY_SUBJECT = {
    "finding": "View code change",
    "scan": "View CI job",
    "supply_chain_incident": "View advisories",
}


class TeamsOptions(ConnectorOptions):
    # The workflow URL carries its own signature, so treat it as a secret.
    url: str = Field(pattern=r"^https://")


def build_card(envelope: Envelope) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": envelope.title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
            "color": _COLOR_BY_SEVERITY.get(envelope.severity or "", "Default"),
        }
    ]
    if envelope.summary:
        body.append({"type": "TextBlock", "text": envelope.summary, "wrap": True})
    if envelope.highlights:
        body.append(
            {
                "type": "FactSet",
                "facts": [{"title": k, "value": v} for k, v in envelope.highlights.items()],
            }
        )
    body.append(
        {
            "type": "TextBlock",
            "text": f"{envelope.kind} · {envelope.occurred_at.isoformat(timespec='seconds')}",
            "isSubtle": True,
            "size": "Small",
            "wrap": True,
        }
    )
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": _CARD_VERSION,
        "msteams": {"width": "Full"},
        "body": body,
    }
    if envelope.url:
        card["actions"] = [
            {
                "type": "Action.OpenUrl",
                "title": _LINK_LABEL_BY_SUBJECT.get(envelope.subject, "Open link"),
                "url": envelope.url,
            }
        ]
    return card


class TeamsConnector(Connector):
    type_name = "teams"
    options_model = TeamsOptions
    options: TeamsOptions

    def build_request(self, envelope: Envelope) -> OutboundRequest:
        return OutboundRequest(
            url=self.options.url,
            json={
                "type": "message",
                "attachments": [
                    {
                        "contentType": _ADAPTIVE_CARD,
                        "contentUrl": None,
                        "content": build_card(envelope),
                    }
                ],
            },
        )
