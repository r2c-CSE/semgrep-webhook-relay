# semgrep-webhook-relay

> [!WARNING]
> **Unofficial and experimental.** This is not a Semgrep product. It isn't supported by Semgrep Support, has no SLA, and may change or break without notice. Use it at your own risk, and try it outside production first.

A small container that receives [Semgrep webhooks](https://semgrep.dev/docs/semgrep-appsec-platform/webhooks), turns each one into a consistent event, and forwards it to the tools you choose. It runs anywhere a container runs and needs no other infrastructure.

Today it can send to:

- **Splunk**, through the HTTP Event Collector (HEC)
- **Microsoft Teams**, through a Teams workflow webhook
- **stdout**, as one JSON line per event, for log pipelines and for trying the relay out

```
Semgrep ──HTTPS──▶ relay ──▶ verify signature ──▶ decode ──▶ route ──▶ queue (SQLite)
                                                                          │
                                         Splunk HEC ◀── deliver with retries ──▶ Teams
```

## Contents

- [What it relays](#what-it-relays)
- [Quick start](#quick-start)
- [Connect it to Semgrep](#connect-it-to-semgrep)
- [Configuration](#configuration)
- [Connectors](#connectors)
- [The event envelope](#the-event-envelope)
- [Delivery guarantees and limits](#delivery-guarantees-and-limits)
- [Security](#security)
- [Operations](#operations)
- [Extending the relay](#extending-the-relay)
- [Development](#development)

## What it relays

Each item Semgrep sends becomes one event with a `kind`, named `<subject>.<action>`:

| Kind | Semgrep payload | Sent when |
| --- | --- | --- |
| `finding.created` | `semgrep_finding` | A policy with a **Call a webhook** action matches a new finding. |
| `scan.completed` | `semgrep_scan` | A scan finishes. `data.outcome` is `succeeded`, `failed`, or `unknown`. |
| `supply_chain_incident.declared` | `semgrep_supply_chain_incident` | Semgrep declares a Supply Chain incident. `data.is_affected` says whether it affects your projects. |
| `malware_firewall_exception.requested` | `semgrep_malware_firewall_exception_request` | A developer asks for an exception to a blocked package. |
| `workflow_issue.detected` | `type: workflow_issue` | A Semgrep workflow run or scan reports an issue. |
| `workflow_issue.triaged` | `type: workflow_issue` | An issue's triage state changes. |
| `semgrep.test` | `{"text": "Test Notification"}` | You click **Test** on the webhook integration in Semgrep. |
| `semgrep.notice` | Other `{"text": ...}` messages | Semgrep reports a problem in plain text. |
| `unknown.received` | Anything else | Semgrep sends a payload type the relay doesn't recognize yet. It's still delivered, with the original in `raw`. |

Some of these payloads aren't in Semgrep's public webhook docs yet, so the relay decodes them on a best-effort basis.

Semgrep doesn't send an event for a finding being fixed or closed, so the relay can't forward one.

## Quick start

1. Copy [`config.example.yaml`](config.example.yaml) to `config/relay.yaml` and edit it. Secrets come from environment variables.
2. Build and run the image:

```sh
docker build -t semgrep-webhook-relay .

docker run -d --name semgrep-webhook-relay \
  -p 8080:8080 \
  -v "$PWD/config:/config:ro" \
  -v semgrep-relay-data:/data \
  -e SEMGREP_WEBHOOK_SECRET='the secret you set in Semgrep' \
  -e SPLUNK_HEC_URL='https://splunk.example.com:8088' \
  -e SPLUNK_HEC_TOKEN='...' \
  -e TEAMS_WORKFLOW_URL='https://...' \
  semgrep-webhook-relay
```

3. Check that it's up: `curl http://localhost:8080/readyz`.

The relay listens on port 8080 and accepts webhooks at `POST /webhooks/semgrep`. Keep `/data` on a persistent volume: it holds the delivery queue.

To validate a config without starting the server, run the image with `check-config` as the command.

## Connect it to Semgrep

Semgrep only posts to **HTTPS** URLs that are **publicly reachable**. Put the relay behind your load balancer or ingress with a TLS certificate, or set `server.tls_cert_file` and `server.tls_key_file` to terminate TLS in the relay. If the relay is only reachable inside your network, use the [Semgrep Network Broker](https://semgrep.dev/docs/semgrep-ci/network-broker) and turn on **Use Network Broker** for the webhook.

In Semgrep:

1. Go to **Settings > Integrations > Add > Webhook**.
2. Set **Webhook URL** to your relay, for example `https://semgrep-relay.example.com/webhooks/semgrep`.
3. Set a **Signature Secret** of at least 15 characters, and give the relay the same value in `semgrep.signing_secrets`.
4. Click **Test**. The relay records a `semgrep.test` event, which is only delivered to routes that list `semgrep.test` (the example config sends it to Teams).
5. In your policies, add the action **Call a webhook** and choose this integration.

See Semgrep's [webhook docs](https://semgrep.dev/docs/semgrep-appsec-platform/webhooks) for what each payload contains.

## Configuration

The config is a YAML file, read from `$RELAY_CONFIG` (default `/config/relay.yaml`). Any string can reference an environment variable as `${NAME}` or `${NAME:-default}`. The relay refuses to start if a referenced variable isn't set, or if the config has an unknown key.

```yaml
server:
  port: 8080                      # default 8080
  webhook_path: /webhooks/semgrep # default /webhooks/semgrep
  max_body_bytes: 10485760        # default 10 MiB
  tls_cert_file: null             # set both to terminate TLS in the relay
  tls_key_file: null

semgrep:
  signing_secrets: [${SEMGREP_WEBHOOK_SECRET}] # list two while rotating
  allow_unsigned: false           # true only for local testing

store:
  path: /data/relay.db
  retention_days: 30              # also the duplicate-detection window

delivery:
  max_attempts: 10
  initial_backoff_seconds: 5      # doubles each retry, ±20% jitter
  max_backoff_seconds: 900
  concurrency: 4
  request_timeout_seconds: 15

connectors:
  <name>:
    type: splunk_hec | teams | stdout
    # ...options for that type

routes:
  - name: <name>
    match: { ... }                # optional; omitted means "everything"
    connectors: [<name>, ...]
```

### Routes

An event goes to every connector of every route it matches, once per connector. A route matches when all of its conditions hold:

| Condition | Matches when | Example |
| --- | --- | --- |
| `kinds` | The kind matches any glob. Default `["*"]`. | `["finding.*", "workflow_issue.*"]` |
| `min_severity` | Severity is at least this: `critical`, `high`, `medium`, `low`, `info`. Events without a severity, such as scans, don't match. | `high` |
| `repositories` | The repository name matches any glob. Events without a repository don't match. | `["acme/*"]` |
| `where` | Each key in the event's `data` equals the given value. | `{is_affected: true}` |

Test notifications (`semgrep.test`) only match a route that lists `semgrep.test` in `kinds` exactly, so a catch-all route doesn't send them to your SIEM.

Finding severities are normalized: Semgrep's `ERROR` becomes `high`, `WARNING` becomes `medium`, and numeric severities 0 to 3 become `low` to `critical`.

## Connectors

### Splunk HEC (`splunk_hec`)

Sends each event to the HEC event endpoint, with the envelope as the event body and `occurred_at` as the event time.

| Option | Default | Notes |
| --- | --- | --- |
| `url` | required | The HEC base URL (`https://splunk.example.com:8088`) or the full `/services/collector/event` URL. |
| `token` | required | The HEC token. |
| `index` | token's default | |
| `source` | `semgrep-webhook-relay` | |
| `sourcetype` | `semgrep:event` | |
| `host` | none | |
| `timestamp` | `occurred` | Index events by `occurred_at` (`occurred`) or by `received_at` (`received`). Use `received` if late notifications fall outside your usual search window. |
| `include_raw` | `true` | Include Semgrep's original payload under `raw`. |
| `verify_tls` | `true` | |
| `ca_bundle` | none | Path to a CA bundle, for HEC endpoints with a private CA. |

Token and request-format errors (HTTP 400, 401, 403) aren't retried. Busy or unavailable responses (HTTP 429, 503) are.

### Microsoft Teams (`teams`)

Posts an Adaptive Card to a channel. In Teams, create a workflow from the **Post to a channel when a webhook request is received** template and use the URL it gives you. The URL works like a password, so pass it in through an environment variable.

| Option | Default | Notes |
| --- | --- | --- |
| `url` | required | The workflow's HTTPS URL. |

The card shows the title, summary, key facts (severity, rule, location, repository, and so on) and a link to the code change, CI job, or advisories when there is one.

### stdout (`stdout`)

Writes each envelope as one JSON line to stdout. Relay logs go to stderr, so the two don't mix. Event content, such as finding messages and file paths, ends up wherever your container output goes.

| Option | Default | Notes |
| --- | --- | --- |
| `include_raw` | `false` | Include Semgrep's original payload under `raw`. |

## The event envelope

Every connector receives the same envelope:

```json
{
  "envelope_version": 1,
  "event_id": "finding.created:11301071",
  "event_id_source": "derived",
  "delivery_id": "54865f8a-feb6-4e93-9ae3-37412fe537f0",
  "received_at": "2026-11-09T00:43:59.342613Z",
  "occurred_at": "2023-02-12T00:50:21.552606Z",
  "occurred_at_source": "payload",
  "kind": "finding.created",
  "subject": "finding",
  "action": "created",
  "schema_version": null,
  "deployment_id": null,
  "repository": "owasp/juice-shop",
  "severity": "high",
  "title": "New finding: express-sequelize-injection in owasp/juice-shop",
  "summary": "Detected a sequelize statement that is tainted by user-input.",
  "url": "https://github.com/owasp/juice-shop/commit/1bb71ff...",
  "highlights": { "Severity": "High", "Rule": "javascript.sequelize...", "Location": "data/static/...:10" },
  "data": { "issue_id": 11301071, "check_id": "...", "path": "...", "line": 10, "cwe": ["CWE-89: ..."] },
  "raw": { "semgrep_finding": { "...": "the original item" } }
}
```

- `event_id` identifies the event, so a repeat of the same event gets the same ID. `delivery_id` identifies the HTTP request, so every request gets a new one.
- `event_id_source` says how the ID was made: `derived` from stable IDs in the payload (such as the issue ID), or `content_hash` when the payload has none. It will be `semgrep` if Semgrep ever sends its own event IDs.
- `received_at` is when the relay accepted the request. `occurred_at` is the payload's own time when it has one (scan completion, incident dispatch, triage time), otherwise `received_at`; `occurred_at_source` says which.
- `data` holds the normalized fields for that kind. `raw` holds the original item.

## Delivery guarantees and limits

- **Semgrep sends each webhook once and doesn't retry.** If the relay is down, that event is lost. Run it somewhere that restarts it automatically, and monitor `/readyz`.
- **The relay replies 200 only after the event is safely written** to its SQLite store. Delivery to destinations happens afterwards.
- **Delivery to destinations is at-least-once.** Failures that are worth retrying (timeouts, connection errors, HTTP 408, 425, 429 and 5xx) are retried with exponential backoff, honoring `Retry-After`. With the defaults, an event is retried for about 36 minutes before it's dead-lettered. Other failures are dead-lettered immediately. A crash between sending and recording the send can cause one duplicate.
- **Duplicates are dropped** when an event with the same `event_id` arrived within `store.retention_days`. Semgrep can send the same finding twice, for example when two policies call the same webhook.
- **Replay protection is limited.** Semgrep's signature covers the body but no timestamp, so a captured request stays valid. Replays inside the retention window are dropped as duplicates; one outside it would be delivered again.
- **Run one replica.** The SQLite store belongs to a single relay process.
- **Ticket sync isn't supported.** Semgrep doesn't send an event when a finding is fixed or closed, so a connector couldn't close a ticket it opened.

## Security

- **Signatures are required by default.** Requests without a valid `X-Semgrep-Signature-256` are rejected with 401. Setting `semgrep.allow_unsigned: true` turns this off; only do that for local testing.
- **Secrets stay out of the config file** through `${ENV_VAR}` references. Config errors never echo connector option values.
- **Logs contain IDs, kinds, connector names and outcomes**, never payload content or secrets. The `stdout` connector is the exception, by design.
- **The image runs as a non-root user** (UID 10001) and stores its data in `/data`.
- **Outbound TLS is verified** unless you turn it off for a connector. Prefer `ca_bundle` for a private CA.
- **The store holds event content** (finding messages, file paths, repository names) for `retention_days`. Protect the `/data` volume accordingly.

## Operations

| Endpoint | Purpose |
| --- | --- |
| `POST /webhooks/semgrep` | Receives Semgrep webhooks. |
| `GET /healthz` | Liveness: the process is up. |
| `GET /readyz` | Readiness: the store is reachable. Also returns delivery counts by status. |

Commands, run inside the container (`docker exec semgrep-webhook-relay semgrep-webhook-relay <command>`):

| Command | Purpose |
| --- | --- |
| `serve` | Run the relay. This is the default. |
| `check-config` | Validate the config and exit. |
| `stats` | Print delivery counts by status. |
| `retry-dead [--connector NAME]` | Requeue dead-lettered deliveries, for example after fixing a token. |

Logs are JSON on stderr. Set `RELAY_LOG_LEVEL` to `DEBUG`, `INFO` (default), `WARNING` or `ERROR`.

## Extending the relay

### Add a connector

Subclass `Connector`, describe its options, and build the request. The relay handles queueing, retries and dead-lettering.

```python
from pydantic import Field

from semgrep_relay.connectors.base import Connector, ConnectorOptions, OutboundRequest
from semgrep_relay.envelope import Envelope


class ExampleChatOptions(ConnectorOptions):
    url: str = Field(pattern=r"^https://")


class ExampleChatConnector(Connector):
    type_name = "example_chat"
    options_model = ExampleChatOptions
    accepts = ("finding.*",)  # optional: kinds this connector can render

    def build_request(self, envelope: Envelope) -> OutboundRequest:
        return OutboundRequest(url=self.options.url, json={"text": envelope.title})
```

Register it in `CONNECTOR_TYPES` in `src/semgrep_relay/connectors/__init__.py`, then use `type: example_chat` in the config. Override `classify()` if the destination signals errors in an unusual way.

### Add a payload type

Add a decoder module under `src/semgrep_relay/decoders/` with `matches()` and `decode()`, and register it in `DECODERS` ahead of `UnknownDecoder`. Return a `dedup_key` built from stable IDs so repeats of the event are detected.

### Ready for future Semgrep changes

The relay is built so that likely improvements to Semgrep's webhooks slot in without reworking it:

| If Semgrep adds | Where it goes |
| --- | --- |
| An event ID header | Name it in `UPSTREAM_EVENT_ID_HEADERS` in `app.py`. It then takes priority over derived IDs, with `event_id_source: semgrep`. |
| An event type header | Name it in `UPSTREAM_EVENT_TYPE_HEADERS`; it's passed to the decoders as a hint. |
| A signature that covers a timestamp | Add a verifier in `verify.py`. Verifiers are chosen by the headers present, so both schemes can run side by side. |
| Retries | Nothing to change: repeats are already dropped as duplicates. |
| A `finding.closed` event | Add a decoder. Routing and connectors work on kinds, so nothing else changes. |
| Versioned finding payloads | Decoders can branch on `schema_version`, which is already in the envelope. |

Two-way sync, such as closing a ticket when a finding closes, also needs state. Connectors can declare `stateful = True`, and the store has a `correlations` table to map a Semgrep issue to the record a connector created. No connector uses either yet.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

To run it locally without Docker:

```sh
RELAY_CONFIG=./relay.yaml uv run semgrep-webhook-relay serve
```

`pyproject.toml` sets uv's `exclude-newer = "1 week"`, so dependency updates never pick up a release less than a week old.
