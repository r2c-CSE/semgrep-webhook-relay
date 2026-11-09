"""``type: "workflow_issue"``: an issue from a Semgrep workflow run, scan, or triage change.

Unlike the other payloads, this one isn't wrapped in a top-level key. Its
``event`` field says why it was sent: ``workflow_complete`` and
``scan_complete`` report detected issues, ``issue_triaged`` reports a triage
change.
"""

from __future__ import annotations

from typing import Any

from semgrep_relay.decoders.base import (
    DecodeContext,
    Decoded,
    as_int,
    as_list,
    as_str,
    compact,
    normalize_severity,
    parse_time,
    truncate,
)

_ACTION_BY_EVENT = {
    "workflow_complete": "detected",
    "scan_complete": "detected",
    "issue_triaged": "triaged",
}


class WorkflowIssueDecoder:
    name = "workflow_issue"

    def matches(self, item: Any) -> bool:
        return isinstance(item, dict) and item.get("type") == "workflow_issue"

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        event = as_str(item.get("event")) or "unknown"
        action = _ACTION_BY_EVENT.get(event, "received")
        raw_issue_id = as_str(item.get("issue_id")) or as_int(item.get("issue_id"))
        issue_id = None if raw_issue_id is None else str(raw_issue_id)
        severity = normalize_severity(item.get("severity"))
        triage_state = as_str(item.get("triage_state"))
        updated_at = as_str(item.get("updated_at"))
        last_detected_at = as_str(item.get("last_detected_at"))
        workflow_id = as_str(item.get("workflow_id"))
        scan_id = as_int(item.get("scan_id"))
        cwe = [str(c) for c in as_list(item.get("cwe"))]

        # An issue can be reported again by a later run or triaged more than
        # once, so the key includes what makes each of those events distinct.
        if issue_id is None:
            dedup_key = None
        elif action == "triaged":
            dedup_key = f"{issue_id}:{triage_state}:{updated_at}"
        else:
            source = workflow_id or (f"scan-{scan_id}" if scan_id is not None else "")
            dedup_key = f"{issue_id}:{source}:{last_detected_at}"

        occurred_at = parse_time(updated_at if action == "triaged" else last_detected_at)
        title = as_str(item.get("title")) or "Untitled issue"
        prefix = "Issue triaged" if action == "triaged" else "Issue detected"

        return Decoded(
            subject="workflow_issue",
            action=action,
            dedup_key=dedup_key,
            occurred_at=occurred_at or parse_time(updated_at),
            deployment_id=as_int(item.get("deployment_id")),
            severity=severity,
            title=f"{prefix}: {title}",
            summary=truncate(item.get("description")),
            highlights=compact(
                {
                    "Severity": severity.title() if severity else None,
                    "Triage state": triage_state,
                    "File": as_str(item.get("file_path")),
                    "Dependency": as_str(item.get("dependency_path")),
                    "Workflow": as_str(item.get("workflow_display_name")) or workflow_id,
                    "CWE": cwe[0] if cwe else None,
                }
            ),
            data={
                "event": event,
                "issue_id": issue_id,
                "repository_id": as_int(item.get("repository_id")),
                "detection_state": as_str(item.get("detection_state")),
                "triage_state": triage_state,
                "file_path": as_str(item.get("file_path")),
                "dependency_path": as_str(item.get("dependency_path")),
                "domain": as_str(item.get("domain")),
                "cwe": cwe,
                "owasp": [str(o) for o in as_list(item.get("owasp"))],
                "workflow_id": workflow_id,
                "scan_id": scan_id,
                "created_at": as_str(item.get("created_at")),
                "last_detected_at": last_detected_at,
                "updated_at": updated_at,
            },
        )
