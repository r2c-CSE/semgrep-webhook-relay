"""``semgrep_finding``: one new finding, sent by a policy's "Call a webhook" action."""

from __future__ import annotations

from typing import Any

from semgrep_relay.decoders.base import (
    DecodeContext,
    Decoded,
    as_dict,
    as_int,
    as_list,
    as_str,
    compact,
    normalize_severity,
    parse_time,
    truncate,
    wrapped,
)

KEY = "semgrep_finding"


class FindingDecoder:
    name = "finding"

    def matches(self, item: Any) -> bool:
        return wrapped(item, KEY) is not None

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        f = wrapped(item, KEY) or {}
        metadata = as_dict(f.get("metadata"))
        check_id = as_str(f.get("check_id")) or "unknown-rule"
        rule_name = check_id.rsplit(".", 1)[-1]
        repo = as_str(f.get("repo_name"))
        path = as_str(f.get("path"))
        line = as_int(f.get("line"))
        location = f"{path}:{line}" if path and line else path
        numeric_id = as_int(f.get("numeric_id"))
        cwe = [str(c) for c in as_list(metadata.get("cwe"))]
        owasp = [str(o) for o in as_list(metadata.get("owasp"))]
        policy = as_dict(metadata.get("semgrep.policy"))
        rule_url = as_str(metadata.get("semgrep.url")) or as_str(metadata.get("shortlink"))
        severity = normalize_severity(f.get("severity"))

        # Semgrep notifies a finding only the first time it's detected, so the
        # issue ID alone identifies this event.
        dedup_key = str(numeric_id) if numeric_id is not None else as_str(f.get("id"))

        return Decoded(
            subject="finding",
            action="created",
            dedup_key=dedup_key,
            # ``start_date`` is when the first scan that saw the finding completed.
            occurred_at=parse_time(f.get("start_date")),
            repository=repo,
            severity=severity,
            title=f"New finding: {rule_name}" + (f" in {repo}" if repo else ""),
            summary=truncate(f.get("message")),
            url=as_str(f.get("pr_url")) or as_str(f.get("commit_url")),
            highlights=compact(
                {
                    "Severity": severity.title() if severity else None,
                    "Rule": check_id,
                    "Location": location,
                    "Repository": repo,
                    "Ref": as_str(f.get("ref")),
                    "CWE": cwe[0] if cwe else None,
                }
            ),
            data={
                "issue_id": numeric_id,
                "syntactic_id": as_str(f.get("id")),
                "check_id": check_id,
                "rule_url": rule_url,
                "path": path,
                "line": line,
                "end_line": as_int(f.get("end_line")),
                "column": as_int(f.get("column")),
                "end_column": as_int(f.get("end_column")),
                "message": as_str(f.get("message")),
                "ref": as_str(f.get("ref")),
                "repo_name": repo,
                "pr_url": as_str(f.get("pr_url")),
                "commit_url": as_str(f.get("commit_url")),
                "commit_date": as_str(f.get("commit_date")),
                "first_seen_scan_id": as_str(f.get("first_seen_scan_id")),
                "confidence": as_str(metadata.get("confidence")),
                "cwe": cwe,
                "owasp": owasp,
                "policy_name": as_str(policy.get("name")),
            },
        )
