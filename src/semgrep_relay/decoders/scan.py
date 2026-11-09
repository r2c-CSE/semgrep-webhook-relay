"""``semgrep_scan``: sent when a scan finishes, as a single object rather than a list."""

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
    parse_time,
    wrapped,
)

KEY = "semgrep_scan"

# Semgrep exits 0 with no blocking findings and 1 with blocking findings. Any
# other exit code means the scan itself failed.
_SUCCESS_EXIT_CODES = (0, 1)


def _outcome(exit_code: int | None) -> str:
    if exit_code is None:
        return "unknown"
    return "succeeded" if exit_code in _SUCCESS_EXIT_CODES else "failed"


class ScanDecoder:
    name = "scan"

    def matches(self, item: Any) -> bool:
        return wrapped(item, KEY) is not None

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        s = wrapped(item, KEY) or {}
        meta = as_dict(s.get("meta"))
        scan_id = as_int(s.get("id"))
        exit_code = as_int(s.get("exit_code"))
        outcome = _outcome(exit_code)
        repo = as_str(meta.get("repository")) or as_str(meta.get("repo_display_name"))
        branch = as_str(meta.get("branch"))
        commit = as_str(meta.get("commit"))
        products = [str(p) for p in as_list(s.get("enabled_products"))]
        full_scan = meta.get("is_full_scan")

        verb = "failed" if outcome == "failed" else "completed"
        return Decoded(
            subject="scan",
            action="completed",
            dedup_key=str(scan_id) if scan_id is not None else None,
            occurred_at=parse_time(s.get("completed_at")),
            deployment_id=as_int(s.get("deployment_id")),
            repository=repo,
            title=f"Scan {verb}" + (f": {repo}" if repo else ""),
            summary=as_str(meta.get("commit_title")),
            url=as_str(meta.get("ci_job_url")),
            highlights=compact(
                {
                    "Repository": repo,
                    "Branch": branch,
                    "Commit": commit[:12] if commit else None,
                    "Trigger": as_str(meta.get("on")),
                    "Full scan": None if full_scan is None else ("Yes" if full_scan else "No"),
                    "Exit code": None if exit_code is None else str(exit_code),
                    "Products": ", ".join(products) or None,
                }
            ),
            data={
                "scan_id": scan_id,
                "hashed_id": as_str(s.get("hashed_id")),
                "repository_id": as_int(s.get("repository_id")),
                "outcome": outcome,
                "exit_code": exit_code,
                "started_at": as_str(s.get("started_at")),
                "completed_at": as_str(s.get("completed_at")),
                "branch": branch,
                "commit": commit,
                "trigger": as_str(meta.get("on")),
                "is_full_scan": bool(full_scan) if full_scan is not None else None,
                "pull_request_id": as_str(meta.get("pull_request_id")),
                "enabled_products": products,
                "semgrep_version": as_str(meta.get("semgrep_version")),
            },
        )
