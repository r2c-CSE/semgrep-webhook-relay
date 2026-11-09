"""``semgrep_supply_chain_incident``: an incident declared by Semgrep's Security Research team."""

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
    truncate,
    wrapped,
)

KEY = "semgrep_supply_chain_incident"
_PACKAGES_IN_HIGHLIGHT = 3


def _package_label(package: dict[str, Any]) -> str:
    name = as_str(package.get("name")) or "unknown"
    ecosystem = as_str(package.get("ecosystem"))
    version = as_str(package.get("version")) or ""
    return f"{ecosystem}/{name}{version}" if ecosystem else f"{name}{version}"


class SupplyChainIncidentDecoder:
    name = "supply_chain_incident"

    def matches(self, item: Any) -> bool:
        return wrapped(item, KEY) is not None

    def decode(self, item: Any, ctx: DecodeContext) -> Decoded:
        i = wrapped(item, KEY) or {}
        metadata = as_dict(i.get("metadata"))
        packages_block = as_dict(i.get("incident_packages"))
        projects_block = as_dict(i.get("matching_projects"))
        packages = [as_dict(p) for p in as_list(packages_block.get("items"))]
        projects = [as_dict(p) for p in as_list(projects_block.get("items"))]
        package_total = as_int(packages_block.get("total_count")) or len(packages)
        project_total = as_int(projects_block.get("total_count")) or len(projects)
        is_affected = bool(i.get("is_affected"))
        is_demo = bool(metadata.get("is_demo"))
        incident_id = as_int(i.get("incident_id"))
        title = as_str(i.get("title")) or "Untitled incident"

        labels = [_package_label(p) for p in packages[:_PACKAGES_IN_HIGHLIGHT]]
        if package_total > len(labels):
            labels.append(f"and {package_total - len(labels)} more")

        return Decoded(
            subject="supply_chain_incident",
            action="declared",
            # Demo incidents have no ID, so they fall back to a content hash.
            dedup_key=None if is_demo or incident_id is None else str(incident_id),
            occurred_at=parse_time(metadata.get("dispatched_at")),
            schema_version=as_int(i.get("schema_version")),
            deployment_id=as_int(i.get("deployment_id")),
            title=f"Supply Chain incident: {title}" + (" (demo)" if is_demo else ""),
            summary=truncate(i.get("description")),
            url=as_str(i.get("advisories_url")) or as_str(i.get("blog_url")),
            highlights=compact(
                {
                    "Affects your projects": "Yes" if is_affected else "No",
                    "Packages": ", ".join(labels) or None,
                    "Matching projects": str(project_total) if is_affected else None,
                }
            ),
            data={
                "incident_id": incident_id,
                "is_affected": is_affected,
                "is_demo": is_demo,
                "blog_url": as_str(i.get("blog_url")),
                "advisories_url": as_str(i.get("advisories_url")),
                "packages": packages,
                "package_total": package_total,
                "matching_projects": projects,
                "matching_project_total": project_total,
            },
        )
