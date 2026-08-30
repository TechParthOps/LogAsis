from __future__ import annotations

"""Integrity and scope checks for the LogAsis investigation workflow.

This module is intentionally deterministic. It does not make security
decisions; it verifies that UI/reporting consumers do not cross case
boundaries and that references still resolve to available evidence.
"""

from collections import defaultdict
from typing import Any


def evidence_by_id(evidence: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("evidence_id", "")).strip(): row
        for row in evidence
        if str(row.get("evidence_id", "")).strip()
    }


def validate_case_scope(
    case: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate that case-scoped references cannot silently escape the case."""
    findings = findings or []
    case_id = str(case.get("case_id", "")).strip()
    linked_ids = {
        str(value).strip()
        for value in (case.get("evidence_ids") or [])
        if str(value).strip()
    }
    available = evidence_by_id(evidence)

    missing_evidence = sorted(linked_ids - set(available))
    unscoped_evidence = sorted(
        eid for eid in linked_ids
        if str(available.get(eid, {}).get("case_id", "")).strip()
        and str(available[eid].get("case_id")).strip() != case_id
    )

    finding_errors: list[str] = []
    for finding in findings:
        fid = str(finding.get("finding_id", "")).strip() or "UNKNOWN"
        refs = {
            str(value).strip()
            for value in (finding.get("evidence_ids") or [])
            if str(value).strip()
        }
        missing = sorted(refs - linked_ids)
        if missing:
            finding_errors.append(
                f"{fid} references evidence outside the case scope: {', '.join(missing)}"
            )

    errors: list[str] = []
    if not case_id:
        errors.append("Case has no case_id.")
    if missing_evidence:
        errors.append(
            "Case references unavailable evidence: " + ", ".join(missing_evidence)
        )
    if unscoped_evidence:
        errors.append(
            "Case references evidence assigned to another case: "
            + ", ".join(unscoped_evidence)
        )
    errors.extend(finding_errors)

    return {
        "valid": not errors,
        "case_id": case_id,
        "linked_evidence_count": len(linked_ids),
        "missing_evidence_ids": missing_evidence,
        "cross_case_evidence_ids": unscoped_evidence,
        "finding_errors": finding_errors,
        "errors": errors,
    }


def normalize_ioc_inventory(iocs: Any) -> dict[str, list[Any]]:
    """Return a stable IOC inventory shape without inventing classifications."""
    types = ("ipv4", "domain", "url", "hash", "username", "process")
    result = {key: [] for key in types}
    if not isinstance(iocs, dict):
        return result
    for key in types:
        value = iocs.get(key, [])
        if isinstance(value, (list, tuple)):
            result[key] = list(value)
    return result


def evidence_lineage(
    case: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Produce a deterministic evidence lineage view for reports/UI."""
    by_id = evidence_by_id(evidence)
    rows = []
    for eid in case.get("evidence_ids", []) or []:
        key = str(eid).strip()
        row = by_id.get(key)
        rows.append({
            "evidence_id": key,
            "present": row is not None,
            "source_file": row.get("source_file", "") if row else "",
            "line": row.get("line", "") if row else "",
            "timestamp": row.get("timestamp", "") if row else "",
            "event_type": row.get("event_type", "") if row else "",
        })
    return rows
