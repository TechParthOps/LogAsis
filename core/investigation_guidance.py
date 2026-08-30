from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class InvestigationGuidance:
    stage: str
    title: str
    detail: str
    next_action: str
    completed: tuple[str, ...]
    remaining: tuple[str, ...]


STAGES = (
    "ingest",
    "triage",
    "investigate",
    "case",
    "response",
    "closure",
)


def _count(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, dict):
        return sum(len(v) if isinstance(v, (list, tuple, set)) else 1 for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return 1


def derive_guidance(
    *,
    event_count: int = 0,
    finding_count: int = 0,
    ioc_count: int = 0,
    evidence_count: int = 0,
    case_selected: bool = False,
    case_status: str = "",
    response_count: int = 0,
) -> InvestigationGuidance:
    """Derive the smallest useful next investigation action.

    This is workflow guidance only. It never changes findings, severity,
    evidence, case state, or response decisions.
    """
    event_count = int(event_count or 0)
    finding_count = int(finding_count or 0)
    ioc_count = int(ioc_count or 0)
    evidence_count = int(evidence_count or 0)
    response_count = int(response_count or 0)
    status = str(case_status or "").strip().lower()

    completed: list[str] = []
    remaining: list[str] = []

    if event_count:
        completed.append("Log loaded")
    else:
        remaining.append("Load a log")

    if finding_count or ioc_count:
        completed.append("Initial triage")
    elif event_count:
        remaining.append("Review Findings / IOCs")

    if evidence_count:
        completed.append("Evidence collected")
    elif finding_count:
        remaining.append("Preserve supporting evidence")

    if case_selected:
        completed.append("Case selected")
    elif finding_count:
        remaining.append("Create or select a case")

    if response_count:
        completed.append("Response recorded")
    elif case_selected and status not in {"closed", "resolved"}:
        remaining.append("Record response / disposition")

    if status in {"closed", "resolved"}:
        completed.append("Case closed")

    if not event_count:
        return InvestigationGuidance(
            "ingest", "Start investigation", "No log is loaded.",
            "Load a log", tuple(completed), tuple(remaining)
        )

    if not finding_count and not ioc_count:
        return InvestigationGuidance(
            "triage", "Triage the dataset",
            "The log is loaded; review the generated findings and IOC inventory.",
            "Open Findings / IOCs", tuple(completed), tuple(remaining)
        )

    if not evidence_count:
        return InvestigationGuidance(
            "investigate", "Strengthen the evidence",
            "Security signals exist, but supporting evidence has not been preserved.",
            "Review evidence", tuple(completed), tuple(remaining)
        )

    if not case_selected:
        return InvestigationGuidance(
            "case", "Move into case investigation",
            "The dataset has evidence but no selected case is active.",
            "Open or create a case", tuple(completed), tuple(remaining)
        )

    if status in {"closed", "resolved"}:
        return InvestigationGuidance(
            "closure", "Investigation complete",
            "The selected case has been resolved/closed.",
            "Review the case report", tuple(completed), tuple(remaining)
        )

    if not response_count:
        return InvestigationGuidance(
            "response", "Complete the response decision",
            "The case has supporting evidence; record the response or disposition.",
            "Open Response / Closure", tuple(completed), tuple(remaining)
        )

    return InvestigationGuidance(
        "closure", "Review and close the case",
        "Core investigation steps are present. Verify the evidence and disposition.",
        "Review Case Intelligence", tuple(completed), tuple(remaining)
    )


def summarize_ioc_count(iocs: Any) -> int:
    return _count(iocs)
