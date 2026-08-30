from __future__ import annotations

"""Bounded Investigation -> Evidence -> Case workflow for LogAsis.

This module deliberately composes the existing EvidenceStore and CaseStore.
It does not create a new persistence layer and does not classify an event as
malicious. Selecting a deterministic investigation candidate simply promotes
that observed event into analyst evidence and, optionally, a case.
"""

from typing import Any

from core.evidence import EvidenceStore
from core.cases import CaseStore


def create_case_from_candidate(
    candidate: dict[str, Any],
    *,
    evidence_store: EvidenceStore,
    case_store: CaseStore,
    source_file: str = "",
    raw_log: str = "",
) -> dict[str, Any]:
    """Promote one investigation candidate into evidence and a case.

    The operation is idempotent:
    - an already-existing evidence record is reused;
    - an existing case linked to that evidence is reused.

    Returns a small workflow result suitable for the GUI and tests.
    """
    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a dictionary")

    if not str(candidate.get("line", "")).strip():
        raise ValueError("Investigation candidate has no record/line identifier.")

    evidence, evidence_created = evidence_store.add_candidate(
        candidate,
        source_file=source_file,
        raw_log=raw_log,
    )
    if evidence is None:
        raise RuntimeError("Evidence creation returned no record.")

    case, case_created = case_store.create_from_evidence(evidence)
    if case is None:
        raise RuntimeError("Case creation returned no record.")

    return {
        "evidence": evidence,
        "case": case,
        "evidence_created": bool(evidence_created),
        "case_created": bool(case_created),
    }
