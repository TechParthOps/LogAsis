from __future__ import annotations

from collections import Counter
from typing import Any


class InvestigationIntelligence:
    """Deterministic cross-case intelligence and investigation health.

    This layer never invents security conclusions. It compares structured facts
    already persisted by CaseStore/EvidenceStore and exposes explainable links
    that an analyst can review.
    """

    SHARED_FIELDS = (
        ("source_ip", "Source IP"),
        ("username", "Username"),
        ("process_name", "Process"),
        ("event_type", "Event type"),
    )

    @staticmethod
    def _case_evidence(case: dict[str, Any], evidence_store) -> list[dict[str, Any]]:
        wanted = {str(x) for x in case.get("evidence_ids", []) if x}
        return [dict(e) for e in evidence_store.records if str(e.get("evidence_id", "")) in wanted]

    @classmethod
    def _signature(cls, evidence: list[dict[str, Any]]) -> dict[str, set[str]]:
        return {
            key: {str(e.get(key, "")).strip().lower() for e in evidence if str(e.get(key, "")).strip()}
            for key, _ in cls.SHARED_FIELDS
        }

    @classmethod
    def compare_cases(cls, selected_case: dict[str, Any], cases: list[dict[str, Any]], evidence_store) -> list[dict[str, Any]]:
        selected = cls._case_evidence(selected_case, evidence_store)
        selected_sig = cls._signature(selected)
        selected_id = str(selected_case.get("case_id", ""))
        matches = []
        for case in cases:
            case_id = str(case.get("case_id", ""))
            if not case_id or case_id == selected_id:
                continue
            evidence = cls._case_evidence(case, evidence_store)
            other_sig = cls._signature(evidence)
            shared = []
            for key, label in cls.SHARED_FIELDS:
                values = sorted(selected_sig[key] & other_sig[key])
                if values:
                    shared.append({"field": key, "label": label, "values": values[:10], "count": len(values)})
            if not shared:
                continue
            score = sum(min(3, item["count"]) for item in shared)
            matches.append({
                "case_id": case_id,
                "title": str(case.get("title", "")),
                "status": str(case.get("status", "")),
                "priority": str(case.get("priority", "")),
                "score": score,
                "shared": shared,
                "evidence_count": len(evidence),
            })
        return sorted(matches, key=lambda x: (-int(x["score"]), x["case_id"]))

    @classmethod
    def build(cls, case: dict[str, Any], cases: list[dict[str, Any]], evidence_store, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        comparisons = cls.compare_cases(case, cases, evidence_store)
        evidence = context.get("evidence") or cls._case_evidence(case, evidence_store)
        severity = Counter(str(e.get("priority", "MEDIUM")).upper() for e in evidence)
        missing = []
        if not evidence:
            missing.append("No linked evidence")
        if not context.get("findings") and not (context.get("intelligence", {}).get("findings") or []):
            missing.append("No evidence-backed findings")
        if not context.get("decision"):
            missing.append("Decision not assessed")
        if context.get("evidence_gaps"):
            missing.append(f"{len(context['evidence_gaps'])} explicit evidence gap(s)")

        health = max(0, 100 - len(missing) * 15)
        if context.get("progress") is not None:
            health = min(100, max(0, round((health + int(context["progress"])) / 2)))

        repeated = []
        for match in comparisons[:5]:
            repeated.append({
                "case_id": match["case_id"],
                "title": match["title"],
                "score": match["score"],
                "shared": match["shared"],
            })

        observations = []
        if comparisons:
            observations.append(f"{len(comparisons)} other case(s) share one or more structured indicators with this case.")
        if severity.get("CRITICAL") or severity.get("HIGH"):
            observations.append("High-priority evidence is present; analyst review should remain focused on attribution and supporting evidence.")
        if context.get("evidence_gaps"):
            observations.append("Evidence gaps remain and should be resolved before a stronger conclusion is recorded.")
        if not observations:
            observations.append("No additional deterministic cross-case observation is available.")

        return {
            "case_id": str(case.get("case_id", "")),
            "case_health": health,
            "cross_case_matches": repeated,
            "cross_case_match_count": len(comparisons),
            "shared_indicator_count": sum(len(x["shared"]) for x in repeated),
            "severity_counts": dict(severity),
            "coverage_gaps": missing,
            "observations": observations,
            "scope": "Structured evidence and persisted case metadata only.",
        }
