from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from core.ioc import extract_iocs, flatten_iocs


class InvestigationContextBuilder:
    """Build a deterministic, case-scoped command-center context.

    This is a presentation/integration layer. It does not create new security
    conclusions; it assembles facts already produced by the existing LogAsis
    evidence, detection, IOC, intelligence, decision, and workflow engines.
    """

    STAGES = (
        ("evidence", "Evidence linked"),
        ("timeline", "Timeline reviewed"),
        ("correlation", "Correlation reviewed"),
        ("findings", "Findings reviewed"),
        ("decision", "Decision assessed"),
        ("gaps", "Evidence gaps assessed"),
        ("actions", "Investigation actions"),
        ("disposition", "Disposition"),
    )

    @staticmethod
    def _case_evidence(case: dict[str, Any], evidence_store) -> list[dict[str, Any]]:
        wanted = {str(x) for x in (case.get("evidence_ids") or []) if x}
        return [
            dict(record)
            for record in evidence_store.records
            if str(record.get("evidence_id", "")) in wanted
        ]

    @staticmethod
    def _filter_findings(detections: Iterable[dict[str, Any]], evidence_ids: set[str]) -> list[dict[str, Any]]:
        result = []
        for finding in detections or []:
            refs = {str(x) for x in (finding.get("evidence_ids") or []) if x}
            if refs & evidence_ids:
                result.append(dict(finding))
        return result

    @staticmethod
    def _filter_iocs(iocs: dict[str, list[dict[str, Any]]], evidence_ids: set[str]) -> list[dict[str, Any]]:
        result = []
        for item in flatten_iocs(iocs or {}):
            refs = {str(x) for x in (item.get("evidence_ids") or []) if x}
            if not refs or refs & evidence_ids:
                result.append(dict(item))
        # Same IOC can be repeated across fields/events. Keep one inventory row
        # per type/value while retaining the largest occurrence count.
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for item in result:
            key = (str(item.get("type", "")), str(item.get("value", "")))
            current = unique.get(key)
            if current is None or int(item.get("occurrences", 0) or 0) > int(current.get("occurrences", 0) or 0):
                unique[key] = item
        return sorted(
            unique.values(),
            key=lambda x: (-int(x.get("occurrences", 0) or 0), str(x.get("type", "")), str(x.get("value", ""))),
        )

    @classmethod
    def build(
        cls,
        case: dict[str, Any],
        evidence_store,
        correlation_engine,
        case_intelligence,
        workflow,
        detections: Iterable[dict[str, Any]] | None = None,
        all_iocs: dict[str, list[dict[str, Any]]] | None = None,
        decision: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        case = dict(case or {})
        evidence = cls._case_evidence(case, evidence_store)
        evidence_ids = {str(x.get("evidence_id", "")) for x in evidence if x.get("evidence_id")}

        correlation = correlation_engine.correlate_case(case)
        intelligence = case_intelligence.build(case)
        findings = cls._filter_findings(detections or [], evidence_ids)

        if all_iocs is None:
            all_iocs = extract_iocs(evidence)
        iocs = cls._filter_iocs(all_iocs, evidence_ids)

        workflow_record = workflow.ensure(case)
        if decision is None:
            # Keep import local to avoid coupling the context builder to GUI.
            from core.case_decision import CaseDecisionEngine
            decision = CaseDecisionEngine.build(case, intelligence)

        gaps = list(decision.get("evidence_gaps", []) or [])
        from core.investigation_response import InvestigationResponseEngine
        response = InvestigationResponseEngine.build(case, decision, workflow_record, intelligence)
        audit = list(workflow_record.get("audit_history", []) or [])
        response_actions = workflow_record.get("response_actions", {}) or {}

        # A review stage means the underlying artifact has actually been
        # generated/inspected, not merely that a case exists.
        stages = {
            "evidence": bool(evidence),
            "timeline": bool(evidence),
            "correlation": True,  # the deterministic engine has evaluated it
            "findings": bool(findings or intelligence.get("findings")),
            "decision": bool(decision),
            "gaps": bool(decision),
            "actions": (not gaps) or bool(audit) or any(response_actions.values()),
            "disposition": str(workflow_record.get("disposition", "Undetermined")) != "Undetermined",
        }
        completed = sum(1 for value in stages.values() if value)
        progress = round((completed / len(cls.STAGES)) * 100)

        if gaps:
            next_step = str(
                gaps[0].get("recommended_action")
                or gaps[0].get("description")
                or "Review the first evidence gap."
            )
            next_reason = f"{len(gaps)} evidence gap(s) remain."
            next_kind = "Evidence gap"
        elif str(workflow_record.get("disposition", "Undetermined")) == "Undetermined":
            next_step = "Record an analyst disposition after reviewing the evidence-backed decision."
            next_reason = "The investigation has no final disposition."
            next_kind = "Disposition"
        elif not response_actions.get("preserve_evidence", False):
            next_step = "Preserve relevant evidence and analyst notes."
            next_reason = "Evidence preservation is still unchecked."
            next_kind = "Response action"
        else:
            next_step = "Export or hand off the completed case report."
            next_reason = "No outstanding deterministic investigation gap is visible."
            next_kind = "Closure"

        event_types = Counter(str(x.get("event_type", "") or "UNKNOWN") for x in evidence)
        source_ips = sorted({str(x.get("source_ip", "")).strip() for x in evidence if str(x.get("source_ip", "")).strip()})
        users = sorted({str(x.get("username", "")).strip() for x in evidence if str(x.get("username", "")).strip()})

        findings_count = len(findings) or len(intelligence.get("findings", []) or [])
        related_cases = 0  # Filled by the UI/store caller when cross-case search is available.

        return {
            "case_id": str(case.get("case_id", "")),
            "title": str(case.get("title", "")),
            "status": str(case.get("status", "")),
            "priority": str(case.get("priority", "")),
            "disposition": str(workflow_record.get("disposition", "Undetermined")),
            "evidence": evidence,
            "evidence_count": len(evidence),
            "evidence_ids": sorted(evidence_ids),
            "findings": findings,
            "findings_count": findings_count,
            "iocs": iocs,
            "ioc_count": len(iocs),
            "correlation": correlation,
            "relationship_count": len(correlation.get("relationships", []) or []),
            "candidate_count": len(correlation.get("related_candidates", []) or []),
            "intelligence": intelligence,
            "decision": decision,
            "evidence_gaps": gaps,
            "workflow": workflow_record,
            "audit_count": len(audit),
            "response_actions": response_actions,
            "response": response,
            "progress": progress,
            "completed_stages": completed,
            "stage_count": len(cls.STAGES),
            "stages": [
                {
                    "id": stage_id,
                    "label": label,
                    "complete": bool(stages[stage_id]),
                }
                for stage_id, label in cls.STAGES
            ],
            "next_step": next_step,
            "next_reason": next_reason,
            "next_kind": next_kind,
            "source_ips": source_ips,
            "users": users,
            "event_types": dict(event_types),
            "related_cases": related_cases,
            "chain": [
                ("Events", len(evidence)),
                ("Evidence", len(evidence)),
                ("Findings", findings_count),
                ("IOCs", len(iocs)),
                ("Case", 1),
                ("Correlations", len(correlation.get("relationships", []) or [])),
                ("Decision", 1 if decision else 0),
                ("Gaps", len(gaps)),
            ],
        }
