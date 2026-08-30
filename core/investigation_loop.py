from __future__ import annotations

"""Deterministic investigation-loop orchestration for LogAsis v0.6.2.

The loop is intentionally thin: InvestigationActionEngine remains responsible
for evidence-bounded searches, while CaseDecisionEngine remains the source of
truth for decision/gap state. This module answers one question: "What should
the analyst do next, and what changed after the last action?"
"""

from datetime import datetime, timezone
from typing import Any


class InvestigationLoopEngine:
    """Build an explainable next-step plan around a case decision."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    @classmethod
    def _sort_gaps(cls, gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            [dict(g) for g in gaps or []],
            key=lambda g: (
                cls.SEVERITY_ORDER.get(str(g.get("severity", "MEDIUM")).upper(), 9),
                str(g.get("gap_id", "")),
            ),
        )

    @classmethod
    def build_plan(
        cls,
        case: dict[str, Any],
        decision: dict[str, Any],
        workflow: dict[str, Any] | None = None,
        action_history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        workflow = workflow or {}
        gaps = cls._sort_gaps(list(decision.get("evidence_gaps", []) or []))
        history = list(action_history or workflow.get("investigation_history", []) or [])

        if gaps:
            gap = gaps[0]
            action_id = str(gap.get("gap_id", "")).strip()
            phase = "EVIDENCE_COLLECTION"
            state = "ACTION_REQUIRED"
            next_step = str(
                gap.get("recommended_action")
                or gap.get("description")
                or "Review the highest-priority evidence gap."
            )
            rationale = (
                f"{gap.get('gap_id', 'Gap')} is the highest-priority unresolved "
                f"{str(gap.get('category', 'investigation')).lower()} gap."
            )
        elif str(workflow.get("disposition", "Undetermined")) == "Undetermined":
            action_id = ""
            phase = "DECISION_REVIEW"
            state = "DECISION_REQUIRED"
            next_step = "Review the deterministic decision and record a case disposition."
            rationale = "No explicit evidence gaps remain, but the case has no recorded disposition."
        else:
            action_id = ""
            phase = "CLOSURE"
            state = "READY_TO_CLOSE"
            next_step = "Review the final evidence-backed report and close or escalate the case."
            rationale = "The current decision has no outstanding gaps and a disposition is recorded."

        last = history[-1] if history else {}
        return {
            "case_id": str(case.get("case_id", "")),
            "state": state,
            "phase": phase,
            "next_action_id": action_id,
            "next_step": next_step,
            "rationale": rationale,
            "open_gap_count": len(gaps),
            "open_gaps": gaps,
            "decision": str(decision.get("decision", "NOT_ESTABLISHED")),
            "confidence": str(decision.get("confidence", "LOW")),
            "iteration": len(history),
            "last_action": str(last.get("action_id", "")),
            "last_result_count": int(last.get("result_count", 0) or 0),
            "last_linked_count": int(last.get("linked_count", 0) or 0),
        }

    @staticmethod
    def make_history_entry(
        action_id: str,
        *,
        result_count: int = 0,
        linked_count: int = 0,
        role: str = "",
        status: str = "completed",
        details: str = "",
    ) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action_id": str(action_id),
            "result_count": int(result_count or 0),
            "linked_count": int(linked_count or 0),
            "role": str(role or ""),
            "status": str(status or "completed"),
            "details": str(details or ""),
        }

    @classmethod
    def after_action(
        cls,
        case: dict[str, Any],
        before_decision: dict[str, Any],
        after_decision: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        before = {str(g.get("gap_id", "")) for g in before_decision.get("evidence_gaps", []) or []}
        after = {str(g.get("gap_id", "")) for g in after_decision.get("evidence_gaps", []) or []}
        resolved = sorted(x for x in before - after if x)
        introduced = sorted(x for x in after - before if x)

        plan = cls.build_plan(case, after_decision, action_history=history)
        plan.update({
            "resolved_gaps": resolved,
            "introduced_gaps": introduced,
            "gap_delta": len(after) - len(before),
            "decision_changed": (
                str(before_decision.get("decision", "")) != str(after_decision.get("decision", ""))
                or str(before_decision.get("confidence", "")) != str(after_decision.get("confidence", ""))
            ),
        })
        return plan
