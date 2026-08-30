from __future__ import annotations

"""Deterministic response and closure lifecycle for LogAsis v0.6.3.

This module plans analyst-controlled response work. It never executes host
containment, deletion, blocking, or other destructive actions. The case
workflow remains the authoritative record of what an analyst has completed.
"""

from typing import Any


class InvestigationResponseEngine:
    """Assess response readiness and controlled case closure."""

    DISPOSITIONS = {
        "Undetermined",
        "True Positive",
        "False Positive",
        "Benign / Authorized",
        "Inconclusive",
    }

    ACTIONS = (
        ("validate_source", "Validate source IP / host authorization", "VALIDATION"),
        ("review_auth", "Review surrounding successful and failed authentication", "VALIDATION"),
        ("review_process", "Review process and parent-process context", "VALIDATION"),
        ("preserve_evidence", "Preserve relevant evidence and analyst notes", "PRESERVATION"),
        ("escalate", "Escalate incident for further response", "ESCALATION"),
    )

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip()

    @classmethod
    def build(
        cls,
        case: dict[str, Any],
        decision: dict[str, Any],
        workflow: dict[str, Any] | None = None,
        intelligence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        workflow = workflow or {}
        intelligence = intelligence or {}
        disposition = cls._norm(workflow.get("disposition") or "Undetermined")
        if disposition not in cls.DISPOSITIONS:
            disposition = "Undetermined"

        gaps = list(decision.get("evidence_gaps", []) or [])
        actions = dict(workflow.get("response_actions", {}) or {})
        action_rows = []

        for key, label, category in cls.ACTIONS:
            checked = bool(actions.get(key, False))
            required = False
            reason = "Optional workflow action."
            if key == "preserve_evidence":
                required = bool(gaps) or bool(decision.get("observed_evidence_ids"))
                reason = "Preservation should be recorded before final case closure."
            elif key == "escalate":
                required = (
                    str(decision.get("decision", "")).upper() == "CONFIRMED"
                    or str(case.get("priority", "")).upper() == "CRITICAL"
                    or disposition == "True Positive"
                )
                reason = "Escalation is recommended when the case is confirmed or high-impact."
            elif key == "validate_source":
                required = any(str(g.get("category", "")).upper() == "SOURCE_ATTRIBUTION" for g in gaps)
                reason = "Source attribution remains an explicit investigation requirement."
            elif key == "review_auth":
                required = any(str(g.get("category", "")).upper() in {"AUTHENTICATION", "SESSION"} for g in gaps)
                reason = "Authentication/session gaps should be resolved before disposition."
            elif key == "review_process":
                required = any(str(g.get("category", "")).upper() in {"PROCESS_ATTRIBUTION", "PRIVILEGE"} for g in gaps)
                reason = "Process or privilege attribution gaps should be reviewed before closure."

            action_rows.append({
                "action_id": key,
                "label": label,
                "category": category,
                "required": required,
                "completed": checked,
                "state": "COMPLETE" if checked else ("REQUIRED" if required else "OPTIONAL"),
                "reason": reason,
            })

        blockers: list[str] = []
        if gaps:
            blockers.append(f"{len(gaps)} evidence gap(s) remain open.")
        if disposition == "Undetermined":
            blockers.append("A final analyst disposition has not been recorded.")
        required_unchecked = [x for x in action_rows if x["required"] and not x["completed"]]
        if required_unchecked:
            blockers.append(
                "Required response action(s) remain unchecked: "
                + ", ".join(x["action_id"] for x in required_unchecked) + "."
            )

        if blockers:
            readiness = "NOT_READY"
            lifecycle = "RESPONSE_REQUIRED" if gaps or required_unchecked else "DECISION_REQUIRED"
            recommendation = "Complete the blocking investigation/response items before closing the case."
        elif disposition in {"True Positive", "Inconclusive"}:
            readiness = "READY_FOR_HANDOFF"
            lifecycle = "RESPONSE_COMPLETE"
            recommendation = "Review the final report and hand the case to the appropriate response/incident owner."
        elif disposition in {"False Positive", "Benign / Authorized"}:
            readiness = "READY_FOR_CLOSURE"
            lifecycle = "CLOSURE_READY"
            recommendation = "Record the final rationale and close the case with the selected disposition."
        else:
            readiness = "NOT_READY"
            lifecycle = "DECISION_REQUIRED"
            recommendation = "Record a defensible disposition before closure."

        history = list(workflow.get("response_history", []) or [])
        report_ready = bool(workflow.get("final_report_ready", False))
        closure_note = cls._norm(workflow.get("closure_note"))
        if readiness == "READY_FOR_CLOSURE" and not closure_note:
            blockers.append("A final closure rationale has not been recorded.")
            readiness = "NOT_READY"
            lifecycle = "CLOSURE_DOCUMENTATION"
            recommendation = "Record a concise closure rationale before closing the case."

        return {
            "case_id": cls._norm(case.get("case_id")),
            "decision": cls._norm(decision.get("decision") or "INSUFFICIENT_EVIDENCE"),
            "confidence": cls._norm(decision.get("confidence") or "LOW"),
            "disposition": disposition,
            "readiness": readiness,
            "lifecycle": lifecycle,
            "recommendation": recommendation,
            "blockers": blockers,
            "required_actions": [x["action_id"] for x in action_rows if x["required"]],
            "completed_required_actions": [x["action_id"] for x in action_rows if x["required"] and x["completed"]],
            "actions": action_rows,
            "open_gap_count": len(gaps),
            "final_report_ready": report_ready,
            "closure_note_present": bool(closure_note),
            "response_iteration_count": len(history),
            "scope": "Deterministic workflow assessment; no host-side response action is executed.",
        }

    @classmethod
    def can_close(cls, assessment: dict[str, Any]) -> bool:
        return assessment.get("readiness") == "READY_FOR_CLOSURE"

    @staticmethod
    def make_response_history_entry(action: str, *, status: str, details: str = "") -> dict[str, Any]:
        from datetime import datetime, timezone
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": str(action),
            "status": str(status),
            "details": str(details or ""),
        }
