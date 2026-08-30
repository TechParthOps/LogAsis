"""
LogAsis v0.4.45 - Case Management & Analyst Workflow.

This module is deliberately independent of the existing CaseStore so it can
be integrated without changing the already-working Evidence, Correlation,
Timeline, Case Intelligence, or AI Analyst implementations.

It persists workflow metadata by case_id:
- status
- priority
- disposition
- analyst notes
- response checklist
- audit history
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseWorkflowStore:
    STATUSES = (
        "New",
        "Open",
        "Investigating",
        "Contained",
        "Resolved",
        "Closed",
    )

    PRIORITIES = (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    DISPOSITIONS = (
        "Undetermined",
        "True Positive",
        "False Positive",
        "Benign / Authorized",
        "Inconclusive",
    )

    RESPONSE_ACTIONS = (
        ("validate_source", "Validate source IP / host authorization"),
        ("review_auth", "Review surrounding successful and failed authentication"),
        ("review_process", "Review process and parent-process context"),
        ("preserve_evidence", "Preserve relevant evidence and analyst notes"),
        ("escalate", "Escalate incident for further response"),
    )

    def __init__(self, path: str | Path = "data/case_workflow.json") -> None:
        self.path = Path(path)
        self.records: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _load(self) -> None:
        if not self.path.exists():
            return

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            self.records = {}
            return

        if isinstance(payload, dict) and isinstance(payload.get("cases"), dict):
            self.records = payload["cases"]
        elif isinstance(payload, dict):
            # Accept a simple case_id -> record mapping too.
            self.records = payload
        else:
            self.records = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": "0.5.0", "cases": self.records}
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _default(self, case: dict[str, Any]) -> dict[str, Any]:
        case_id = str(case.get("case_id", "")).strip()
        now = self._now()
        return {
            "case_id": case_id,
            "status": str(case.get("status") or "New"),
            "priority": str(case.get("priority") or "MEDIUM"),
            "disposition": "Undetermined",
            "analyst_notes": str(case.get("analyst_notes") or ""),
            "response_actions": {
                key: False for key, _ in self.RESPONSE_ACTIONS
            },
            "audit_history": [
                {
                    "timestamp": now,
                    "action": "Case workflow initialized",
                    "details": "v0.4.45 analyst workflow metadata created.",
                }
            ],
            "created_at": now,
            "updated_at": now,
            "investigation_history": [],
            "response_history": [],
            "final_report_ready": False,
            "closure_note": "",
            "handoff": {
                "type": "Incident Response",
                "recipient": "",
                "owner": "",
                "note": "",
                "ready": False,
                "package_generated_at": "",
            },
        }

    def ensure(self, case: dict[str, Any]) -> dict[str, Any]:
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise ValueError("Case record has no case_id.")

        if case_id not in self.records:
            self.records[case_id] = self._default(case)
            self.save()
        else:
            self._migrate(self.records[case_id], case)

        return deepcopy(self.records[case_id])

    def _migrate(
        self,
        record: dict[str, Any],
        case: dict[str, Any],
    ) -> None:
        changed = False

        if not record.get("case_id"):
            record["case_id"] = str(case.get("case_id", ""))
            changed = True

        if "status" not in record:
            record["status"] = str(case.get("status") or "New")
            changed = True

        if "priority" not in record:
            record["priority"] = str(case.get("priority") or "MEDIUM")
            changed = True

        if "disposition" not in record:
            record["disposition"] = "Undetermined"
            changed = True

        if "analyst_notes" not in record:
            record["analyst_notes"] = str(case.get("analyst_notes") or "")
            changed = True

        actions = record.setdefault("response_actions", {})
        for key, _ in self.RESPONSE_ACTIONS:
            if key not in actions:
                actions[key] = False
                changed = True

        record.setdefault("audit_history", [])
        record.setdefault("investigation_history", [])
        record.setdefault("response_history", [])
        record.setdefault("final_report_ready", False)
        record.setdefault("closure_note", "")
        handoff = record.setdefault("handoff", {})
        handoff.setdefault("type", "Incident Response")
        handoff.setdefault("recipient", "")
        handoff.setdefault("owner", "")
        handoff.setdefault("note", "")
        handoff.setdefault("ready", False)
        handoff.setdefault("package_generated_at", "")
        record.setdefault("created_at", self._now())
        record.setdefault("updated_at", self._now())

        if changed:
            record["updated_at"] = self._now()
            self.save()

    def get(self, case_id: str) -> dict[str, Any] | None:
        record = self.records.get(str(case_id))
        return deepcopy(record) if record else None

    def update(
        self,
        case_id: str,
        *,
        status: str | None = None,
        priority: str | None = None,
        disposition: str | None = None,
        analyst_notes: str | None = None,
        response_actions: dict[str, bool] | None = None,
        audit_action: str | None = None,
        audit_details: str = "",
    ) -> dict[str, Any]:
        case_id = str(case_id)
        if case_id not in self.records:
            raise KeyError(f"Unknown case: {case_id}")

        record = self.records[case_id]

        changes: list[str] = []

        if status is not None:
            if status not in self.STATUSES:
                raise ValueError(f"Invalid case status: {status}")
            if record.get("status") != status:
                changes.append(f"Status: {record.get('status')} -> {status}")
                record["status"] = status

        if priority is not None:
            if priority not in self.PRIORITIES:
                raise ValueError(f"Invalid case priority: {priority}")
            if record.get("priority") != priority:
                changes.append(f"Priority: {record.get('priority')} -> {priority}")
                record["priority"] = priority

        if disposition is not None:
            if disposition not in self.DISPOSITIONS:
                raise ValueError(f"Invalid case disposition: {disposition}")
            if record.get("disposition") != disposition:
                changes.append(
                    f"Disposition: {record.get('disposition')} -> {disposition}"
                )
                record["disposition"] = disposition

        if analyst_notes is not None:
            if record.get("analyst_notes", "") != analyst_notes:
                record["analyst_notes"] = analyst_notes
                changes.append("Analyst notes updated")

        if response_actions is not None:
            actions = record.setdefault("response_actions", {})
            for key, value in response_actions.items():
                known = {item[0] for item in self.RESPONSE_ACTIONS}
                if key not in known:
                    raise ValueError(f"Unknown response action: {key}")
                value = bool(value)
                if actions.get(key) != value:
                    actions[key] = value
                    changes.append(
                        f"Response action '{key}' set to {value}"
                    )

        if changes or audit_action:
            now = self._now()
            record["updated_at"] = now
            action = audit_action or "Case workflow updated"
            details = audit_details or "; ".join(changes)
            record.setdefault("audit_history", []).append(
                {
                    "timestamp": now,
                    "action": action,
                    "details": details,
                }
            )
            self.save()

        return deepcopy(record)

    def audit(
        self,
        case_id: str,
        action: str,
        details: str = "",
    ) -> dict[str, Any]:
        return self.update(
            case_id,
            audit_action=action,
            audit_details=details,
        )

    def record_investigation_iteration(
        self,
        case_id: str,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist one deterministic investigation-loop iteration."""
        case_id = str(case_id)
        if case_id not in self.records:
            raise KeyError(f"Unknown case: {case_id}")
        record = self.records[case_id]
        history = record.setdefault("investigation_history", [])
        record.setdefault("response_history", [])
        record.setdefault("final_report_ready", False)
        record.setdefault("closure_note", "")
        history.append(dict(entry))
        now = self._now()
        record["updated_at"] = now
        record.setdefault("audit_history", []).append({
            "timestamp": now,
            "action": "Investigation loop iteration",
            "details": (
                f"Action {entry.get('action_id', '')}; "
                f"results={entry.get('result_count', 0)}; "
                f"linked={entry.get('linked_count', 0)}; "
                f"status={entry.get('status', 'completed')}"
            ),
        })
        self.save()
        return deepcopy(record)

    def record_response_action(
        self,
        case_id: str,
        action: str,
        *,
        status: str = "completed",
        details: str = "",
    ) -> dict[str, Any]:
        """Persist one analyst-controlled response lifecycle action."""
        from datetime import datetime, timezone
        case_id = str(case_id)
        if case_id not in self.records:
            raise KeyError(f"Unknown case: {case_id}")
        record = self.records[case_id]
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": str(action),
            "status": str(status),
            "details": str(details or ""),
        }
        record.setdefault("response_history", []).append(entry)
        record["updated_at"] = entry["timestamp"]
        record.setdefault("audit_history", []).append({
            "timestamp": entry["timestamp"],
            "action": "Response lifecycle action",
            "details": f"{action}: {status}. {details}".strip(),
        })
        self.save()
        return deepcopy(record)

    def set_closure_documentation(
        self,
        case_id: str,
        *,
        final_report_ready: bool | None = None,
        closure_note: str | None = None,
    ) -> dict[str, Any]:
        """Persist closure documentation without changing the disposition."""
        case_id = str(case_id)
        if case_id not in self.records:
            raise KeyError(f"Unknown case: {case_id}")
        record = self.records[case_id]
        changes = []
        if final_report_ready is not None and bool(record.get("final_report_ready", False)) != bool(final_report_ready):
            record["final_report_ready"] = bool(final_report_ready)
            changes.append(f"Final report ready: {bool(final_report_ready)}")
        if closure_note is not None and record.get("closure_note", "") != str(closure_note):
            record["closure_note"] = str(closure_note)
            changes.append("Closure rationale updated")
        if changes:
            now = self._now()
            record["updated_at"] = now
            record.setdefault("audit_history", []).append({
                "timestamp": now,
                "action": "Closure documentation updated",
                "details": "; ".join(changes),
            })
            self.save()
        return deepcopy(record)

    def set_handoff(
        self,
        case_id: str,
        *,
        handoff_type: str | None = None,
        recipient: str | None = None,
        owner: str | None = None,
        note: str | None = None,
        ready: bool | None = None,
        package_generated_at: str | None = None,
    ) -> dict[str, Any]:
        """Persist analyst handoff metadata without changing case disposition."""
        case_id = str(case_id)
        if case_id not in self.records:
            raise KeyError(f"Unknown case: {case_id}")
        record = self.records[case_id]
        handoff = record.setdefault("handoff", {})
        changes = []
        values = {
            "type": handoff_type,
            "recipient": recipient,
            "owner": owner,
            "note": note,
            "ready": ready,
            "package_generated_at": package_generated_at,
        }
        for key, value in values.items():
            if value is None:
                continue
            value = bool(value) if key == "ready" else str(value)
            if handoff.get(key) != value:
                handoff[key] = value
                changes.append(f"{key} updated")
        if changes:
            now = self._now()
            record["updated_at"] = now
            record.setdefault("audit_history", []).append({
                "timestamp": now,
                "action": "Case handoff updated",
                "details": "; ".join(changes),
            })
            self.save()
        return deepcopy(record)

    def export_case(self, case_id: str) -> dict[str, Any]:
        record = self.get(case_id)
        if record is None:
            raise KeyError(f"Unknown case: {case_id}")
        return record

    def clear(self) -> int:
        removed = len(self.records)
        self.records = {}
        self.save()
        return removed

    def all(self) -> list[dict[str, Any]]:
        return [deepcopy(record) for record in self.records.values()]


class CaseWorkflow(CaseWorkflowStore):
    """Backward-compatible 4.x workflow facade over the v0.5 store.

    Supports both historical ``CaseWorkflow(path)`` construction and the
    older ``CaseWorkflow(CaseStore)`` API used by integrations/tests.
    ``apply()`` updates the supplied CaseStore record and persists it through
    that store, while the modern CaseWorkflowStore API remains available.
    """

    def __init__(self, path_or_store: str | Path | Any = "data/case_workflow.json") -> None:
        self.case_store = None
        if hasattr(path_or_store, "cases") and hasattr(path_or_store, "save"):
            # Some historical CaseStore variants exposed ``cases``; use it.
            self.case_store = path_or_store
            path = getattr(path_or_store, "path", "data/case_workflow.json")
        elif hasattr(path_or_store, "records") and hasattr(path_or_store, "save") and hasattr(path_or_store, "get"):
            self.case_store = path_or_store
            path = getattr(path_or_store, "path", "data/case_workflow.json")
        else:
            path = path_or_store
        super().__init__(path)

    def _case_list(self):
        if self.case_store is None:
            return []
        if hasattr(self.case_store, "cases"):
            return self.case_store.cases
        if hasattr(self.case_store, "records"):
            return self.case_store.records
        return []

    def apply(
        self,
        case: dict[str, Any],
        *,
        status: str | None = None,
        priority: str | None = None,
        disposition: str | None = None,
        notes: str | None = None,
        checklist: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        """Apply historical workflow fields directly to a CaseStore case."""
        case_id = str(case.get("case_id", "")).strip()
        if not case_id:
            raise ValueError("Case record has no case_id.")

        # Ensure the modern workflow record exists as well.
        if case_id not in self.records:
            self.ensure(case)

        response_actions = None
        if checklist is not None:
            known_actions = {key for key, _ in self.RESPONSE_ACTIONS}
            response_actions = {
                key: bool(value)
                for key, value in checklist.items()
                if key in known_actions
            }

        updated = self.update(
            case_id,
            status=status,
            priority=priority,
            disposition=disposition,
            analyst_notes=notes,
            response_actions=response_actions,
            audit_action="Case workflow updated",
        )

        # Preserve the historical CaseStore persistence contract.
        target = None
        if self.case_store is not None:
            # Older CaseStore variants/tests expose a mutable ``cases`` list
            # even when the modern store uses ``records``.  Prefer that list
            # when present so the legacy persistence contract is honored.
            legacy_cases = getattr(self.case_store, "cases", None)
            if isinstance(legacy_cases, list):
                for item in legacy_cases:
                    if str(item.get("case_id", "")) == case_id:
                        target = item
                        break
            if target is None and hasattr(self.case_store, "get"):
                target = self.case_store.get(case_id)
            if target is None:
                for item in self._case_list():
                    if str(item.get("case_id", "")) == case_id:
                        target = item
                        break

            if target is not None:
                if status is not None:
                    target["status"] = status
                if priority is not None:
                    target["priority"] = priority
                if disposition is not None:
                    target["disposition"] = disposition
                if notes is not None:
                    target["notes"] = notes
                    target["analyst_notes"] = notes
                if checklist is not None:
                    target["checklist"] = dict(checklist)
                target["workflow"] = updated
                self.case_store.save()

        return target if target is not None else updated

