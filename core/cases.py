from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseStore:
    """Persistent local incident/case store linking analyst evidence."""

    STATUSES = ("New", "Open", "Investigating", "Contained", "Resolved", "Closed")
    PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def __init__(self, path: str | Path = "data/cases.json"):
        self.path = Path(path)
        self.records: list[dict[str, Any]] = []
        self.load()

    @property
    def cases(self) -> list[dict[str, Any]]:
        """Backward-compatible alias for the historical ``cases`` list."""
        return self.records

    @cases.setter
    def cases(self, value: list[dict[str, Any]]) -> None:
        self.records = list(value or [])

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            self.records = []
            return self.records
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self.records = payload if isinstance(payload, list) else []
        except (OSError, json.JSONDecodeError):
            self.records = []
        return self.records

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.stem}-", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.records, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _next_id(self) -> str:
        highest = 0
        for record in self.records:
            value = str(record.get("case_id", "")).upper().removeprefix("CASE-")
            if value.isdigit():
                highest = max(highest, int(value))
        return f"CASE-{highest + 1:06d}"

    def create_from_evidence(self, evidence: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        evidence_id = str(evidence.get("evidence_id", "")).strip()
        for case in self.records:
            if evidence_id and evidence_id in case.get("evidence_ids", []):
                return case, False

        priority = str(evidence.get("priority", "MEDIUM") or "MEDIUM").upper()
        if priority not in self.PRIORITIES:
            priority = "MEDIUM"

        event_type = str(evidence.get("event_type", "") or "Security Event").strip()
        source_ip = str(evidence.get("source_ip", "") or "").strip()
        username = str(evidence.get("username", "") or "").strip()
        title = f"{event_type}"
        context = []
        if source_ip:
            context.append(source_ip)
        if username:
            context.append(username)
        if context:
            title += " — " + " / ".join(context)

        now = self._now()
        record = {
            "case_id": self._next_id(),
            "status": "New",
            "priority": priority,
            "title": title[:180],
            "description": (
                "Case created from analyst-selected evidence. "
                "Validate the surrounding events and host context before drawing conclusions."
            ),
            "analyst_notes": "",
            "evidence_ids": [evidence_id] if evidence_id else [],
            "source_file": evidence.get("source_file", ""),
            "created_at": now,
            "updated_at": now,
        }
        self.records.append(record)
        self.save()
        return record, True

    def update(self, case_id: str, **changes: Any) -> dict[str, Any] | None:
        for record in self.records:
            if record.get("case_id") != case_id:
                continue
            if "status" in changes and changes["status"] not in self.STATUSES:
                raise ValueError(f"Invalid case status: {changes['status']}")
            if "priority" in changes and changes["priority"] not in self.PRIORITIES:
                raise ValueError(f"Invalid case priority: {changes['priority']}")
            record.update(changes)
            record["updated_at"] = self._now()
            self.save()
            return record
        return None

    def link_evidence(self, case_id: str, evidence_id: str) -> dict[str, Any] | None:
        for record in self.records:
            if record.get("case_id") != case_id:
                continue
            ids = list(record.get("evidence_ids", []) or [])
            if evidence_id and evidence_id not in ids:
                ids.append(evidence_id)
                record["evidence_ids"] = ids
                record["updated_at"] = self._now()
                self.save()
            return record
        return None

    def all(self) -> list[dict[str, Any]]:
        """Return a snapshot of all stored cases for read-only consumers."""
        return list(self.records)

    def get(self, case_id: str) -> dict[str, Any] | None:
        return next(
            (record for record in self.records if record.get("case_id") == case_id),
            None,
        )

    def clear(self) -> int:
        removed = len(self.records)
        self.records = []
        self.save()
        return removed

    def export_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.records, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target
