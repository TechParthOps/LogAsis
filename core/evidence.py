from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class EvidenceRecord(dict):
    """Backward-compatible structured evidence record.

    LogAsis 4.x exposed ``EvidenceRecord`` to the case-intelligence and
    workflow API surface. v0.5 keeps the canonical persistence format as
    dictionaries while preserving the old public type.
    """

    DEFAULTS = {
        "evidence_id": "", "status": "New", "analyst_notes": "",
        "source_file": "", "line": "", "timestamp": "", "event_type": "",
        "event_id": "", "priority": "MEDIUM", "score": 0,
        "source_ip": "", "destination_ip": "", "destination_port": "",
        "username": "", "process_name": "", "command": "",
        "parent_image": "", "parent_command": "", "action": "",
        "severity": "", "hashes": "", "reasons": [], "message": "",
        "raw_log": "", "triage_role": "Observed", "investigation_action_id": "",
    }

    # Positional constructor order retained from the LogAsis 4.x public API.
    # Keep this explicit: a number of integrations/tests construct evidence
    # records without keyword arguments.
    _POSITIONAL_FIELDS = (
        "evidence_id", "line", "priority", "score", "timestamp",
        "event_type", "source_ip", "destination_ip", "destination_port",
        "username", "process_name", "parent_image", "parent_command",
        "action",
    )

    def __init__(self, *args, **kwargs):
        data = dict(self.DEFAULTS)
        data["reasons"] = []

        if args:
            # New/canonical form: EvidenceRecord(mapping)
            if len(args) == 1 and isinstance(args[0], (dict, EvidenceRecord)):
                data.update(dict(args[0]))
            else:
                # Legacy 4.x form: EvidenceRecord(field1, field2, ...)
                if len(args) > len(self._POSITIONAL_FIELDS):
                    raise TypeError(
                        f"EvidenceRecord accepts at most {len(self._POSITIONAL_FIELDS)} "
                        "legacy positional arguments"
                    )
                data.update(dict(zip(self._POSITIONAL_FIELDS, args)))

        # Older callers used raw_message; canonical v0.5 uses raw_log/message.
        raw_message = kwargs.pop("raw_message", None)
        data.update(kwargs)
        if raw_message is not None:
            data["raw_log"] = raw_message
            data.setdefault("message", raw_message)

        data["reasons"] = list(data.get("reasons") or [])
        super().__init__(data)

    @classmethod
    def from_candidate(cls, candidate, source_file="", raw_log=""):
        candidate = dict(candidate or {})
        candidate.setdefault("source_file", source_file)
        if raw_log:
            candidate.setdefault("raw_log", raw_log)
        return cls(candidate)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def to_dict(self):
        return dict(self)


class EvidenceStore:
    """Persistent local store for analyst-reviewed investigation evidence."""

    STATUSES = ("New", "Reviewed", "Escalated", "Closed")
    PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def __init__(self, path: str | Path = "data/evidence.json"):
        self.path = Path(path)
        self.records: list[dict[str, Any]] = []
        self.load()

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
            match = str(record.get("evidence_id", "")).upper().removeprefix("EV-")
            if match.isdigit():
                highest = max(highest, int(match))
        return f"EV-{highest + 1:06d}"

    @staticmethod
    def _candidate_key(candidate: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(candidate.get("source_file", "")),
            str(candidate.get("line", "")),
            str(candidate.get("timestamp", "")),
        )

    def add_candidate(
        self,
        candidate: dict[str, Any],
        source_file: str = "",
        raw_log: str = "",
    ) -> tuple[dict[str, Any] | None, bool]:
        """Add one investigation candidate unless the same source/record exists."""
        candidate_key = self._candidate_key({**candidate, "source_file": source_file})
        for existing in self.records:
            existing_key = self._candidate_key(existing)
            if existing_key == candidate_key:
                return existing, False

        record = {
            "evidence_id": self._next_id(),
            "status": "New",
            "analyst_notes": "",
            "source_file": source_file,
            "line": candidate.get("line", ""),
            "timestamp": candidate.get("timestamp", ""),
            "event_type": candidate.get("event_type", ""),
            "event_id": candidate.get("event_id", ""),
            "priority": candidate.get("priority", "MEDIUM"),
            "score": int(candidate.get("score", 0) or 0),
            "source_ip": candidate.get("source_ip", ""),
            "destination_ip": candidate.get("destination_ip", ""),
            "destination_port": candidate.get("destination_port", ""),
            "username": candidate.get("username", ""),
            "process_name": candidate.get("process_name", ""),
            "command": candidate.get("command", ""),
            "parent_image": candidate.get("parent_image", ""),
            "parent_command": candidate.get("parent_command", ""),
            "action": candidate.get("action", ""),
            "severity": candidate.get("severity", ""),
            "hashes": candidate.get("hashes", ""),
            "reasons": list(candidate.get("reasons", []) or []),
            "message": candidate.get("message", ""),
            "raw_log": raw_log or candidate.get("raw_log", ""),
            "triage_role": candidate.get("triage_role", "Observed"),
            "investigation_action_id": candidate.get("investigation_action_id", ""),
        }
        self.records.append(record)
        self.save()
        return record, True

    def update(self, evidence_id: str, **changes: Any) -> dict[str, Any] | None:
        for record in self.records:
            if record.get("evidence_id") == evidence_id:
                if "status" in changes and changes["status"] not in self.STATUSES:
                    raise ValueError(f"Invalid evidence status: {changes['status']}")
                record.update(changes)
                self.save()
                return record
        return None

    def clear(self) -> int:
        """Remove all locally stored evidence records and persist the empty collection.

        The caller is responsible for confirmation before invoking this method.
        Returns the number of records removed.
        """
        removed = len(self.records)
        self.records = []
        self.save()
        return removed

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        return next(
            (record for record in self.records if record.get("evidence_id") == evidence_id),
            None,
        )

    def filter(self, status: str = "All", priority: str = "All") -> list[dict[str, Any]]:
        records = self.records
        if status != "All":
            records = [r for r in records if r.get("status") == status]
        if priority != "All":
            records = [r for r in records if r.get("priority") == priority]
        return list(records)

    def export_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.records, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target
