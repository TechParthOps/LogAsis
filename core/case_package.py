from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CasePackageError(ValueError):
    """Raised when an investigation package cannot be safely imported."""


class CasePackageEngine:
    """Create, validate, export, and import reusable LogAsis case packages.

    A package is a portable snapshot of one case and its case-scoped evidence
    and workflow state. Import is conservative: existing records are never
    silently overwritten. Evidence IDs are remapped on collision and the case
    ID is remapped when the destination already contains a different case.
    """

    SCHEMA = "logasis.case-package"
    VERSION = "1.0"
    PACKAGE_TYPES = ("Investigation Package", "Case Handoff Package")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _json_hash(value: Any) -> str:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def build(
        cls,
        *,
        case: dict[str, Any],
        workflow: dict[str, Any],
        evidence: list[dict[str, Any]],
        investigation_package: dict[str, Any] | None = None,
        package_type: str = "Investigation Package",
        source_instance: str = "LogAsis",
    ) -> dict[str, Any]:
        if not case.get("case_id"):
            raise CasePackageError("Cannot package a case without a case_id.")
        if package_type not in cls.PACKAGE_TYPES:
            package_type = cls.PACKAGE_TYPES[0]

        linked = {str(x) for x in (case.get("evidence_ids") or []) if x}
        scoped = [copy.deepcopy(x) for x in evidence if str(x.get("evidence_id", "")) in linked]
        package = {
            "schema": cls.SCHEMA,
            "schema_version": cls.VERSION,
            "package_type": package_type,
            "package_id": f"PKG-{uuid.uuid4().hex[:12].upper()}",
            "created_at": cls._now(),
            "source_instance": source_instance,
            "case": copy.deepcopy(case),
            "workflow": copy.deepcopy(workflow or {}),
            "evidence": scoped,
            "investigation": copy.deepcopy(investigation_package or {}),
            "import_history": [],
            "transfer_state": {
                "status": "exported",
                "original_case_id": str(case.get("case_id")),
                "imported_case_id": "",
                "evidence_id_map": {},
                "reassessment_required": False,
            },
        }
        package["integrity"] = {
            "case_sha256": cls._json_hash(package["case"]),
            "workflow_sha256": cls._json_hash(package["workflow"]),
            "evidence_sha256": cls._json_hash(package["evidence"]),
            "package_sha256": cls._json_hash({
                "schema": package["schema"],
                "schema_version": package["schema_version"],
                "case": package["case"],
                "workflow": package["workflow"],
                "evidence": package["evidence"],
                "investigation": package["investigation"],
            }),
        }
        return package

    @classmethod
    def validate(cls, package: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        if not isinstance(package, dict):
            return {"valid": False, "errors": ["Package must be a JSON object."]}

        if package.get("schema") != cls.SCHEMA:
            errors.append("Unsupported package schema.")
        if str(package.get("schema_version", "")) != cls.VERSION:
            errors.append(f"Unsupported package version: {package.get('schema_version')!r}.")

        case = package.get("case")
        workflow = package.get("workflow")
        evidence = package.get("evidence")
        if not isinstance(case, dict) or not case.get("case_id"):
            errors.append("Package has no valid case record.")
        if not isinstance(workflow, dict):
            errors.append("Package has no valid workflow record.")
        if not isinstance(evidence, list):
            errors.append("Package evidence must be a list.")

        if isinstance(case, dict) and isinstance(evidence, list):
            evidence_ids = {str(x.get("evidence_id", "")) for x in evidence if isinstance(x, dict)}
            missing = [
                str(x) for x in (case.get("evidence_ids") or [])
                if str(x) and str(x) not in evidence_ids
            ]
            if missing:
                errors.append("Case references evidence not included in the package: " + ", ".join(missing))

        return {
            "valid": not errors,
            "errors": errors,
            "case_id": str(case.get("case_id", "")) if isinstance(case, dict) else "",
            "evidence_count": len(evidence) if isinstance(evidence, list) else 0,
        }

    @staticmethod
    def export_json(package: dict[str, Any], path: str | Path) -> Path:
        validation = CasePackageEngine.validate(package)
        if not validation["valid"]:
            raise CasePackageError("; ".join(validation["errors"]))
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding="utf-8")
        return destination

    @staticmethod
    def load_json(path: str | Path) -> dict[str, Any]:
        source = Path(path)
        try:
            package = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CasePackageError(f"Could not read investigation package: {exc}") from exc
        validation = CasePackageEngine.validate(package)
        if not validation["valid"]:
            raise CasePackageError("; ".join(validation["errors"]))
        return package

    @classmethod
    def import_into_stores(cls, package: dict[str, Any], case_store, evidence_store, workflow_store) -> dict[str, Any]:
        validation = cls.validate(package)
        if not validation["valid"]:
            raise CasePackageError("; ".join(validation["errors"]))

        original_case = copy.deepcopy(package["case"])
        original_workflow = copy.deepcopy(package["workflow"])
        evidence_rows = copy.deepcopy(package["evidence"])

        existing_cases = {str(x.get("case_id")): x for x in case_store.all()}
        case_id = str(original_case.get("case_id"))
        imported_case_id = case_id
        existing = existing_cases.get(case_id)

        if existing is not None:
            # Never overwrite an existing case. Even when the source case uses
            # the same evidence IDs, a transfer may contain newer workflow or
            # evidence content. Import it as an explicit revision instead.
            suffix = 1
            while f"{case_id}-R{suffix}" in existing_cases:
                suffix += 1
            imported_case_id = f"{case_id}-R{suffix}"

        existing_evidence = {str(x.get("evidence_id")): x for x in evidence_store.records}
        evidence_map: dict[str, str] = {}
        imported_evidence: list[dict[str, Any]] = []

        for row in evidence_rows:
            old_id = str(row.get("evidence_id", "")).strip()
            if not old_id:
                raise CasePackageError("Package contains evidence without an evidence_id.")

            target_id = old_id
            if target_id in existing_evidence:
                if existing_evidence[target_id] == row:
                    # Safe reuse: package references an identical local evidence record.
                    evidence_map[old_id] = target_id
                    continue
                target_id = evidence_store._next_id()
                while target_id in existing_evidence:
                    target_id = evidence_store._next_id()

            copied = copy.deepcopy(row)
            copied["evidence_id"] = target_id
            evidence_store.records.append(copied)
            existing_evidence[target_id] = copied
            evidence_map[old_id] = target_id
            imported_evidence.append(copied)

        # Rewrite the case's evidence references to the destination IDs.
        imported_case = copy.deepcopy(original_case)
        imported_case["case_id"] = imported_case_id
        imported_case["evidence_ids"] = [
            evidence_map.get(str(x), str(x))
            for x in (original_case.get("evidence_ids") or [])
        ]
        imported_case["status"] = "Investigating" if str(imported_case.get("status")) == "Closed" else imported_case.get("status", "New")
        imported_case["updated_at"] = case_store._now()
        imported_case["imported_from_package"] = str(package.get("package_id", ""))
        imported_case["imported_at"] = case_store._now()
        imported_case["source_case_id"] = case_id

        # Store the case first, then migrate workflow to the destination ID.
        case_store.records.append(imported_case)
        workflow = copy.deepcopy(original_workflow)
        workflow["case_id"] = imported_case_id
        workflow["status"] = imported_case.get("status", workflow.get("status", "Investigating"))
        workflow["updated_at"] = case_store._now()
        workflow.setdefault("audit_history", []).append({
            "timestamp": case_store._now(),
            "action": "Investigation package imported",
            "details": f"Imported {package.get('package_id', '')} from case {case_id}. Reassessment required.",
        })
        workflow["handoff"] = dict(workflow.get("handoff") or {})
        workflow["handoff"]["ready"] = False
        workflow["final_report_ready"] = False
        workflow["closure_note"] = ""
        workflow["imported_from_package"] = str(package.get("package_id", ""))
        workflow["source_case_id"] = case_id
        workflow["reassessment_required"] = True
        workflow_store.records[imported_case_id] = workflow

        # Save exactly once per store.
        evidence_store.save()
        case_store.save()
        workflow_store.save()

        return {
            "case_id": imported_case_id,
            "source_case_id": case_id,
            "package_id": str(package.get("package_id", "")),
            "evidence_id_map": evidence_map,
            "imported_evidence_count": len(imported_evidence),
            "reused_evidence_count": len(evidence_rows) - len(imported_evidence),
            "reassessment_required": True,
        }
