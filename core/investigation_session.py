from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationSession:
    """Case-scoped UI state for the active LogAsis investigation.

    This intentionally contains identifiers and UI context, not the evidence
    dataset itself. Persistent facts remain owned by the existing stores.
    """

    source_file: str = ""
    selected_case_id: str = ""
    selected_evidence_id: str = ""
    selected_finding_id: str = ""
    selected_ioc_type: str = ""
    selected_ioc_value: str = ""
    current_view: str = "Dashboard"
    filters: dict[str, str] = field(default_factory=dict)

    def select_case(self, case_id: str | None) -> None:
        self.selected_case_id = str(case_id or "")
        self.selected_evidence_id = ""
        self.selected_finding_id = ""
        self.selected_ioc_type = ""
        self.selected_ioc_value = ""

    def select_evidence(self, evidence_id: str | None) -> None:
        self.selected_evidence_id = str(evidence_id or "")

    def select_finding(self, finding_id: str | None) -> None:
        self.selected_finding_id = str(finding_id or "")

    def select_ioc(self, ioc_type: str | None, value: str | None) -> None:
        self.selected_ioc_type = str(ioc_type or "")
        self.selected_ioc_value = str(value or "")

    def set_view(self, view: str) -> None:
        self.current_view = str(view or "")

    def snapshot(self) -> dict[str, Any]:
        return deepcopy({
            "source_file": self.source_file,
            "selected_case_id": self.selected_case_id,
            "selected_evidence_id": self.selected_evidence_id,
            "selected_finding_id": self.selected_finding_id,
            "selected_ioc_type": self.selected_ioc_type,
            "selected_ioc_value": self.selected_ioc_value,
            "current_view": self.current_view,
            "filters": self.filters,
        })
