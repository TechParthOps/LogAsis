from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source: str = ""
    line: str = ""
    timestamp: str = ""
    event_type: str = ""


@dataclass(frozen=True)
class Explanation:
    finding_id: str
    title: str
    classification: str
    confidence: str
    observed_facts: tuple[str, ...] = field(default_factory=tuple)
    supporting_evidence: tuple[EvidenceRef, ...] = field(default_factory=tuple)
    correlation: tuple[str, ...] = field(default_factory=tuple)
    analyst_interpretation: str = ""
    limitations: tuple[str, ...] = field(default_factory=tuple)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def evidence_ref(record: Any, fallback_id: str = "") -> EvidenceRef:
    if not isinstance(record, dict):
        return EvidenceRef(evidence_id=fallback_id, source=_text(record))

    return EvidenceRef(
        evidence_id=_text(record.get("evidence_id") or record.get("id") or fallback_id),
        source=_text(record.get("source") or record.get("source_file") or record.get("file")),
        line=_text(record.get("line") or record.get("line_number")),
        timestamp=_text(record.get("timestamp") or record.get("time")),
        event_type=_text(record.get("event_type") or record.get("type")),
    )


def build_explanation(
    finding: dict[str, Any],
    *,
    evidence: Iterable[Any] = (),
    related_events: Iterable[Any] = (),
) -> Explanation:
    """Build an explainability record without changing the finding itself.

    The function intentionally distinguishes observed facts from interpretation.
    It does not upgrade severity/confidence and does not invent evidence.
    """
    finding_id = _text(finding.get("finding_id") or finding.get("id") or "finding")
    title = _text(finding.get("title") or finding.get("name") or finding_id)
    classification = _text(
        finding.get("classification") or finding.get("category") or "Unclassified"
    )

    raw_confidence = _text(finding.get("confidence"))
    confidence = raw_confidence if raw_confidence else "Not stated"

    facts: list[str] = []
    for key in ("description", "observation", "message", "reason"):
        value = _text(finding.get(key))
        if value and value not in facts:
            facts.append(value)

    refs: list[EvidenceRef] = []
    for index, item in enumerate(evidence):
        ref = evidence_ref(item, f"{finding_id}-e{index + 1}")
        if ref.evidence_id:
            refs.append(ref)

    correlations: list[str] = []
    for item in related_events:
        if isinstance(item, dict):
            event = _text(
                item.get("summary")
                or item.get("message")
                or item.get("event_type")
                or item.get("type")
            )
        else:
            event = _text(item)
        if event and event not in correlations:
            correlations.append(event)

    limitations: list[str] = []
    if not refs:
        limitations.append("No linked evidence record is available.")
    if not correlations:
        limitations.append("No related-event correlation is recorded.")
    if not raw_confidence:
        limitations.append("The finding does not provide an explicit confidence value.")

    interpretation = _text(
        finding.get("analyst_interpretation")
        or finding.get("interpretation")
        or finding.get("assessment")
    )

    return Explanation(
        finding_id=finding_id,
        title=title,
        classification=classification,
        confidence=confidence,
        observed_facts=tuple(facts),
        supporting_evidence=tuple(refs),
        correlation=tuple(correlations),
        analyst_interpretation=interpretation,
        limitations=tuple(limitations),
    )


def explanation_dict(explanation: Explanation) -> dict[str, Any]:
    return {
        "finding_id": explanation.finding_id,
        "title": explanation.title,
        "classification": explanation.classification,
        "confidence": explanation.confidence,
        "observed_facts": list(explanation.observed_facts),
        "supporting_evidence": [
            {
                "evidence_id": ref.evidence_id,
                "source": ref.source,
                "line": ref.line,
                "timestamp": ref.timestamp,
                "event_type": ref.event_type,
            }
            for ref in explanation.supporting_evidence
        ],
        "correlation": list(explanation.correlation),
        "analyst_interpretation": explanation.analyst_interpretation,
        "limitations": list(explanation.limitations),
    }
