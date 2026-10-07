from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


class CorrelationEngine:
    """Deterministic, explainable correlation of evidence records."""

    DEFAULT_WINDOW_SECONDS = 300

    def __init__(self, evidence_store):
        self.evidence_store = evidence_store

    @staticmethod
    def _parse_time(value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    def related_evidence(
        self,
        evidence_id: str,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> list[dict[str, Any]]:
        target = self.evidence_store.get(evidence_id)
        if not target:
            return []

        target_time = self._parse_time(target.get("timestamp"))
        target_ip = self._norm(target.get("source_ip"))
        target_user = self._norm(target.get("username"))
        target_process = self._norm(target.get("process_name"))
        target_type = self._norm(target.get("event_type"))

        results = []
        for candidate in self.evidence_store.records:
            cid = str(candidate.get("evidence_id", ""))
            if not cid or cid == evidence_id:
                continue

            reasons = []

            cip = self._norm(candidate.get("source_ip"))
            cuser = self._norm(candidate.get("username"))
            cprocess = self._norm(candidate.get("process_name"))
            ctype = self._norm(candidate.get("event_type"))

            if target_ip and cip and target_ip == cip:
                reasons.append("Same source IP")
            if target_user and cuser and target_user == cuser:
                reasons.append("Same username")
            if target_process and cprocess and target_process == cprocess:
                reasons.append("Same process")
            if target_type and ctype and target_type == ctype:
                reasons.append("Same event type")

            candidate_time = self._parse_time(candidate.get("timestamp"))
            if target_time and candidate_time:
                try:
                    delta = abs((candidate_time - target_time).total_seconds())
                    if delta <= window_seconds:
                        reasons.append(
                            f"Within {window_seconds // 60}-minute time window"
                        )
                except TypeError:
                    pass

            if reasons:
                score = len(reasons)
                results.append({
                    "evidence_id": cid,
                    "score": score,
                    "reasons": reasons,
                    "timestamp": candidate.get("timestamp", ""),
                    "priority": candidate.get("priority", ""),
                    "event_type": candidate.get("event_type", ""),
                    "source_ip": candidate.get("source_ip", ""),
                    "username": candidate.get("username", ""),
                    "process_name": candidate.get("process_name", ""),
                })

        results.sort(
            key=lambda item: (
                -int(item.get("score", 0)),
                str(item.get("timestamp", "")),
                str(item.get("evidence_id", "")),
            )
        )
        return results

    def build_timeline(
        self,
        evidence_ids: list[str] | tuple[str, ...],
    ) -> list[dict[str, Any]]:
        wanted = {str(item) for item in evidence_ids if item}
        records = [
            record for record in self.evidence_store.records
            if str(record.get("evidence_id", "")) in wanted
        ]
        records.sort(
            key=lambda item: (
                str(item.get("timestamp", "")),
                str(item.get("evidence_id", "")),
            )
        )
        return records

    def case_summary(self, evidence_ids: list[str] | tuple[str, ...]) -> dict[str, Any]:
        timeline = self.build_timeline(evidence_ids)
        priorities = Counter(
            str(item.get("priority", "UNKNOWN")).upper()
            for item in timeline
        )
        users = sorted({
            str(item.get("username", "")).strip()
            for item in timeline
            if str(item.get("username", "")).strip()
        })
        source_ips = sorted({
            str(item.get("source_ip", "")).strip()
            for item in timeline
            if str(item.get("source_ip", "")).strip()
        })
        event_types = Counter(
            str(item.get("event_type", "UNKNOWN"))
            for item in timeline
        )

        timestamps = [
            str(item.get("timestamp", ""))
            for item in timeline
            if str(item.get("timestamp", ""))
        ]

        return {
            "total_events": len(timeline),
            "critical": priorities.get("CRITICAL", 0),
            "high": priorities.get("HIGH", 0),
            "medium": priorities.get("MEDIUM", 0),
            "low": priorities.get("LOW", 0),
            "users": users,
            "source_ips": source_ips,
            "event_types": dict(event_types),
            "first_observed": timestamps[0] if timestamps else "",
            "last_observed": timestamps[-1] if timestamps else "",
        }

    def correlate_case(self, case: dict[str, Any]) -> dict[str, Any]:
        evidence_ids = list(case.get("evidence_ids", []) or [])
        timeline = self.build_timeline(evidence_ids)
        summary = self.case_summary(evidence_ids)

        relationships = []
        related_candidates = []
        seen_relationships = set()
        seen_candidates = set()
        linked_set = {str(item) for item in evidence_ids if item}

        for evidence_id in evidence_ids:
            for related in self.related_evidence(evidence_id):
                rid = str(related["evidence_id"])
                if rid in linked_set:
                    pair = tuple(sorted((str(evidence_id), rid)))
                    if pair in seen_relationships:
                        continue
                    seen_relationships.add(pair)
                    relationships.append({
                        "evidence_a": pair[0],
                        "evidence_b": pair[1],
                        "score": related["score"],
                        "reasons": related["reasons"],
                    })
                else:
                    if rid in seen_candidates:
                        continue
                    seen_candidates.add(rid)
                    related_candidates.append({
                        **related,
                        "related_to": str(evidence_id),
                    })

        related_candidates.sort(
            key=lambda item: (
                -int(item.get("score", 0)),
                str(item.get("timestamp", "")),
                str(item.get("evidence_id", "")),
            )
        )

        return {
            "case_id": case.get("case_id", ""),
            "summary": summary,
            "timeline": timeline,
            "relationships": relationships,
            "related_candidates": related_candidates,
        }
