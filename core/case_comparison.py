from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class CaseComparisonEngine:
    """Deterministic, explainable comparison of two case-intelligence reports.

    The engine identifies overlap across entities, event context, and time. It
    deliberately distinguishes similarity/correlation from causation.
    """

    TEMPORAL_WINDOW_SECONDS = 300

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _parse_time(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            text = str(value).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (TypeError, ValueError):
            return None

    @classmethod
    def _values(cls, report: dict[str, Any], key: str) -> set[str]:
        values = report.get(key, []) or []
        return {
            cls._norm(value)
            for value in values
            if cls._norm(value)
        }

    @classmethod
    def _timeline_values(cls, report: dict[str, Any], key: str) -> set[str]:
        values = set()
        for event in report.get("timeline", []) or []:
            value = cls._norm(event.get(key))
            if value:
                values.add(value)
        return values

    @classmethod
    def _time_distance(cls, left: dict[str, Any], right: dict[str, Any]) -> float | None:
        best = None
        for a in left.get("timeline", []) or []:
            ta = cls._parse_time(a.get("timestamp"))
            if not ta:
                continue
            for b in right.get("timeline", []) or []:
                tb = cls._parse_time(b.get("timestamp"))
                if not tb:
                    continue
                try:
                    delta = abs((ta - tb).total_seconds())
                except TypeError:
                    continue
                if best is None or delta < best:
                    best = delta
        return best

    @classmethod
    def compare(cls, current: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
        current_ips = cls._values(current, "source_ips")
        other_ips = cls._values(other, "source_ips")
        current_users = cls._values(current, "users")
        other_users = cls._values(other, "users")

        current_processes = cls._timeline_values(current, "process_name")
        other_processes = cls._timeline_values(other, "process_name")
        current_types = cls._timeline_values(current, "event_type")
        other_types = cls._timeline_values(other, "event_type")
        current_actions = cls._timeline_values(current, "action")
        other_actions = cls._timeline_values(other, "action")

        shared_ips = sorted(current_ips & other_ips)
        shared_users = sorted(current_users & other_users)
        shared_processes = sorted(current_processes & other_processes)
        shared_event_types = sorted(current_types & other_types)
        shared_actions = sorted(current_actions & other_actions)

        current_ids = {
            str(item.get("evidence_id", "")).strip()
            for item in current.get("timeline", []) or []
            if str(item.get("evidence_id", "")).strip()
        }
        other_ids = {
            str(item.get("evidence_id", "")).strip()
            for item in other.get("timeline", []) or []
            if str(item.get("evidence_id", "")).strip()
        }
        shared_evidence_ids = sorted(current_ids & other_ids)

        distance = cls._time_distance(current, other)
        temporal_overlap = (
            distance is not None and distance <= cls.TEMPORAL_WINDOW_SECONDS
        )

        # Explainable weights: identity overlap is stronger than generic
        # event-type/process overlap, while time proximity is weak evidence.
        components = {
            "shared_source_ips": len(shared_ips) * 4,
            "shared_users": len(shared_users) * 3,
            "shared_processes": len(shared_processes) * 2,
            "shared_event_types": len(shared_event_types),
            "shared_actions": len(shared_actions),
            "temporal_proximity": 1 if temporal_overlap else 0,
            "shared_evidence": len(shared_evidence_ids) * 2,
        }
        score = sum(components.values())

        if shared_ips or shared_users:
            classification = "ENTITY OVERLAP"
        elif score >= 3:
            classification = "POTENTIAL OVERLAP"
        elif score > 0:
            classification = "WEAK OVERLAP"
        else:
            classification = "NO DETERMINISTIC OVERLAP"

        reasons = []
        if shared_ips:
            reasons.append("shared source IP")
        if shared_users:
            reasons.append("shared username")
        if shared_processes:
            reasons.append("shared process")
        if shared_event_types:
            reasons.append("shared event type")
        if shared_actions:
            reasons.append("shared action")
        if shared_evidence_ids:
            reasons.append("shared evidence ID")
        if temporal_overlap:
            reasons.append(
                f"events within {cls.TEMPORAL_WINDOW_SECONDS // 60}-minute window"
            )

        if reasons:
            explanation = "Overlap indicators: " + ", ".join(reasons) + "."
        else:
            explanation = "No deterministic overlap indicators were identified."

        explanation += (
            " Similarity or temporal proximity does not establish causation, "
            "common ownership, or a single incident."
        )

        return {
            "case_id": str(other.get("case_id", "")),
            "title": str(other.get("title", "")),
            "score": score,
            "classification": classification,
            "shared_source_ips": shared_ips,
            "shared_users": shared_users,
            "shared_processes": shared_processes,
            "shared_event_types": shared_event_types,
            "shared_actions": shared_actions,
            "shared_evidence_ids": shared_evidence_ids,
            "temporal_proximity": temporal_overlap,
            "nearest_event_seconds": distance,
            "components": components,
            "reasons": reasons,
            "explanation": explanation,
            "causation_established": False,
        }

    @classmethod
    def compare_many(
        cls,
        current: dict[str, Any],
        others: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        results = [cls.compare(current, other) for other in others]
        results.sort(
            key=lambda item: (
                -int(item.get("score", 0)),
                str(item.get("case_id", "")),
            )
        )
        return results
