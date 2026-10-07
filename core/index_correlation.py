"""Index-backed correlation engine for LogAsis.

Uses the persistent EventIndex for entity-based correlation instead of
scanning the full evidence store. Supports user, IP, process, PID, session,
and timestamp-window relationships.
"""

from __future__ import annotations

from typing import Any

from core.event_index import EventIndex


class IndexCorrelationEngine:
    """Deterministic correlation using the persistent EventIndex."""

    _CORRELATION_FIELDS = (
        ("source_ip", "same source IP"),
        ("destination_ip", "same destination IP"),
        ("username", "same user"),
        ("process_name", "same process"),
        ("event_type", "same event type"),
        ("action", "same action"),
    )

    def __init__(self, index: EventIndex):
        self.index = index

    def related_positions(self, position: int, window_seconds: int = 300) -> list[dict[str, Any]]:
        event = self.index.get_event(position)
        if not event:
            return []

        target_ip = self.index._norm(event.get("source_ip"))
        target_user = self.index._norm(event.get("username"))
        target_process = self.index._norm(event.get("process_name"))
        target_type = self.index._norm(event.get("event_type"))
        target_time = self.index._parse_timestamp(event.get("timestamp"))

        candidate_positions: set[int] = set()
        if target_ip:
            candidate_positions.update(self.index.entity_lookup("ip", target_ip))
        if target_user:
            candidate_positions.update(self.index.entity_lookup("username", target_user))
        if target_process:
            candidate_positions.update(self.index.entity_lookup("process", target_process))

        results = []
        for pos in candidate_positions:
            if pos == position:
                continue
            candidate = self.index.get_event(pos)
            if not candidate:
                continue

            reasons = []
            for field, label in self._CORRELATION_FIELDS:
                a = self.index._norm(event.get(field))
                b = self.index._norm(candidate.get(field))
                if a and b and a == b:
                    reasons.append(label)

            candidate_time = self.index._parse_timestamp(candidate.get("timestamp"))
            if target_time and candidate_time:
                try:
                    delta = abs((candidate_time - target_time).total_seconds())
                    if delta <= window_seconds:
                        reasons.append(f"within {window_seconds}s")
                except TypeError:
                    pass

            if reasons:
                results.append({
                    "position": pos,
                    "reasons": reasons,
                    "score": len(reasons),
                    "event": candidate,
                })

        results.sort(key=lambda x: (-x["score"], x["position"]))
        return results

    def correlate_positions(self, positions: list[int], window_seconds: int = 300) -> dict[str, Any]:
        all_related: dict[int, list[dict[str, Any]]] = {}
        for pos in positions:
            all_related[pos] = self.related_positions(pos, window_seconds)

        relationships = []
        seen_pairs: set[tuple[int, int]] = set()
        for pos, related_list in all_related.items():
            for rel in related_list:
                pair = tuple(sorted((pos, rel["position"])))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                relationships.append({
                    "position_a": pair[0],
                    "position_b": pair[1],
                    "reasons": rel["reasons"],
                    "score": rel["score"],
                })

        relationships.sort(key=lambda x: (-x["score"], x["position_a"], x["position_b"]))
        return {
            "relationship_count": len(relationships),
            "relationships": relationships[:100],
        }

    def entity_correlation(self, entity_type: str, value: str) -> dict[str, Any]:
        positions = self.index.entity_lookup(entity_type, value)
        if not positions:
            return {"entity_type": entity_type, "entity_value": value, "positions": [], "relationships": []}

        events = self.index.get_events(positions)
        return {
            "entity_type": entity_type,
            "entity_value": value,
            "positions": positions,
            "event_count": len(positions),
            "events": events[:50],
        }
