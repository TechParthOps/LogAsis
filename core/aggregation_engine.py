"""Aggregation engine for LogAsis.

Provides facet counts, top-K, time-series histograms, and field statistics
using the persistent EventIndex. All aggregations are computed from indexes,
not full DataFrame scans.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from core.event_index import EventIndex


class AggregationEngine:
    """Compute aggregations over the EventIndex."""

    def __init__(self, index: EventIndex):
        self.index = index

    def count(self, positions: list[int] | set[int] | None = None) -> int:
        if positions is None:
            return self.index.size
        return len(positions)

    def facet(self, field: str, positions: set[int] | None = None, limit: int = 50) -> dict[str, int]:
        return self.index.facet_counts(field, positions, limit)

    def top_k(self, field: str, k: int = 10, positions: set[int] | None = None) -> list[tuple[str, int]]:
        counts = self.index.facet_counts(field, positions, k)
        return list(counts.items())

    def distinct_count(self, field: str, positions: set[int] | None = None) -> int:
        if positions is None:
            return self.index.field_cardinality.get(field, 0)
        if field not in self.index._field_values:
            return 0
        count = 0
        for rows in self.index._field_values[field].values():
            if rows & positions:
                count += 1
        return count

    def time_histogram(
        self,
        bucket_seconds: int = 3600,
        positions: set[int] | None = None,
    ) -> dict[str, int]:
        if not self.index._sorted_timestamps:
            return {}
        bucket = max(1, int(bucket_seconds))
        counts: Counter[int] = Counter()
        for ts, pos in self.index._sorted_timestamps:
            if positions is not None and pos not in positions:
                continue
            bucket_id = int(ts.timestamp() // bucket)
            counts[bucket_id] += 1
        return {
            datetime.fromtimestamp(bid * bucket).isoformat(): count
            for bid, count in sorted(counts.items())
        }

    def time_range(self, positions: set[int] | None = None) -> dict[str, str]:
        timestamps = []
        for ts, pos in self.index._sorted_timestamps:
            if positions is not None and pos not in positions:
                continue
            timestamps.append(ts)
        if not timestamps:
            return {"first": "", "last": "", "duration_seconds": "0"}
        return {
            "first": timestamps[0].isoformat(),
            "last": timestamps[-1].isoformat(),
            "duration_seconds": str(int((timestamps[-1] - timestamps[0]).total_seconds())),
        }

    def field_statistics(self, field: str) -> dict[str, Any]:
        if field not in self.index._field_values:
            return {"field": field, "exists": False}
        values = self.index._field_values[field]
        total = sum(len(rows) for rows in values.values())
        return {
            "field": field,
            "exists": True,
            "distinct_count": len(values),
            "total_occurrences": total,
            "cardinality_ratio": round(len(values) / max(1, self.index.size), 4),
        }

    def entity_summary(self, entity_type: str) -> dict[str, int]:
        if entity_type not in self.index.entity_indexes:
            return {}
        return {
            value: len(positions)
            for value, positions in self.index.entity_indexes[entity_type].items()
        }

    def severity_counts(self, positions: set[int] | None = None) -> dict[str, int]:
        return self.index.facet_counts("severity", positions, limit=20)

    def event_type_counts(self, positions: set[int] | None = None) -> dict[str, int]:
        return self.index.facet_counts("event_type", positions, limit=50)

    def action_counts(self, positions: set[int] | None = None) -> dict[str, int]:
        return self.index.facet_counts("action", positions, limit=50)

    def source_ip_counts(self, positions: set[int] | None = None, limit: int = 20) -> dict[str, int]:
        return self.index.facet_counts("source_ip", positions, limit)

    def username_counts(self, positions: set[int] | None = None, limit: int = 20) -> dict[str, int]:
        return self.index.facet_counts("username", positions, limit)

    def process_counts(self, positions: set[int] | None = None, limit: int = 20) -> dict[str, int]:
        return self.index.facet_counts("process_name", positions, limit)

    def authentication_summary(self, positions: set[int] | None = None) -> dict[str, Any]:
        actions = self.index.facet_counts("action", positions, limit=50)
        return {
            "failed_logins": actions.get("failed_login", 0),
            "successful_logins": actions.get("successful_login", 0),
            "total_auth_events": actions.get("failed_login", 0) + actions.get("successful_login", 0),
        }

    def coverage_summary(self, candidate_positions: set[int] | None = None) -> dict[str, Any]:
        total = self.index.size
        if candidate_positions is None:
            return {
                "total_events": total,
                "indexed_events": total,
                "candidate_events": total,
                "coverage_status": "COMPLETE",
                "coverage_ratio": 1.0,
            }
        candidate_count = len(candidate_positions)
        ratio = candidate_count / max(1, total)
        if ratio >= 0.99:
            status = "COMPLETE"
        elif ratio >= 0.5:
            status = "TARGETED"
        elif ratio > 0:
            status = "PARTIAL"
        else:
            status = "UNKNOWN"
        return {
            "total_events": total,
            "indexed_events": total,
            "candidate_events": candidate_count,
            "coverage_status": status,
            "coverage_ratio": round(ratio, 4),
        }
