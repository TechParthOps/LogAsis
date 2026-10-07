"""Timeline engine for LogAsis.

Given entity, event IDs, time range, session, or correlation ID,
returns ordered events from the persistent index.
"""

from __future__ import annotations

from typing import Any

from core.event_index import EventIndex


class TimelineEngine:
    """Build ordered event timelines from the EventIndex."""

    def __init__(self, index: EventIndex):
        self.index = index

    def for_positions(self, positions: list[int]) -> list[dict[str, Any]]:
        events = self.index.get_events(positions)
        decorated = []
        for pos, event in zip(positions, events):
            ts = self.index._parse_timestamp(event.get("timestamp"))
            decorated.append((ts, pos, event))
        decorated.sort(key=lambda x: (x[0] or self.index._parse_timestamp(""), x[1]))
        return [event for _, _, event in decorated]

    def for_entity(self, entity_type: str, value: str, limit: int = 100) -> list[dict[str, Any]]:
        positions = self.index.entity_lookup(entity_type, value)
        return self.for_positions(positions[:limit])

    def for_time_range(self, start, end, limit: int = 1000) -> list[dict[str, Any]]:
        positions = self.index.timestamp_range(start, end)
        return self.for_positions(positions[:limit])

    def for_correlation(self, field: str, value: Any, limit: int = 100) -> list[dict[str, Any]]:
        positions = self.index.correlation_lookup(field, value)
        return self.for_positions(positions[:limit])

    def for_session(self, session_value: str, limit: int = 200) -> list[dict[str, Any]]:
        correlation_fields = self.index.correlation_fields
        all_positions: set[int] = set()
        for field in correlation_fields:
            all_positions.update(self.index.exact(field, session_value))
        return self.for_positions(sorted(all_positions)[:limit])
