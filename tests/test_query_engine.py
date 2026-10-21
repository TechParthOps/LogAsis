"""Regression tests for the query/index layer defects found in the audit.

C1: EventIndex.intersect returned ALL rows when every position set was empty.
C2: QueryEngine._finalize overwrote count with the truncated sample length.
C8/C9: timestamp handling and fail-closed plan validation.
"""

from __future__ import annotations

import pytest

from core.event_index import EventIndex
from core.query_engine import QueryEngine
from core.log_dataset import LogDataset


def _events(n: int = 20) -> list[dict]:
    events = []
    for i in range(n):
        events.append({
            "timestamp": f"2026-09-15T08:{i % 60:02d}:00Z",
            "event_type": "authentication" if i % 2 else "firewall",
            "source_ip": "198.51.100.23" if i < 10 else "203.0.113.5",
            "action": "failed_login" if i % 2 else "blocked",
            "message": f"event {i}",
        })
    return events


class TestEventIndexIntersect:
    def test_intersect_with_empty_set_returns_empty(self):
        idx = EventIndex(_events())
        a = set(idx.exact("source_ip", "198.51.100.23"))
        empty = set(idx.exact("source_ip", "0.0.0.0"))
        assert len(a) == 10
        assert idx.intersect(a, empty) == []
        assert idx.intersect(empty, a) == []
        assert idx.intersect(empty) == []

    def test_intersect_no_conditions_returns_all(self):
        idx = EventIndex(_events())
        assert len(idx.intersect()) == idx.size

    def test_dataset_filter_and_fail_closed(self):
        ds = LogDataset.__new__(LogDataset)
        # Build through the normal constructor path
        import pandas as pd
        from core.analytics import events_to_dataframe
        df = events_to_dataframe(_events())
        ds = LogDataset(df, source_file="t")
        result = ds.filter_and(("source_ip", "0.0.0.0"), ("action", "failed_login"))
        assert result == []


class TestCountSemantics:
    def test_count_not_corrupted_by_limit(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        plan = engine.compile({
            "operation": "AND",
            "limit": 3,
            "conditions": [
                {"field": "source_ip", "operator": "EXACT", "value": "198.51.100.23"},
                {"field": "action", "operator": "EXACT", "value": "failed_login"},
            ],
        })
        result = engine.execute(plan)
        assert result["count"] == 5          # full matching set
        assert result["returned_count"] == 3  # bounded sample
        assert result["truncated"] is True
        assert result["exhaustive"] is False
        assert len(result["positions"]) == 3

    def test_count_unlimited_is_exact(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        result = engine.execute({
            "operation": "AND",
            "conditions": [{"field": "source_ip", "operator": "EXACT", "value": "198.51.100.23"}],
        })
        assert result["count"] == 10
        assert result["exhaustive"] is True
        assert result["truncated"] is False


class TestPlanValidation:
    def test_unknown_field_fails_closed(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        plan = engine.compile({
            "operation": "AND",
            "conditions": [{"field": "not_a_real_field", "operator": "EXACT", "value": "x"}],
        })
        assert not plan.is_valid
        result = engine.execute(plan)
        assert result["count"] == 0
        assert "Unknown field" in result["error"]

    def test_bare_condition_is_leaf_not_unbounded_and(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        result = engine.execute({
            "operation": "AND",
            "conditions": [{"field": "source_ip", "operator": "EXACT", "value": "198.51.100.23"}],
        })
        assert result["count"] == 10  # not the whole dataset

    def test_unsupported_operator_rejected(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        result = engine.execute({
            "operation": "AND",
            "conditions": [{"field": "source_ip", "operator": "DROP TABLE", "value": "x"}],
        })
        assert result["count"] == 0
        assert result["error"]

    def test_and_with_zero_match_condition_is_zero(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        result = engine.execute({
            "operation": "AND",
            "conditions": [
                {"field": "source_ip", "operator": "EXACT", "value": "198.51.100.23"},
                {"field": "action", "operator": "EXACT", "value": "successful_login"},  # absent
            ],
        })
        assert result["count"] == 0


class TestTimestampHandling:
    def test_mixed_naive_and_aware_timestamps_build(self):
        events = [
            {"timestamp": "2026-09-15T08:00:00Z", "message": "aware"},
            {"timestamp": "2026-09-15 08:05:00", "message": "naive"},
        ]
        idx = EventIndex(events)  # must not raise TypeError
        assert idx.size == 2
        result = idx.timestamp_range(
            EventIndex._parse_timestamp("2026-09-15T07:00:00Z"),
            EventIndex._parse_timestamp("2026-09-15T09:00:00Z"),
        )
        assert len(result) == 2

    def test_unparseable_timestamp_excluded_from_range(self):
        events = [
            {"timestamp": "2026-09-15T08:00:00Z", "message": "ok"},
            {"timestamp": "not-a-timestamp", "message": "bad"},
        ]
        idx = EventIndex(events)
        assert idx.size == 2
        result = idx.timestamp_range(
            EventIndex._parse_timestamp("2026-09-15T00:00:00Z"),
            EventIndex._parse_timestamp("2026-09-15T23:59:59Z"),
        )
        assert len(result) == 1


class TestNotOperator:
    def test_not_excludes_matching(self):
        idx = EventIndex(_events())
        engine = QueryEngine(idx)
        result = engine.execute({
            "operation": "NOT",
            "condition": {"field": "source_ip", "operator": "EXACT", "value": "198.51.100.23"},
        })
        assert result["count"] == 10
