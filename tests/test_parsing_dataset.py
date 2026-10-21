"""Tests for parsing, normalization, and dataset integrity."""

from __future__ import annotations

import pandas as pd
import pytest

from parsers.json_log import JsonLogParser
from core.analytics import events_to_dataframe
from core.log_dataset import LogDataset
from tests.conftest import make_events


class TestJsonParser:
    def test_ndjson_preserves_custom_fields(self):
        text = (
            '{"timestamp": "2026-09-15T08:00:00Z", "event_uid": "X-1", "user": "bob", '
            '"vendor_score": 42, "nested": {"deep_field": "deep-value"}}\n'
            '{"timestamp": "2026-09-15T08:01:00Z", "event_uid": "X-2", "user": "amy"}\n'
        )
        events = JsonLogParser().parse(text)
        assert len(events) == 2
        assert events[0]["vendor_score"] == 42
        assert events[0]["nested_deep_field"] == "deep-value"
        assert events[0]["line"] == 1
        assert events[1]["line"] == 2

    def test_malformed_lines_tracked_not_fatal(self):
        text = (
            '{"timestamp": "2026-09-15T08:00:00Z", "user": "bob"}\n'
            '{this is not json\n'
            '{"timestamp": "2026-09-15T08:01:00Z", "user": "amy"}\n'
        )
        events = JsonLogParser().parse(text)
        assert len(events) == 2  # bad line skipped, good lines kept

    def test_source_line_mapping_stable(self):
        text = '{"user": "a"}\n\n{"user": "b"}\n'
        events = JsonLogParser().parse(text)
        assert [e["line"] for e in events] == [1, 2]


class TestEventsToDataframe:
    def test_malformed_timestamp_does_not_crash(self):
        events = [{"timestamp": "not-a-timestamp", "user": "x", "message": "m"}]
        df = events_to_dataframe(events)
        assert len(df) == 1
        assert "timestamp_parse_failed" in df.columns
        assert bool(df.iloc[0]["timestamp_parse_failed"])

    def test_all_bad_timestamps_do_not_crash(self):
        events = [{"timestamp": "bad1", "user": "x"}, {"timestamp": "bad2", "user": "y"}]
        df = events_to_dataframe(events)
        assert len(df) == 2

    def test_mixed_naive_aware_timestamps(self):
        events = [
            {"timestamp": "2026-09-15T08:00:00Z", "user": "a"},
            {"timestamp": "2026-09-15 09:00:00", "user": "b"},
        ]
        df = events_to_dataframe(events)
        assert df["timestamp_dt"].notna().all()
        assert str(df["timestamp_dt"].dtype).startswith("datetime64")

    def test_hour_and_date_derived(self):
        events = [{"timestamp": "2026-09-15T08:30:00Z", "user": "a"}]
        df = events_to_dataframe(events)
        assert int(df.iloc[0]["hour"]) == 8
        assert str(df.iloc[0]["date"]) == "2026-09-15"

    def test_duplicate_events_preserved_individually(self):
        # Duplicate ingestion must NOT silently deduplicate or inflate: two
        # identical records are two rows with distinct positions.
        raw = '{"timestamp": "2026-09-15T08:00:00Z", "user": "a", "action": "failed_login"}'
        events = JsonLogParser().parse(raw + "\n" + raw)
        df = events_to_dataframe(events)
        assert len(df) == 2
        ds = LogDataset(df, source_file="dup")
        assert ds.event_index.exact("action", "failed_login") == [0, 1]


class TestLogDataset:
    def test_index_covers_loaded_dataset(self):
        events = [
            {"timestamp": "2026-09-15T08:00:00Z", "user": "a", "action": "failed_login"},
            {"timestamp": "2026-09-15T08:01:00Z", "user": "b", "action": "successful_login"},
        ]
        df = events_to_dataframe(events)
        ds = LogDataset(df, source_file="x")
        assert ds.event_index.size == len(df) == 2
        assert ds.size == 2

    def test_nat_timestamps_index_builds(self):
        events = [
            {"timestamp": "2026-09-15T08:00:00Z", "user": "a"},
            {"timestamp": "not-a-timestamp", "user": "b"},
        ]
        df = events_to_dataframe(events)
        ds = LogDataset(df, source_file="x")  # must not raise on datetime fillna
        assert ds.size == 2

    def test_dataset_id_stable_and_content_hash(self):
        events = [{"timestamp": "2026-09-15T08:00:00Z", "user": "a"}]
        df = events_to_dataframe(events)
        ds1 = LogDataset(df, source_file="x")
        ds2 = LogDataset(df, source_file="x")
        assert ds1.dataset_id == ds2.dataset_id
        assert ds1.content_hash == ds2.content_hash

    def test_stale_index_detection(self):
        events = [{"timestamp": "2026-09-15T08:00:00Z", "user": "a"}]
        df = events_to_dataframe(events)
        ds = LogDataset(df, source_file="x")
        assert ds.event_index.size == len(ds.df)
        # Mutating the frame must invalidate the size match so AI layers
        # refuse the stale index.
        mutated = pd.concat([ds.df, ds.df], ignore_index=True)
        assert ds.event_index.size != len(mutated)
