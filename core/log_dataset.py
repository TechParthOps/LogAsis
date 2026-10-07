"""Persistent dataset session for LogAsis.

One LogDataset per uploaded log file. Holds the DataFrame, EventIndex,
QueryEngine, AggregationEngine, RAG index, analytics cache, and coverage
metadata. All AI questions in one uploaded log reuse this object.

When a new log is loaded, the old dataset session is destroyed and a new one
is built. Dataset-level caches are NOT invalidated when only the UI filter
changes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

from core.event_index import EventIndex
from core.query_engine import QueryEngine, QueryPlan
from core.aggregation_engine import AggregationEngine
from core.analytics import events_to_dataframe, summary
from core.integrity import build_evidence_manifest


class LogDataset:
    """Persistent indexed representation of one loaded log file.

    Lifecycle:
        UPLOAD -> PARSE ONCE -> NORMALIZE ONCE -> BUILD INDEX ONCE -> READY
        READY -> FILTER / SEARCH / AGGREGATION / AI QUERY / TIMELINE / CORRELATION / DASHBOARD

    The index is built once and reused for all operations. Filtering is a
    VIEW operation that does NOT rebuild indexes or rerun analysis.
    """

    def __init__(self, df: pd.DataFrame, source_file: str = "", dataset_id: str = ""):
        self.df = df
        self.source_file = str(source_file or "")
        self.dataset_id = dataset_id or self._compute_dataset_id(df, source_file)
        self.event_index = EventIndex(df.fillna("").to_dict("records"))
        self.query_engine = QueryEngine(self.event_index)
        self.aggregation_engine = AggregationEngine(self.event_index)
        self._analytics_cache: dict[str, Any] = {}
        self._rag_index = None
        self._tool_catalog: dict[str, Any] | None = None
        self._content_hash: str | None = None
        self._evidence_manifest = None
        self._build_analytics_cache()

    @staticmethod
    def _compute_dataset_id(df: pd.DataFrame, source_file: str) -> str:
        components = {
            "source_file": str(source_file or ""),
            "row_count": str(len(df)),
            "columns": ",".join(sorted(str(c) for c in df.columns)),
        }
        raw = json.dumps(components, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _build_analytics_cache(self) -> None:
        if self.df.empty:
            return
        self._analytics_cache = {
            "summary": summary(self.df),
            "timestamp_range": self.aggregation_engine.time_range(),
            "severity_counts": self.aggregation_engine.severity_counts(),
            "event_type_counts": self.aggregation_engine.event_type_counts(),
            "action_counts": self.aggregation_engine.action_counts(),
            "source_ip_counts": self.aggregation_engine.source_ip_counts(),
            "username_counts": self.aggregation_engine.username_counts(),
            "process_counts": self.aggregation_engine.process_counts(),
            "authentication_summary": self.aggregation_engine.authentication_summary(),
            "coverage": self.aggregation_engine.coverage_summary(),
        }
        try:
            self._evidence_manifest = build_evidence_manifest(
                self.source_file,
                self.df.fillna("").to_dict("records"),
                [],
            )
        except Exception:
            self._evidence_manifest = None

    @property
    def size(self) -> int:
        return len(self.df)

    @property
    def analytics(self) -> dict[str, Any]:
        return dict(self._analytics_cache)

    @property
    def evidence_manifest(self):
        return self._evidence_manifest

    @property
    def content_hash(self) -> str:
        """Stable content identity of the loaded evidence.

        Computed once per uploaded log and reused by AI session caching, so
        repeat questions never rescan or reserialize the DataFrame.
        """
        if self._content_hash is None:
            frame = self.df.reindex(sorted(self.df.columns, key=str), axis=1)
            try:
                serialized = frame.to_json(orient="records", date_format="iso", default_handler=str)
            except TypeError:
                serialized = frame.astype(str).to_json(orient="records")
            self._content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return self._content_hash

    def get_rag_index(self):
        if self._rag_index is None:
            from ai.rag import LogRAGIndex
            self._rag_index = LogRAGIndex(self.df)
        return self._rag_index

    def get_tool_catalog(self) -> dict[str, Any]:
        """Evidence-ID catalog for the AI investigation tools.

        Built once per uploaded log and reused for every question, so the AI
        tool layer never re-serializes the full DataFrame per investigation.
        """
        if self._tool_catalog is None:
            from ai.investigation_agent import build_tool_catalog
            self._tool_catalog = build_tool_catalog(self.df)
        return self._tool_catalog

    def query(self, plan: QueryPlan | dict[str, Any]) -> dict[str, Any]:
        return self.query_engine.execute(plan)

    def filter_exact(self, field: str, value: Any) -> list[int]:
        return self.event_index.exact(field, value)

    def filter_and(self, *conditions: tuple[str, Any]) -> list[int]:
        position_sets = [set(self.event_index.exact(field, value)) for field, value in conditions]
        return self.event_index.intersect(*position_sets)

    def filter_or(self, *conditions: tuple[str, Any]) -> list[int]:
        position_sets = [set(self.event_index.exact(field, value)) for field, value in conditions]
        return self.event_index.union(*position_sets)

    def facet(self, field: str, positions: set[int] | None = None, limit: int = 50) -> dict[str, int]:
        return self.aggregation_engine.facet(field, positions, limit)

    def distinct_values(self, field: str, limit: int | None = None) -> list[str]:
        return self.event_index.distinct_values(field, limit)

    def prefix_values(self, field: str, prefix: str, limit: int = 100) -> list[str]:
        return self.event_index.prefix_values(field, prefix, limit)

    def get_events(self, positions: list[int]) -> pd.DataFrame:
        if not positions:
            return self.df.iloc[0:0]
        return self.df.iloc[positions]

    def get_event(self, position: int) -> dict[str, Any] | None:
        return self.event_index.get_event(position)

    def coverage(self, candidate_positions: set[int] | None = None) -> dict[str, Any]:
        return self.aggregation_engine.coverage_summary(candidate_positions)

    def invalidate_caches(self) -> None:
        self.event_index.clear_caches()
        self._analytics_cache.clear()
        self._rag_index = None
        self._tool_catalog = None
        self._content_hash = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "source_file": self.source_file,
            "size": self.size,
            "columns": [str(c) for c in self.df.columns],
            "analytics": self._analytics_cache,
        }


class DatasetSession:
    """Manages the lifecycle of LogDataset objects.

    Holds the current dataset and ensures safe replacement when a new log
    is loaded. Old caches are invalidated on replacement.
    """

    def __init__(self):
        self._dataset: LogDataset | None = None
        self._dataset_generation = 0

    @property
    def dataset(self) -> LogDataset | None:
        return self._dataset

    @property
    def generation(self) -> int:
        return self._dataset_generation

    def set_dataset(self, dataset: LogDataset) -> None:
        if self._dataset is not None:
            self._dataset.invalidate_caches()
        self._dataset = dataset
        self._dataset_generation += 1

    def clear(self) -> None:
        if self._dataset is not None:
            self._dataset.invalidate_caches()
        self._dataset = None
        self._dataset_generation += 1

    def is_valid_for(self, dataset_id: str) -> bool:
        return self._dataset is not None and self._dataset.dataset_id == dataset_id
