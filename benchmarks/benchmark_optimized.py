"""Optimized performance benchmark for LogAsis.

Compares baseline (DataFrame scan) vs optimized (indexed) operations.
Run: python -m benchmarks.benchmark_optimized
"""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.analytics import events_to_dataframe, apply_filters, summary
from core.event_index import EventIndex
from core.query_engine import QueryEngine
from core.aggregation_engine import AggregationEngine
from core.log_dataset import LogDataset
from benchmarks.benchmark_baseline import _generate_synthetic_events


def _measure(label: str, func, *args, **kwargs) -> dict[str, Any]:
    tracemalloc.start()
    start = time.perf_counter()
    try:
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {
            "operation": label,
            "elapsed_seconds": round(elapsed, 4),
            "peak_memory_mb": round(peak / 1024 / 1024, 2),
            "result_count": len(result) if hasattr(result, "__len__") else 0,
            "status": "ok",
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        tracemalloc.stop()
        return {
            "operation": label,
            "elapsed_seconds": round(elapsed, 4),
            "peak_memory_mb": 0,
            "result_count": 0,
            "status": f"error: {exc}",
        }


def run_optimized_benchmarks(dataset_sizes: list[int] | None = None) -> dict[str, Any]:
    if dataset_sizes is None:
        dataset_sizes = [10000, 100000]

    all_results: dict[str, Any] = {
        "benchmark_version": "optimized-1.0",
        "timestamp": pd.Timestamp.now().isoformat(),
        "datasets": {},
    }

    for size in dataset_sizes:
        print(f"\n{'='*60}")
        print(f"Optimized benchmark with {size:,} events")
        print(f"{'='*60}")

        results: list[dict[str, Any]] = []

        events = _generate_synthetic_events(size)

        r = _measure("events_to_dataframe", events_to_dataframe, events)
        results.append(r)
        df = events_to_dataframe(events)

        r = _measure("event_index_build", EventIndex, df.fillna("").to_dict("records"))
        results.append(r)
        index = EventIndex(df.fillna("").to_dict("records"))

        r = _measure("log_dataset_creation", LogDataset, df, source_file="test.log")
        results.append(r)
        dataset = LogDataset(df, source_file="test.log")

        def populate_filter_values_indexed():
            return index.distinct_values("source_ip")

        r = _measure("filter_value_population_indexed", populate_filter_values_indexed)
        results.append(r)

        def apply_filter_indexed():
            positions = index.exact("source_ip", "10.0.0.1")
            return df.iloc[positions] if positions else df.iloc[0:0]

        r = _measure("filter_application_indexed", apply_filter_indexed)
        results.append(r)

        engine = QueryEngine(index)
        r = _measure("query_exact", engine.execute, {"operation": "EXACT", "field": "source_ip", "value": "10.0.0.1"})
        results.append(r)

        r = _measure("query_and", engine.execute, {
            "operation": "AND",
            "conditions": [
                {"operation": "EXACT", "field": "source_ip", "value": "10.0.0.1"},
                {"operation": "EXACT", "field": "action", "value": "failed_login"},
            ],
        })
        results.append(r)

        agg = AggregationEngine(index)
        r = _measure("aggregation_facet", agg.facet, "source_ip", limit=20)
        results.append(r)

        r = _measure("aggregation_top_k", agg.top_k, "source_ip", k=10)
        results.append(r)

        r = _measure("aggregation_time_histogram", agg.time_histogram, 3600)
        results.append(r)

        r = _measure("aggregation_coverage", agg.coverage_summary, {0, 1, 2})
        results.append(r)

        r = _measure("dataset_analytics_cache", lambda: dataset.analytics)
        results.append(r)

        r = _measure("dataset_query", dataset.query, {"operation": "EXACT", "field": "source_ip", "value": "10.0.0.1"})
        results.append(r)

        from ai.context import build_evidence_context

        question = "How many failed logins came from 10.0.0.1 and which user account was used?"

        r = _measure("evidence_seed_scan", build_evidence_context, df, question, max_events=24)
        results.append(r)

        r = _measure(
            "evidence_seed_indexed",
            build_evidence_context,
            df,
            question,
            max_events=24,
            event_index=index,
        )
        results.append(r)

        r = _measure(
            "evidence_seed_indexed_cached_terms",
            build_evidence_context,
            df,
            "failed login activity for that same user account",
            max_events=24,
            event_index=index,
        )
        results.append(r)

        from ai.investigation_agent import InvestigationToolLayer

        r = _measure("tool_catalog_build", InvestigationToolLayer, df)
        results.append(r)

        r = _measure("tool_catalog_build_indexed", InvestigationToolLayer, df, event_index=index)
        results.append(r)

        tool_layer = InvestigationToolLayer(df, event_index=index)
        r = _measure("tool_search_indexed", tool_layer.search_events, query="10.0.0.1", limit=12)
        results.append(r)

        dataset.get_tool_catalog()
        r = _measure("tool_catalog_shared_cached", lambda: dataset.get_tool_catalog())
        results.append(r)

        all_results["datasets"][str(size)] = {
            "event_count": size,
            "results": results,
        }

        for r in results:
            print(f"  {r['operation']:40s} {r['elapsed_seconds']:10.4f}s  {r['peak_memory_mb']:8.2f}MB  {r['status']}")

    return all_results


def main():
    print("LogAsis Optimized Performance Benchmark")
    print("=" * 60)

    sizes = [10000, 100000]
    if len(sys.argv) > 1:
        sizes = [int(x) for x in sys.argv[1].split(",")]

    results = run_optimized_benchmarks(sizes)

    output_path = Path(__file__).resolve().parent / "optimized_results.json"
    output_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
