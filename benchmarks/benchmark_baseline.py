"""Baseline performance benchmark for LogAsis.

Measures current implementation performance across all key operations.
Run: python -m benchmarks.benchmark_baseline
"""

from __future__ import annotations

import json
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.analytics import events_to_dataframe, apply_filters, summary
from core.event_index import EventIndex
from core.log_parser import parse_file
from core.investigation import build_investigation_report
from core.ioc import extract_iocs
from core.detections import DetectionEngine
from core.integrity import build_evidence_manifest
from ai.rag import LogRAGIndex, build_rag_context


def _generate_synthetic_events(count: int) -> list[dict[str, Any]]:
    """Generate synthetic log events for benchmarking."""
    import random
    from datetime import datetime, timedelta

    base_time = datetime(2024, 1, 15, 8, 0, 0)
    events = []
    ips = [f"10.0.0.{i}" for i in range(1, 51)]
    users = [f"user{i}" for i in range(1, 21)]
    actions = ["failed_login", "successful_login", "command_exec", "file_access", "network_connect"]
    processes = ["sshd", "bash", "python", "cmd.exe", "powershell.exe", "nc", "curl"]

    for i in range(count):
        ts = base_time + timedelta(seconds=i * 30)
        events.append({
            "timestamp": ts.isoformat(),
            "event_type": random.choice(["USER_AUTH", "EXECVE", "SYSCALL", "NETWORK"]),
            "source_ip": random.choice(ips),
            "destination_ip": random.choice(ips),
            "username": random.choice(users),
            "process_name": random.choice(processes),
            "command": f"/usr/bin/{random.choice(processes)} --flag" if random.random() > 0.5 else "",
            "pid": str(random.randint(1000, 65535)),
            "ppid": str(random.randint(1, 999)),
            "uid": str(random.choice([0, 1000, 1001])),
            "euid": str(random.choice([0, 1000])),
            "auid": "1000",
            "audit_serial": str(random.randint(100000, 999999)),
            "action": random.choice(actions),
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "message": f"Event {i}: authentication attempt from {random.choice(ips)}",
            "line": str(i + 1),
        })
    return events


def _measure(label: str, func, *args, **kwargs) -> dict[str, Any]:
    """Measure execution time and memory of a function."""
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


def run_benchmarks(dataset_sizes: list[int] | None = None) -> dict[str, Any]:
    """Run all benchmarks and return results."""
    if dataset_sizes is None:
        dataset_sizes = [10000, 100000]

    all_results: dict[str, Any] = {
        "benchmark_version": "baseline-1.0",
        "timestamp": pd.Timestamp.now().isoformat(),
        "datasets": {},
    }

    for size in dataset_sizes:
        print(f"\n{'='*60}")
        print(f"Benchmarking with {size:,} events")
        print(f"{'='*60}")

        results: list[dict[str, Any]] = []

        # 1. Event generation (baseline)
        r = _measure("generate_synthetic_events", _generate_synthetic_events, size)
        results.append(r)
        events = _generate_synthetic_events(size)

        # 2. DataFrame conversion
        r = _measure("events_to_dataframe", events_to_dataframe, events)
        results.append(r)
        df = events_to_dataframe(events)

        # 3. EventIndex build
        r = _measure("event_index_build", EventIndex, df.fillna("").to_dict("records"))
        results.append(r)
        index = EventIndex(df.fillna("").to_dict("records"))

        # 4. Filter field population (current: full DataFrame scan)
        def populate_filter_values_current():
            values = df["source_ip"].fillna("").astype(str).str.strip()
            return sorted({v for v in values.tolist() if v}, key=lambda v: v.casefold())

        r = _measure("filter_value_population", populate_filter_values_current)
        results.append(r)

        # 5. Filter application (current: full DataFrame scan)
        def apply_filter_current():
            values = df["source_ip"].fillna("").astype(str).str.strip()
            return df[values.str.casefold() == "10.0.0.1"].copy()

        r = _measure("filter_application", apply_filter_current)
        results.append(r)

        # 6. EventIndex exact lookup (optimized)
        r = _measure("event_index_exact_lookup", index.exact, "source_ip", "10.0.0.1")
        results.append(r)

        # 7. Summary computation
        r = _measure("summary", summary, df)
        results.append(r)

        # 8. Investigation report
        r = _measure("build_investigation_report", build_investigation_report, df)
        results.append(r)

        # 9. IOC extraction
        r = _measure("extract_iocs", extract_iocs, df.fillna("").to_dict("records"))
        results.append(r)

        # 10. Detection engine
        r = _measure("detection_engine", DetectionEngine().run, df.fillna("").to_dict("records"))
        results.append(r)

        # 11. Evidence manifest
        r = _measure("build_evidence_manifest", build_evidence_manifest, "test.log", df.fillna("").to_dict("records"), [])
        results.append(r)

        # 12. RAG index build (current: per-question)
        r = _measure("rag_index_build", LogRAGIndex, df)
        results.append(r)

        # 13. RAG retrieval
        rag = LogRAGIndex(df)
        r = _measure("rag_retrieval", rag.retrieve, "failed login from 10.0.0.1", top_k=24)
        results.append(r)

        # 14. Full background analysis pipeline
        def full_analysis():
            report = build_investigation_report(df)
            iocs = extract_iocs(df.fillna("").to_dict("records"))
            detections = DetectionEngine().run(df.fillna("").to_dict("records"))
            manifest = build_evidence_manifest("test.log", df.fillna("").to_dict("records"), [])
            return {"report": report, "iocs": iocs, "detections": detections, "manifest": manifest}

        r = _measure("full_background_analysis", full_analysis)
        results.append(r)

        all_results["datasets"][str(size)] = {
            "event_count": size,
            "results": results,
        }

        for r in results:
            print(f"  {r['operation']:40s} {r['elapsed_seconds']:10.4f}s  {r['peak_memory_mb']:8.2f}MB  {r['status']}")

    return all_results


def main():
    print("LogAsis Baseline Performance Benchmark")
    print("=" * 60)

    sizes = [10000, 100000]
    if len(sys.argv) > 1:
        sizes = [int(x) for x in sys.argv[1].split(",")]

    results = run_benchmarks(sizes)

    output_path = Path(__file__).resolve().parent / "baseline_results.json"
    output_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
