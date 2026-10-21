"""Benchmark dataset loading and validation through the real LogAsis pipeline.

All ingestion goes through the production parsers and LogDataset so the
benchmark measures the actual application behavior, never a shortcut.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from core.log_dataset import LogDataset
from parsers.json_log import JsonLogParser
from parsers.syslog import SyslogParser
from core.log_parser import parse_file as parse_generic_file
from core.analytics import events_to_dataframe


@dataclass
class BenchmarkFile:
    name: str
    path: Path
    expected_events: int
    sha256: str
    actual_events: int = 0
    hash_ok: bool = False
    parse_ok: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class LoadedDataset:
    file_name: str
    dataset: LogDataset
    df: pd.DataFrame
    # position -> event_uid mapping for evidence identity checks
    position_identity: dict[int, str] = field(default_factory=dict)


def validate_files(benchmark_dir: str | Path) -> tuple[list[BenchmarkFile], dict[str, Any]]:
    """Validate file hashes/counts against manifest.json."""
    root = Path(benchmark_dir)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files: list[BenchmarkFile] = []
    for entry in manifest.get("files", []):
        rel = entry.get("file", "")
        path = root / rel
        item = BenchmarkFile(
            name=rel,
            path=path,
            expected_events=int(entry.get("events", 0)),
            sha256=str(entry.get("sha256", "")).lower(),
        )
        if not path.exists():
            item.notes.append("file missing")
            files.append(item)
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        item.hash_ok = digest == item.sha256
        if not item.hash_ok:
            item.notes.append(f"sha256 mismatch: {digest}")
        files.append(item)
    return files, manifest


def load_ground_truth(benchmark_dir: str | Path) -> list[dict[str, Any]]:
    path = Path(benchmark_dir) / "ground_truth" / "questions_ground_truth.jsonl"
    questions = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            questions.append(json.loads(line))
    return questions


def load_file_through_pipeline(benchmark_dir: str | Path, file_name: str) -> LoadedDataset:
    """Ingest one benchmark log with the production ingestion path."""
    root = Path(benchmark_dir)
    path = root / file_name
    if not path.exists():
        # Ground truth references bare file names; the manifest uses logs/...
        path = root / "logs" / Path(file_name).name
    if not path.exists():
        raise FileNotFoundError(f"Benchmark log not found: {file_name}")
    text = path.read_text(encoding="utf-8", errors="replace")
    # Production parsers. The benchmark corpus is NDJSON.
    parser = JsonLogParser()
    events = parser.parse(text)
    if not events:
        # Fall back to the generic parser for non-JSON benchmark fixtures.
        parsed = parse_generic_file(str(path))
        events = [e.to_dict() for e in parsed]
    df = events_to_dataframe(events)
    dataset = LogDataset(df, source_file=str(path))
    identity: dict[int, str] = {}
    if "event_uid" in df.columns:
        for pos, value in enumerate(df["event_uid"].fillna("").astype(str)):
            if value.strip():
                identity[pos] = value.strip()
    return LoadedDataset(file_name=file_name, dataset=dataset, df=df, position_identity=identity)


def prepare_datasets(
    benchmark_dir: str | Path,
    progress=None,
) -> dict[str, Any]:
    """Validate + ingest every benchmark file. Returns a report dict."""
    progress = progress or (lambda *a, **k: None)
    files, manifest = validate_files(benchmark_dir)
    report: dict[str, Any] = {
        "benchmark_dir": str(benchmark_dir),
        "files": [],
        "all_hashes_ok": True,
        "all_counts_ok": True,
    }
    for item in files:
        progress(10, f"Validating {item.name}")
        entry = {
            "file": item.name,
            "expected_events": item.expected_events,
            "sha256_ok": item.hash_ok,
            "notes": list(item.notes),
        }
        if item.path.exists() and item.hash_ok:
            progress(50, f"Ingesting {item.name}")
            loaded = load_file_through_pipeline(benchmark_dir, item.name)
            item.actual_events = int(len(loaded.df))
            entry["parsed_events"] = item.actual_events
            entry["count_ok"] = item.actual_events == item.expected_events
            entry["indexed_events"] = int(loaded.dataset.event_index.size)
            entry["identity_mapped"] = len(loaded.position_identity)
            if not entry["count_ok"]:
                report["all_counts_ok"] = False
                entry["notes"].append(
                    f"parsed {item.actual_events} != expected {item.expected_events}"
                )
        else:
            report["all_hashes_ok"] = False
        report["files"].append(entry)
    report["total_events"] = sum(f["expected_events"] for f in report["files"])
    return report


def evid_to_identity_mapping(loaded: LoadedDataset) -> dict[str, str]:
    """Map runtime evidence IDs (EVID-NNN) to source identities (event_uid)."""
    return {
        f"EVID-{pos + 1:03d}": uid
        for pos, uid in loaded.position_identity.items()
    }
