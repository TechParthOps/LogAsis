"""Benchmark integration tests (run when the corpus is available).

These load the real benchmark corpus through the production pipeline and
verify the release gates end-to-end. Marked slow; skipped automatically when
E:\\LogAsis_AI_Analyst_Benchmark is not present.
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import BENCHMARK_DIR, skip_without_benchmark

pytestmark = skip_without_benchmark()


@pytest.fixture(scope="module")
def loaded_datasets():
    from training.dataset import load_file_through_pipeline

    files = [
        "authentication_large.jsonl", "web_security_large.jsonl",
        "endpoint_process_large.jsonl", "dns_firewall_large.jsonl",
        "linux_audit_large.jsonl", "mixed_enterprise_large.jsonl",
        "parser_edge_cases.jsonl",
    ]
    return {f: load_file_through_pipeline(BENCHMARK_DIR, f) for f in files}


class TestIngestion:
    def test_event_counts_match_manifest(self, loaded_datasets):
        manifest = json.loads((BENCHMARK_DIR / "manifest.json").read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            name = entry["file"].split("/")[-1]
            assert len(loaded_datasets[name].df) == entry["events"], name

    def test_index_covers_dataset(self, loaded_datasets):
        for name, loaded in loaded_datasets.items():
            assert loaded.dataset.event_index.size == len(loaded.df), name

    def test_parser_edge_cases_survive(self, loaded_datasets):
        loaded = loaded_datasets["parser_edge_cases.jsonl"]
        assert len(loaded.df) == 5
        assert "timestamp_parse_failed" in loaded.df.columns

    def test_prompt_injection_record_is_data(self, loaded_datasets):
        loaded = loaded_datasets["parser_edge_cases.jsonl"]
        from core.log_dataset import safe_frame_records
        texts = " ".join(str(v) for v in safe_frame_records(loaded.df)[3].values())
        assert "ignore previous instructions" in texts.lower()


class TestBenchmarkQuestions:
    def _ground_truth(self):
        from training.dataset import load_ground_truth

        return load_ground_truth(BENCHMARK_DIR)

    def test_all_exact_counts_exact(self, loaded_datasets):
        from core.deterministic_qa import DeterministicQAEngine

        gt = [q for q in self._ground_truth() if q.get("answer_type") == "exact_count"]
        assert len(gt) == 11
        for q in gt:
            loaded = loaded_datasets[q["dataset"]]
            engine = DeterministicQAEngine(loaded.df, loaded.dataset)
            result = engine.answer(q["question"])
            assert result is not None, q["id"]
            assert result.count == q["expected_count"], (
                f"{q['id']}: {result.count} != {q['expected_count']}"
            )

    def test_all_abstentions_refuse(self, loaded_datasets):
        from core.deterministic_qa import DeterministicQAEngine

        gt = [
            q for q in self._ground_truth()
            if q.get("answer_type") in {"insufficient_evidence", "causality_not_established"}
        ]
        assert len(gt) == 6
        for q in gt:
            loaded = loaded_datasets[q["dataset"]]
            engine = DeterministicQAEngine(loaded.df, loaded.dataset)
            result = engine.answer(q["question"])
            assert result is not None, q["id"]
            text = result.answer.lower()
            assert any(
                phrase in text
                for phrase in ("does not", "not established", "do not prove", "not prove",
                               "not demonstrate", "not, by itself", "not by itself")
            ), q["id"]

    def test_correlated_events_question(self, loaded_datasets):
        from core.deterministic_qa import DeterministicQAEngine

        gt = [q for q in self._ground_truth() if q.get("answer_type") == "correlated_events"]
        assert len(gt) == 1
        q = gt[0]
        loaded = loaded_datasets[q["dataset"]]
        engine = DeterministicQAEngine(loaded.df, loaded.dataset)
        result = engine.answer(q["question"])
        assert result is not None
        assert result.count == q["expected_count"]

    def test_repeated_runs_deterministic(self, loaded_datasets):
        from core.deterministic_qa import DeterministicQAEngine

        q = self._ground_truth()[0]
        loaded = loaded_datasets[q["dataset"]]
        counts = set()
        ids = set()
        for _ in range(3):
            engine = DeterministicQAEngine(loaded.df, loaded.dataset)
            result = engine.answer(q["question"])
            counts.add(result.count)
            ids.add(tuple(result.evidence_ids_all))
        assert len(counts) == 1
        assert len(ids) == 1
