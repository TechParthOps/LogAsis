"""Benchmark runner: execute reference questions through the AI Analyst.

Predictions are written separately from ground truth. The runner never passes
ground-truth answers, filters, expected counts, or expected evidence IDs into
the prompt or retrieval corpus. Questions run through the production
LogInvestigatorAgent path; deterministic questions are answered without a
provider, analytical questions use the configured provider when available.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.dataset import load_file_through_pipeline, load_ground_truth  # noqa: E402


def run_benchmark(
    benchmark_dir: str | Path,
    output_path: str | Path,
    use_provider: bool = False,
    provider_name: str = "Live AI",
    progress=None,
) -> dict[str, Any]:
    progress = progress or (lambda *a, **k: None)
    benchmark_dir = Path(benchmark_dir)
    questions = load_ground_truth(benchmark_dir)

    # Keep the AI answer cache disabled for scored runs: a cached answer from
    # a previous code version must never be scored as a fresh result.
    os.environ["LOGASIS_AI_CACHE"] = "0"

    from core.question_understanding import QuestionSchema, analyze_question  # noqa: E402
    from ai.agent import LogInvestigatorAgent  # noqa: E402

    loaded_by_file: dict[str, Any] = {}
    predictions: list[dict[str, Any]] = []
    started = time.perf_counter()

    agent = None
    if use_provider:
        agent = LogInvestigatorAgent.with_provider(provider_name)

    # Scenario-group conversation context mirrors the GUI session: earlier
    # questions in the same group may be referenced ("this source").
    groups: dict[str, list[dict[str, Any]]] = {}
    for q in questions:
        groups.setdefault(str(q.get("split_group", q["id"])), []).append(q)

    for gi, (group_name, group_questions) in enumerate(sorted(groups.items()), 1):
        prior_questions: list[str] = []
        for qi, q in enumerate(group_questions, 1):
            progress(
                int(((gi - 1) / len(groups)) * 100),
                f"[{gi}/{len(groups)}] {q['id']}",
            )
            dataset_file = str(q.get("dataset", ""))
            if dataset_file not in loaded_by_file:
                loaded_by_file[dataset_file] = load_file_through_pipeline(benchmark_dir, dataset_file)
            loaded = loaded_by_file[dataset_file]
            df = loaded.df
            dataset = loaded.dataset

            # Extract question entities for context (schema-derived only).
            entities: list[dict[str, Any]] = []
            try:
                schema = QuestionSchema(dataset.event_index)
                analysis = analyze_question(str(q["question"]), schema)
                entities = [e.to_dict() for e in analysis.entities]
            except Exception:
                entities = []

            t0 = time.perf_counter()
            error = ""
            answer_text = ""
            provider_used = False
            try:
                if agent is not None:
                    answer_text = agent.answer(
                        str(q["question"]),
                        df,
                        source_file=dataset_file,
                        dataset=dataset,
                        conversation_context=list(prior_questions),
                    )
                    provider_used = True
                else:
                    # Deterministic-only mode: same production path as the
                    # app (agent.answer short-circuits to the deterministic
                    # engine when the question is factually answerable).
                    agent_det = LogInvestigatorAgent(provider=None)
                    answer_text = agent_det.answer(
                        str(q["question"]),
                        df,
                        source_file=dataset_file,
                        dataset=dataset,
                        conversation_context=list(prior_questions),
                    )
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            latency = time.perf_counter() - t0

            # Structured result for evidence/coverage scoring. Re-run the
            # deterministic engine on the SAME question to capture the
            # structured query metadata that the rendered report summarizes.
            # Ground truth is never consulted here.
            structured: dict[str, Any] = {}
            try:
                from core.deterministic_qa import DeterministicQAEngine
                from core.question_understanding import QuestionSchema as _QS

                engine = DeterministicQAEngine(df, dataset)
                context = _build_context(engine, prior_questions)
                det = engine.answer(str(q["question"]), context)
                if det is not None:
                    structured = det.to_dict(max_records=10)
            except Exception:
                structured = {}

            predictions.append({
                "id": q["id"],
                "question": q["question"],
                "dataset": dataset_file,
                "answer_text": answer_text,
                "error": error,
                "provider_used": provider_used,
                "latency_seconds": round(latency, 3),
                "question_entities": entities,
                "deterministic": structured,
            })
            prior_questions.append(str(q["question"]))

    elapsed = time.perf_counter() - started
    output = {
        "runner_version": "logasis-benchmark-1.0",
        "benchmark_dir": str(benchmark_dir),
        "mode": "provider" if use_provider else "deterministic",
        "elapsed_seconds": round(elapsed, 2),
        "question_count": len(predictions),
        "predictions": predictions,
    }
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def _build_context(engine, prior_questions: list[str]) -> list[dict[str, Any]]:
    """Build conversation context from prior question strings."""
    from core.question_understanding import QuestionSchema, analyze_question

    context = []
    for q in prior_questions[-6:]:
        try:
            analysis = analyze_question(str(q), engine.schema)
            context.append({
                "question": str(q),
                "entities": [e.to_dict() for e in analysis.entities],
            })
        except Exception:
            continue
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run LogAsis benchmark questions")
    parser.add_argument("--benchmark", required=True, help="Path to the benchmark directory")
    parser.add_argument("--output", default="benchmarks/predictions.json", help="Predictions output path")
    parser.add_argument("--provider", action="store_true", help="Route analytical questions through the configured provider")
    parser.add_argument("--provider-name", default="Live AI")
    args = parser.parse_args(argv)

    def progress(pct, msg):
        print(f"[{pct:3d}%] {msg}")

    result = run_benchmark(args.benchmark, args.output, use_provider=args.provider,
                           provider_name=args.provider_name, progress=progress)
    errors = [p for p in result["predictions"] if p["error"]]
    print(f"Predictions written to {args.output}")
    print(f"Questions: {result['question_count']}, errors: {len(errors)}")
    for p in errors:
        print(f"  ERROR {p['id']}: {p['error']}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
