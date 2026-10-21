"""Generate additional regression questions from the loaded benchmark datasets.

These are derived deterministically from the data schema (distinct values,
counts) WITHOUT reading ground truth, so they can extend the regression
suite without leaking the answer key. Each generated question records its
own deterministic expected answer computed by the same validated query
engine used in production.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.dataset import load_file_through_pipeline  # noqa: E402
from core.deterministic_qa import DeterministicQAEngine  # noqa: E402


def generate_questions(benchmark_dir: str | Path, max_per_file: int = 4) -> list[dict]:
    """Produce schema-derived questions with deterministic expected answers."""
    root = Path(benchmark_dir)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    out: list[dict] = []
    qnum = 1
    for entry in manifest.get("files", []):
        fname = entry["file"]
        loaded = load_file_through_pipeline(benchmark_dir, fname)
        df = loaded.df
        dataset = loaded.dataset
        engine = DeterministicQAEngine(df, dataset)
        schema = engine.schema

        candidates: list[tuple[str, dict[str, str]]] = []

        action_field = schema.canonical_field("action")
        event_type_field = schema.canonical_field("event_type")
        ip_field = schema.canonical_field("source_ip")
        user_field = schema.canonical_field("user") or schema.canonical_field("username")
        host_field = schema.canonical_field("host")

        if action_field and ip_field:
            actions = schema.distinct(action_field)[:2]
            ips = [v for v in schema.distinct(ip_field) if v][:40]
            if actions and ips:
                # Pick the action+ip pair with the smallest non-zero count for
                # a sharper regression probe.
                best = None
                for action in actions:
                    for ip in ips[:10]:
                        res = engine._execute({action_field: action, ip_field: ip})
                        count = int(res.get("count", 0))
                        if 0 < count and (best is None or count < best[0]):
                            best = (count, action, ip)
                if best:
                    count, action, ip = best
                    label = action.replace("_", " ")
                    candidates.append((
                        f"How many events with action {label} came from {ip}?",
                        {action_field: action, ip_field: ip},
                    ))

        if event_type_field and host_field:
            event_types = schema.distinct(event_type_field)[:3]
            hosts = [v for v in schema.distinct(host_field) if v][:5]
            event_types = [e for e in event_types if e]
            hosts = [h for h in hosts if h]
            for et in event_types:
                for host in hosts[:2]:
                    res = engine._execute({event_type_field: et, host_field: host})
                    if int(res.get("count", 0)) > 0:
                        candidates.append((
                            f"How many {str(et).replace('_', ' ')} events were recorded on host {host}?",
                            {event_type_field: et, host_field: host},
                        ))
                        break

        if user_field and action_field and schema.distinct(action_field):
            users = [v for v in schema.distinct(user_field) if v][:30]
            action = schema.distinct(action_field)[0]
            for user in users[:6]:
                res = engine._execute({user_field: user, action_field: action})
                if int(res.get("count", 0)) > 0:
                    label = action.replace("_", " ")
                    candidates.append((
                        f"How many events with action {label} involve user {user}?",
                        {user_field: user, action_field: action},
                    ))
                    break

        produced = 0
        for question, filters in candidates:
            if produced >= max_per_file:
                break
            res = engine._execute(filters)
            count = int(res.get("count", 0))
            det = engine.answer(question)
            if det is None or det.count != count:
                # Skip questions the deterministic engine cannot answer —
                # those would be unfair regressions.
                continue
            out.append({
                "id": f"GEN-{qnum:03d}",
                "dataset": fname,
                "question": question,
                "expected_count": count,
                "filters": filters,
                "answer_type": "exact_count",
                "generated": True,
                "evidence_ids": [loaded.position_identity.get(p, f"pos:{p}") for p in res.get("positions", [])][:200],
            })
            qnum += 1
            produced += 1
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate regression questions from the corpus")
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--max-per-file", type=int, default=4)
    parser.add_argument("--output", default="benchmarks/generated_questions.jsonl")
    args = parser.parse_args(argv)

    questions = generate_questions(args.benchmark, args.max_per_file)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for q in questions:
            handle.write(json.dumps(q, ensure_ascii=False) + "\n")
    print(f"Generated {len(questions)} questions -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
