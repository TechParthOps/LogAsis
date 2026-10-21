"""Optional, provider-independent export of curated training examples.

Implements section 14 of the accuracy program:
- Splits by scenario group (never by individual rows) so near-duplicate
  scenarios cannot leak across splits.
- Includes normal observations, suspicious-but-benign behavior, conflicting
  evidence, false premises, and insufficient-evidence cases drawn from the
  benchmark corpus and from claim-verification checks.
- Reference evidence is exported with each example.
- Fine-tuning is optional: normal application operation never requires it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.dataset import load_file_through_pipeline, load_ground_truth  # noqa: E402


def _stable_group_split(group_name: str, ratios=(0.6, 0.2, 0.2)) -> str:
    """Deterministic scenario-level split assignment."""
    digest = hashlib.sha256(str(group_name).encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) % 1000 / 1000
    if bucket < ratios[0]:
        return "train"
    if bucket < ratios[0] + ratios[1]:
        return "validation"
    return "test"


def export(
    benchmark_dir: str | Path,
    output_dir: str | Path,
) -> dict:
    root = Path(benchmark_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    questions = load_ground_truth(root)
    loaded_cache: dict[str, Any] = {}

    examples: list[dict] = []
    for q in questions:
        fname = str(q.get("dataset", ""))
        if fname not in loaded_cache:
            loaded_cache[fname] = load_file_through_pipeline(root, fname)
        group = str(q.get("split_group", q["id"]))
        split = str(q.get("split") or _stable_group_split(group))
        example = {
            "id": q["id"],
            "scenario_group": group,
            "split": split,
            "dataset": fname,
            "question": q["question"],
            "reference_answer": q.get("expected_answer") or q.get("reference_answer", ""),
            "answer_type": q.get("answer_type", ""),
            "expected_count": q.get("expected_count"),
            "reference_evidence_ids": list(q.get("evidence_ids", []) or []),
            "filters": q.get("filters") or {},
        }
        examples.append(example)

    # Split integrity check: no scenario group may appear in two splits.
    group_splits: dict[str, set[str]] = {}
    for example in examples:
        group_splits.setdefault(example["scenario_group"], set()).add(example["split"])
    leakage = {g: s for g, s in group_splits.items() if len(s) > 1}

    split_counts = {"train": 0, "validation": 0, "test": 0}
    for example in examples:
        split_counts[example["split"]] = split_counts.get(example["split"], 0) + 1

    files = {}
    for split in ("train", "validation", "test"):
        payload = [e for e in examples if e["split"] == split]
        target = out_dir / f"{split}_examples.jsonl"
        with target.open("w", encoding="utf-8") as handle:
            for example in payload:
                handle.write(json.dumps(example, ensure_ascii=False) + "\n")
        files[str(target)] = len(payload)

    report = {
        "exported_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "total_examples": len(examples),
        "split_counts": split_counts,
        "scenario_groups": len(group_splits),
        "leakage_groups": leakage,
        "files": files,
        "note": (
            "Examples contain reference answers and evidence for evaluation/fine-tuning. "
            "Never include test answers in prompts or retrieval corpora, and never tune "
            "on the scored test split."
        ),
    }
    (out_dir / "export_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export curated training examples")
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--output", default="training_exports")
    args = parser.parse_args(argv)
    report = export(args.benchmark, args.output)
    print(json.dumps(report, indent=2))
    return 0 if not report["leakage_groups"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
