"""Benchmark evaluator: score predictions against ground truth.

Metrics (each reported separately, undefined metrics reported as unavailable):
- exact-count accuracy
- question-answer accuracy (semantic)
- evidence precision / recall / citation validity (event_uid space)
- claim grounding / unsupported-claim rate
- abstention correctness (zero unsupported assertions of compromise,
  exfiltration, exploitation, or causation)
- coverage accounting, latency, provider errors

The evaluator is the ONLY component that reads ground truth, and it never
modifies predictions to fit the answer key.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.dataset import (  # noqa: E402
    evid_to_identity_mapping,
    load_file_through_pipeline,
    load_ground_truth,
)

# Phrases that assert a supported positive security conclusion. An abstention
# answer must not contain them (outside an explicit negation).
_POSITIVE_CONCLUSION_RE = re.compile(
    r"\b(?:proves?|confirms?|establishes|demonstrates)\s+(?:that\s+)?"
    r"(.{0,80}?)\s*(?:compromis|exfiltrat|exploit|breach|malware|infect|caused|causation)",
    re.I,
)
_REFUSAL_RE = re.compile(
    r"\b(?:does\s+not|do\s+not|not\s+establish|not\s+prove|cannot\s+(?:be\s+)?(?:establish|conclude|determine)|"
    r"not\s+by\s+itself|not,?\s+by\s+itself|no\s+evidence|insufficient|"
    r"not\s+demonstrat|causation\s+is\s+not|does\s+not,?\s+by\s+itself)\b",
    re.I,
)


def _has_refusal(text: str) -> bool:
    return bool(_REFUSAL_RE.search(text or ""))


def _asserts_conclusion(text: str) -> bool:
    """True when the text asserts (not negates) a proven compromise/exfil/etc."""
    for match in _POSITIVE_CONCLUSION_RE.finditer(text or ""):
        prefix = (text or "")[max(0, match.start() - 60):match.start()]
        if re.search(r"\b(?:does\s+not|do\s+not|not|never|cannot)\b", prefix, re.I):
            continue
        return True
    # Direct affirmative claims
    if re.search(r"\b(?:was|were|account\s+was)\s+compromised\b", text or "", re.I) and not re.search(
        r"\b(?:not|no|never)\s+(?:compromised|prove)", text, re.I
    ):
        return True
    if re.search(r"\bcaused\s+the\b", text or "", re.I) and not re.search(
        r"\b(?:not|does not|do not)\b", text, re.I
    ):
        return True
    return False


def evaluate(
    benchmark_dir: str | Path,
    predictions_path: str | Path,
    baseline_path: str | Path | None = None,
) -> dict[str, Any]:
    benchmark_dir = Path(benchmark_dir)
    predictions_doc = json.loads(Path(predictions_path).read_text(encoding="utf-8"))
    predictions = {p["id"]: p for p in predictions_doc.get("predictions", [])}
    ground_truth = {q["id"]: q for q in load_ground_truth(benchmark_dir)}

    # Evidence identity mapping per dataset (EVID -> event_uid).
    mappings: dict[str, dict[str, str]] = {}
    loaded_cache: dict[str, Any] = {}
    for qid, q in ground_truth.items():
        fname = q.get("dataset", "")
        if fname not in loaded_cache:
            loaded_cache[fname] = load_file_through_pipeline(benchmark_dir, fname)
            mappings[fname] = evid_to_identity_mapping(loaded_cache[fname])

    per_question: list[dict[str, Any]] = []
    counts = {
        "exact_count_total": 0,
        "exact_count_correct": 0,
        "qa_total": 0,
        "qa_correct": 0,
        "abstention_total": 0,
        "abstention_correct": 0,
        "citation_total": 0,
        "citation_valid": 0,
        "unsupported_claim_total": 0,
        "unsupported_claim_questions": 0,
    }
    evidence_recall_values: list[float] = []
    evidence_precision_values: list[float] = []
    latencies: list[float] = []
    provider_errors = 0

    for qid, q in sorted(ground_truth.items()):
        pred = predictions.get(qid)
        row: dict[str, Any] = {"id": qid, "answer_type": q.get("answer_type", "")}
        if pred is None:
            row["missing"] = True
            per_question.append(row)
            continue
        row["missing"] = False
        answer_text = str(pred.get("answer_text", "") or "")
        det = pred.get("deterministic") or {}
        fname = q.get("dataset", "")
        mapping = mappings.get(fname, {})
        reverse_map = {uid: evid for evid, uid in mapping.items()}

        latencies.append(float(pred.get("latency_seconds", 0) or 0))
        if pred.get("error"):
            provider_errors += 1

        # --- citation validity: every cited EVID id must exist in the dataset
        cited_evids = set()
        for match in re.findall(r"\[(EVID-\d+)\]", answer_text, re.I):
            cited_evids.add(match.upper())
        for evid in det.get("evidence_ids_all", []) or []:
            cited_evids.add(str(evid).upper())
        invalid = [e for e in cited_evids if e not in mapping]
        counts["citation_total"] += 1
        if not invalid:
            counts["citation_valid"] += 1
        row["citation_valid"] = not invalid
        row["invalid_citations"] = invalid[:10]

        # --- evidence precision/recall in event_uid space
        predicted_uids = {mapping[e] for e in cited_evids if e in mapping}
        expected_uids = {str(u) for u in q.get("evidence_ids", []) or []}
        if expected_uids:
            recall = len(predicted_uids & expected_uids) / len(expected_uids)
            precision = (
                len(predicted_uids & expected_uids) / len(predicted_uids)
                if predicted_uids else None
            )
            evidence_recall_values.append(recall)
            if precision is not None:
                evidence_precision_values.append(precision)
            row["evidence_recall"] = round(recall, 4)
            row["evidence_precision"] = round(precision, 4) if precision is not None else None

        # --- exact-count accuracy
        expected_count = q.get("expected_count")
        pred_count = det.get("count")
        if q.get("answer_type") == "exact_count" and expected_count is not None:
            counts["exact_count_total"] += 1
            ok = pred_count == expected_count
            if ok:
                counts["exact_count_correct"] += 1
            row["exact_count_match"] = ok
            row["predicted_count"] = pred_count
            row["expected_count"] = expected_count
            counts["qa_total"] += 1
            if ok:
                counts["qa_correct"] += 1
        elif q.get("answer_type") == "correlated_events" and expected_count is not None:
            counts["qa_total"] += 1
            ok = pred_count == expected_count
            if ok:
                counts["qa_correct"] += 1
            row["exact_count_match"] = ok
            row["predicted_count"] = pred_count
            row["expected_count"] = expected_count

        # --- abstention correctness
        if q.get("answer_type") in {"insufficient_evidence", "causality_not_established"}:
            counts["abstention_total"] += 1
            counts["qa_total"] += 1
            refused = _has_refusal(answer_text)
            asserted = _asserts_conclusion(answer_text)
            ok = refused and not asserted
            if ok:
                counts["abstention_correct"] += 1
                counts["qa_correct"] += 1
            row["abstention_correct"] = ok
            row["asserted_conclusion"] = asserted

        # --- claim grounding over structured claims
        claims = det.get("claims", []) or []
        unsupported = [
            c for c in claims
            if str(c.get("type", "")).upper() in {"UNSUPPORTED_CLAIM", "CONTRADICTED_CLAIM"}
        ]
        counts["unsupported_claim_questions"] += 1
        counts["unsupported_claim_total"] += len(unsupported)
        row["unsupported_claims"] = len(unsupported)

        row["coverage_status"] = (det.get("coverage", {}) or {}).get("coverage_status", "UNKNOWN")
        row["latency_seconds"] = pred.get("latency_seconds")
        per_question.append(row)

    def _ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    metrics = {
        "exact_count_accuracy": _ratio(counts["exact_count_correct"], counts["exact_count_total"]),
        "qa_accuracy": _ratio(counts["qa_correct"], counts["qa_total"]),
        "evidence_precision_mean": (
            round(statistics.mean(evidence_precision_values), 4) if evidence_precision_values else None
        ),
        "evidence_recall_mean": (
            round(statistics.mean(evidence_recall_values), 4) if evidence_recall_values else None
        ),
        "evidence_recall_min": (
            round(min(evidence_recall_values), 4) if evidence_recall_values else None
        ),
        "citation_validity": _ratio(counts["citation_valid"], counts["citation_total"]),
        "unsupported_claim_rate": _ratio(counts["unsupported_claim_total"], counts["unsupported_claim_questions"]),
        "abstention_correct_rate": _ratio(counts["abstention_correct"], counts["abstention_total"]),
        "median_latency_seconds": round(statistics.median(latencies), 3) if latencies else None,
        "p95_latency_seconds": (
            round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3) if latencies else None
        ),
        "provider_error_count": provider_errors,
    }

    report = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "predictions_path": str(predictions_path),
        "mode": predictions_doc.get("mode", "unknown"),
        "question_count": len(ground_truth),
        "counts": counts,
        "metrics": metrics,
        "release_gates": {
            "exact_count_accuracy>=0.99": (
                metrics["exact_count_accuracy"] is not None and metrics["exact_count_accuracy"] >= 0.99
            ),
            "citation_validity=1.0": metrics["citation_validity"] == 1.0,
            "abstention_unsupported_rate=0": (
                metrics["abstention_correct_rate"] is not None
                and counts["abstention_correct"] == counts["abstention_total"]
            ),
            "evidence_recall>=0.90": (
                metrics["evidence_recall_min"] is not None and metrics["evidence_recall_min"] >= 0.90
            ),
        },
        "per_question": per_question,
    }

    if baseline_path and Path(baseline_path).exists():
        try:
            baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
            report["baseline_comparison"] = {
                "baseline_path": str(baseline_path),
                "baseline_metrics": baseline.get("metrics", {}),
                "current_metrics": metrics,
            }
        except Exception:
            pass
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate LogAsis benchmark predictions")
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--baseline", default=None, help="Baseline results JSON for comparison")
    parser.add_argument("--output", default=None, help="Where to write the results JSON")
    args = parser.parse_args(argv)

    report = evaluate(args.benchmark, args.predictions, args.baseline)
    out = Path(args.output) if args.output else Path(args.predictions).with_name("results.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Results written to {out}")
    m = report["metrics"]
    for key, value in m.items():
        print(f"  {key}: {value}")
    print("Release gates:")
    for gate, ok in report["release_gates"].items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
