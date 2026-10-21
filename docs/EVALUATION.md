# Evaluation and benchmarking

LogAsis is evaluated against the synthetic LogAsis AI Analyst Benchmark
(`E:\LogAsis_AI_Analyst_Benchmark`): 7 NDJSON log files (14,999 events), 18
reference questions with ground-truth answers, exact counts, filters, and
`event_uid` evidence identifiers.

**Leakage rule:** the ground truth directory is the evaluator's answer key.
It is never passed into the AI prompt, the retrieval corpus, or the query
layer during scored runs. Predictions are written separately from ground
truth.

## Workflow

Run from the repository root. All commands use the production ingestion
pipeline (parsers → events_to_dataframe → LogDataset).

```powershell
# 1. Validate dataset hashes and ingest every file (verifies counts)
python -m training.prepare --benchmark "E:\LogAsis_AI_Analyst_Benchmark" --output benchmarks/prepared_dataset.json

# 2. Run all questions through the AI Analyst (deterministic mode; no
#    provider needed because factual questions are answered by the
#    deterministic query engine). Add --provider to route analytical
#    questions through the configured Live AI provider.
python -m training.benchmark --benchmark "E:\LogAsis_AI_Analyst_Benchmark" --output benchmarks/predictions.json

# 3. Score the predictions against ground truth (separate step; the only
#    component that reads the answer key)
python -m training.evaluate --benchmark "E:\LogAsis_AI_Analyst_Benchmark" --predictions benchmarks/predictions.json --output benchmarks/results.json

# 4. Optional: generate extra schema-derived regression questions
python -m training.generate_questions --benchmark "E:\LogAsis_AI_Analyst_Benchmark" --output benchmarks/generated_questions.jsonl

# 5. Optional: leakage-safe training example export (split by scenario group)
python -m training.finetune_export --benchmark "E:\LogAsis_AI_Analyst_Benchmark" --output training_exports
```

## Metrics (reported separately, never aggregated into one score)

| Metric | Definition | Denominator |
|---|---|---|
| exact_count_accuracy | predicted count == expected count | questions with `expected_count` |
| qa_accuracy | count match (factual) or refusal semantics (abstention) | all scored questions |
| evidence_precision | |predicted ∩ expected| / |predicted| | questions with expected evidence |
| evidence_recall | |predicted ∩ expected| / |expected| | questions with expected evidence |
| citation_validity | every cited EVID id resolves in the loaded dataset | all answered questions |
| unsupported_claim_rate | claims typed UNSUPPORTED/CONTRADICTED per question | questions with structured claims |
| abstention_correct_rate | refusal present AND no asserted conclusion | abstention questions |
| latency | median and p95 wall-clock per question | all questions |
| provider_error_count | questions where the provider raised | all questions |

Undefined metrics (empty denominators) are reported as `null`, never as 0.

## Release gates (initial)

- exact_count_accuracy ≥ 0.99 on deterministic count questions
- citation validity = 1.0 (every emitted evidence reference exists)
- zero unsupported assertions of compromise/exfiltration/exploitation/causation
  in the explicit abstention cases
- evidence recall ≥ 0.90 on questions with a fully specified expected evidence set
- every answer discloses truncation/partial coverage when present

## Regression tests

```powershell
python -m pytest tests/ -v          # full suite (83 tests)
python -m pytest tests/ -q          # quick run
```

Benchmark integration tests load the real corpus and are skipped
automatically when the benchmark directory is not present.

## Baseline comparison

`training.evaluate --baseline <results.json>` compares the current metrics
with a previously recorded run. Keep the evaluated predictions file immutable
after scoring; never retune prompts or code against the scored test split
without re-running everything afterwards.
