"""LogAsis training/evaluation tooling.

Public entry points (see docs/EVALUATION.md):

- ``python -m training.prepare    --benchmark <dir>``  validate + ingest the benchmark corpus
- ``python -m training.benchmark  --benchmark <dir>``  run the questions, write predictions
- ``python -m training.evaluate   --benchmark <dir>``  score predictions against ground truth
- ``python -m training.generate_questions --benchmark <dir>``  derive extra regression questions
- ``python -m training.finetune_export --benchmark <dir>``  leakage-safe training example export

The scored evaluator never passes ground truth (filters, expected counts,
expected evidence IDs) into the AI's prompt or retrieval corpus. Predictions
are written separately from ground truth.
"""

__all__ = [
    "dataset",
    "prepare",
    "benchmark",
    "evaluate",
    "generate_questions",
    "finetune_export",
]
