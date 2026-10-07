# LogAsis Evaluation Framework

## Metrics

### Question Answer Accuracy
- Exact-match accuracy for factual questions
- Claim-level scoring for analytical questions

### Evidence Metrics
- Evidence Recall@K
- Evidence Precision@K
- MRR (Mean Reciprocal Rank)
- F1 Score

### Claim Metrics
- Claim Grounding Accuracy
- Unsupported Claim Rate
- Citation Accuracy

### System Metrics
- Latency (retrieval, planning, provider, total)
- Token Usage
- Investigation Steps
- Tool Calls

## Benchmark Suite

### Filter Tests
- Exact field lookup
- Multiple filters (AND, OR, NOT)
- Empty results
- High-cardinality fields
- Long values
- Custom fields
- Case handling
- Numeric fields
- Timestamps
- Stale request cancellation

### AI Tests
- Arbitrary question
- Known question
- Paraphrased question
- Unseen question
- Unknown field
- Multi-event question
- Timeline question
- Contradiction question
- Insufficient evidence
- Provider failure
- Malformed provider response

### Grounding Tests
- Unsupported claim rejection
- Valid claim acceptance
- Multiple evidence IDs
- Contradiction detection
- False premise handling

### RAG Tests
- Index built once
- Reused across questions
- Cache invalidation
- Exact identifier retrieval
- Lexical retrieval
- Semantic retrieval

## Evaluation Commands

```bash
# Run all tests
python -m pytest tests/ -v

# Run performance benchmarks
python -m benchmarks.benchmark_baseline
python -m benchmarks.benchmark_optimized

# Prepare a dataset and generate ground-truth questions
python -m training.prepare --dataset HDFS_v1
python -m training.generate_questions --dataset HDFS_v1

# Retrieval benchmark (no model/provider required):
# Recall@K, MRR, precision, F1, latency of the index-backed retriever
python -m training.benchmark --dataset HDFS_v1

# Full model evaluation: run your model over questions.json to produce
# predictions.json, then score answer accuracy, claim grounding,
# citation accuracy, and system metrics
python -m training.evaluate --predictions preds.json --ground-truth data/prepared/HDFS_v1/questions.json
```

Metrics that cannot be computed from the supplied inputs are reported as
`null` (never a misleading 0.0) - for example `question_answer_accuracy`
when predictions contain only evidence IDs.

## Split Methodology

- **Train**: 70% of examples
- **Validation**: 15% of examples
- **Test**: 15% of examples

Split by:
- Dataset (no overlap between train/test datasets)
- Scenario (no overlap between train/test scenarios)
- Question formulation (different wordings in different splits)

`training.split_dataset(examples, group_key="type")` assigns whole groups
to a single split so the same template/scenario never appears in two
splits. `training.validate_dataset` verifies that split files are
question-disjoint.

## Leakage Prevention

- Never evaluate on the same examples used for generation/tuning
- Include completely unseen logs in the test set
- A model that answers different wording of the same memorized log is not demonstrating generalization
