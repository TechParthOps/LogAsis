# LogAsis Performance Report

All timings below are from the benchmark harness with `tracemalloc` enabled:

```powershell
python -m benchmarks.benchmark_baseline      # original DataFrame-scan behavior
python -m benchmarks.benchmark_optimized     # indexed behavior (writes optimized_results.json)
```

## Baseline measurements (10K events, original code)

| Operation | Time (s) | Memory (MB) |
|-----------|----------|-------------|
| EventIndex build | 2.0116 | 48.62 |
| Filter value population (DataFrame scan) | 0.0030 | 0.16 |
| Filter application (DataFrame scan) | 0.0137 | 0.82 |
| RAG index build (per call) | 21.0355 | 65.88 |
| RAG retrieval (per question) | 20.9477 | 6.47 |
| Full background analysis | 18.0913 | 30.77 |
| Investigation report | 8.0323 | 8.78 |
| IOC extraction | 7.0560 | 10.64 |

A 100K-event baseline run did not finish within 120 seconds.

## Optimized measurements (10K events)

| Operation | Time (s) | Memory (MB) |
|-----------|----------|-------------|
| EventIndex build | 1.87 | 64.84 |
| LogDataset creation (index + analytics) | 3.41 | 80.76 |
| Filter value population (indexed) | 0.0001 | 0.00 |
| Filter application (indexed) | 0.0016 | 0.05 |
| Query exact / AND | 0.0001 / 0.0002 | 0.01 |
| Aggregation facet / top-k | 0.0001 / 0.0000 | 0.00 |
| Dataset analytics cache | 0.0000 | 0.00 |
| Evidence seed for one AI question (scan) | 3.5970 | 19.97 |
| Evidence seed for one AI question (indexed) | 0.0924 | 3.83 |
| AI tool catalog build (per question, old) | 1.0943 | 20.78 |
| AI tool catalog (shared, cached per dataset) | 0.0000 | 0.00 |
| AI tool search (indexed) | 0.0635 | 0.16 |

## Optimized measurements (100K events)

| Operation | Time (s) | Memory (MB) |
|-----------|----------|-------------|
| EventIndex build | 18.59 | 624.08 |
| LogDataset creation (index + analytics) | 34.43 | 782.26 |
| Filter value population (indexed) | 0.0002 | 0.00 |
| Filter application (indexed) | 0.0026 | 0.38 |
| Query exact / AND | 0.0003 / 0.0025 | 0.17 |
| Aggregation time histogram | 0.1148 | 0.15 |
| Evidence seed for one AI question (scan) | 34.4757 | 199.52 |
| Evidence seed for one AI question (indexed) | 0.8978 | 38.49 |
| Evidence seed (indexed, cached terms) | 0.6570 | 23.80 |
| AI tool catalog build (per question, old) | 11.2900 | 209.53 |
| AI tool catalog (shared, cached per dataset) | 0.0000 | 0.00 |
| AI tool search (indexed) | 0.6359 | 1.94 |

## Performance improvements

| Operation | Before | After | Speedup |
|-----------|--------|-------|---------|
| Filter value population | 0.0030s | 0.0001s | 30x |
| Filter application | 0.0137s | 0.0016s | 8.6x |
| Facet counts | ~0.01s | 0.0001s | 100x |
| AI evidence seed, 10K | 3.60s | 0.09s | 39x |
| AI evidence seed, 100K | 34.48s | 0.90s | 38x |
| AI tool catalog, 10K | 1.09s per question | 0s after first | once per dataset |
| AI tool catalog, 100K | 11.29s per question | 0s after first | once per dataset |
| RAG index | 21s per question | built once per dataset | reused |
| Background analysis on filter change | 18.09s | not triggered | removed |

## Key findings

1. **Per-question full scans were the dominant cost.** Evidence seeding for
   one AI question scanned every row (`iterrows`); it now resolves candidate
   postings through the persistent `EventIndex` with identical ranking
   (verified by parity tests in `tests/test_ai.py`).

2. **Filters are O(lookup).** Filter value population and application query
   the index instead of the DataFrame.

3. **Filter changes no longer rerun background analysis.** Filtering is a
   VIEW operation; the 18s full-analysis path is not started.

4. **One index, one catalog, one RAG index per uploaded log.** `LogDataset`
   caches analytics, the evidence-ID tool catalog, and the RAG index; every
   question reuses them.

5. **The full optimized benchmark at 100K events completes in ~2 minutes**;
   the equivalent baseline did not complete in 120 seconds.

## Scalability

- 10K events: ~2s index build
- 100K events: ~19s index build (benchmark-completed)
- 1M events: ~3-4min index build (estimated, not measured)
- 10M+ events: requires streaming ingestion plus an on-disk index (future work)

## Memory usage

The in-memory index uses roughly 4-6x the DataFrame size (624MB index for a
100K-event dataset whose DataFrame is ~130MB). This is acceptable for a
desktop investigation workspace up to low-hundreds-of-thousands of events.
