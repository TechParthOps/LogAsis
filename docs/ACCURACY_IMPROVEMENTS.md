# LogAsis AI Analyst — Accuracy, Evidence Grounding & Benchmark Results

Date: 2026-10-18
Scope: full accuracy/evidence-grounding upgrade executed against
`E:\LogAsis-main` with the synthetic benchmark corpus at
`E:\LogAsis_AI_Analyst_Benchmark`.

Companion documents:
- `docs/AUDIT_2026-10-17.md` — Phase 1 root-cause audit (all defects reproduced)
- `docs/EVALUATION.md` — how to reproduce the benchmark
- `docs/AI_INVESTIGATION.md` — updated architecture

---

## 1. Root-cause analysis of the original hallucination defects

Every defect below was **reproduced by execution** before being fixed (see
the audit doc for reproduction steps). The most consequential causes:

### Wrong exact counts
1. **`EventIndex.intersect` returned ALL rows when every condition set was
   empty** (`core/event_index.py`). Reproduced: an AND query with one
   non-matching filter returned 854 rows instead of 0.
2. **`QueryEngine._finalize` overwrote `count` with the truncated sample
   length** when a `limit` was set. Reproduced: 45 matching events reported
   as 5.
3. **Bare field/value condition dicts compiled to an empty AND that matched
   every row** (`core/query_engine.py::compile`). A malformed model-produced
   plan silently became "match everything" (reproduced: 2,500 of 2,500 rows).
4. **No deterministic count path existed at all**: the investigation runtime
   had no aggregation tool, so the model estimated totals from ≤64 sampled
   records.

### Unsupported / fabricated statements
5. `core/claim_verification.py` classified nearly every claim as a
   HIGH-confidence VERIFIED_FACT because certainty detection used substrings
   like `"is"` (matching "this"/"analysis").
6. `_aggregate_support_gap` validated set-level counts against the ≤64-record
   evidence bundle — rejecting TRUE dataset-level counts and inviting the
   model to hedge.
7. No causal guard: "X caused Y" could pass with only temporal evidence.

### Large-log and pipeline defects
8. `events_to_dataframe` crashed on files with malformed or mixed-format
   timestamps (the parser edge-case file was **unloadable**).
9. `EventIndex` timestamp sorting crashed on mixed naive/aware timestamps.
10. `df.fillna("")` crashed on datetime/nullable-integer columns containing
    missing values, breaking index builds and several GUI refresh paths.
11. GUI upload ran parse → normalize → index → analytics → render entirely on
    the Qt GUI thread → Windows "Not responding".

---

## 2. What was implemented

1. **Deterministic factual layer** (`core/question_understanding.py`,
   `core/deterministic_qa.py`): dynamic schema discovery, entity resolution
   against actual distinct values, standard security-log phrase vocabulary,
   well-known service ports, time constraints ("after the failures"),
   contextual references ("this source") from session history, labelled-
   sequence interpretation, verified zeros for identifiers absent from every
   field, and abstention scaffolds for prove/cause questions with explicit
   anti-hallucination refusals. Every plan is validated by
   `QueryEngine.compile` (fail-closed) before execution; every number in the
   answer is an executed query result.
2. **Query/index repairs**: fail-closed `intersect`, count/limit separation
   (`count` vs `returned_count` vs `truncated`), plan validation with
   explicit errors, UTC-normalized timestamp parsing, datetime-safe record
   serialization (`safe_frame_records`), parse-failure flags.
3. **Investigation runtime**: `count_events` tool (exact, exhaustive),
   coverage accounting (`total_events` … `completion_reason`), completion
   status (`COMPLETED_SUFFICIENT`, `COMPLETED_INSUFFICIENT`, `PARTIAL`,
   `FAILED`), deterministic counts injected into synthesis prompts and claim
   verification, budget exhaustion never reports "completed".
4. **Claim grounding**: deterministic full-dataset count corroboration
   (true counts accepted beyond the bundle sample; contradicted counts
   rejected with the query result in the reason), causal-support gap
   (temporal proximity insufficient; negations safe), HYPOTHESIS claim
   class, stronger exploitation/malware/exfiltration corroboration
   requirements.
5. **GUI**: `IngestionWorker` (background parse+index with progress; the
   window stays responsive), analysis-worker record conversion moved off the
   GUI thread, AI session conversation context.
6. **`training/` package**: dataset validation (all 7 hashes verified),
   benchmark runner (ground-truth isolation), evaluator (metrics with
   explicit denominators), question generator, leakage-safe fine-tune export
   (split by scenario group).
7. **`tests/` suite**: 83 tests covering counts, empty results, unknown
   fields, AND/OR/NOT, timestamps, duplicates, custom fields, paraphrases,
   timelines, fabricated citations, unsupported claims, contradictions,
   prompt injection as data, provider timeouts, malformed model responses,
   coverage accounting, and full-benchmark integration.
8. **Packaging**: PyInstaller spec + Inno Setup script + build script →
   `packaging/Output/LogAsis-Setup-0.9.7.exe` (verified launching).

---

## 3. Before-and-after evaluation

### Before (measured pre-fix behavior)
- `parser_edge_cases.jsonl` (5 events): **unloadable** through the normal
  pipeline (crash in `events_to_dataframe`).
- `filter_and(no-match-ip, failed_login)` on the authentication file:
  **854 rows returned instead of 0**.
- AND query with `limit=5`: **count reported as 5 instead of 45**.
- Bare-condition plan: **2,500 of 2,500 rows matched** instead of 45.
- Exact-count questions were answered by LLM estimation over a bounded
  sample (≤64 of 2,500 events) — no deterministic result existed to measure;
  this is the structural cause of the wrong counts.
- No benchmark harness, no test suite, no training package existed despite
  the documentation referencing them.

### After (measured post-fix, full benchmark run)
Runner: `python -m training.benchmark` + `python -m training.evaluate`
(18/18 questions, 0 errors, deterministic mode — the mode the release gates
define for factual questions):

| Metric | Result | Gate |
|---|---|---|
| exact_count_accuracy | **1.000** (11/11) | ≥ 0.99 — **PASS** |
| qa_accuracy | **1.000** (18/18) | — |
| citation_validity | **1.000** | = 1.0 — **PASS** |
| unsupported_claim_rate | **0.000** | — |
| abstention_correct_rate | **1.000** (6/6) | 0 unsupported assertions — **PASS** |
| evidence_recall (min / mean) | **1.000 / 1.000** | ≥ 0.90 — **PASS** |
| evidence_precision (mean) | 0.711 | informational (abstentions observe whole reference sets) |
| median / p95 latency | 0.026 s / 0.049 s | — |
| provider errors | 0 | — |

All four release gates **PASS**. Machine-readable outputs:
`benchmarks/prepared_dataset.json`, `benchmarks/predictions.json`,
`benchmarks/results.json`, `benchmarks/generated_questions.jsonl`
(17 generated regression questions), `training_exports/` (train/validation/
test split by scenario group, zero leakage groups).

### Test suite
`python -m pytest tests/ -q` → **83 passed** (includes full-corpus
integration tests; skipped automatically if the corpus is absent).

### Packaging
- Portable bundle: `dist\LogAsis\LogAsis.exe` (25.2 MB) — verified to launch.
- Setup exe: `packaging\Output\LogAsis-Setup-0.9.7.exe` (100.7 MB).

---

## 4. Modified files

| File | Purpose of change |
|---|---|
| `core/event_index.py` | fail-closed intersect; UTC-normalized timestamp parsing |
| `core/query_engine.py` | count/limit separation; fail-closed plan validation; leaf-condition compilation; time-range bounds; validation errors |
| `core/analytics.py` | crash fixes for malformed/mixed timestamps; parse-failure flags |
| `core/log_dataset.py` | datetime-safe record serialization (`safe_frame_records`); public helper |
| `core/question_understanding.py` | NEW: deterministic question analysis |
| `core/deterministic_qa.py` | NEW: deterministic QA engine with coverage + claims |
| `core/timeline_engine.py` | None-vs-datetime sort crash fix |
| `core/claim_verification.py` | evidence-based claim classification (replaces "is"/"was" keyword logic) |
| `ai/agent.py` | deterministic QA integration; deterministic report renderer; conversation context; provider-optional path |
| `ai/investigation_agent.py` | `count_events` tool; coverage accounting; completion status; deterministic counts in synthesis |
| `ai/claim_grounding.py` | deterministic count corroboration; causal guard; HYPOTHESIS class; stronger corroboration for exploitation/malware/exfiltration |
| `gui/main_window.py` | async ingestion worker (fixes "Not responding"); safe record conversion on workers; AI conversation context |
| `training/*` | NEW: prepare / benchmark / evaluate / generate_questions / finetune_export |
| `tests/*` | NEW: 83-test regression suite |
| `packaging/*` | NEW: PyInstaller spec, Inno Setup script, build script |
| `docs/AUDIT_2026-10-17.md` | NEW: Phase 1 audit with reproductions |
| `docs/EVALUATION.md` | rewritten for the real training/ + tests/ tooling |
| `docs/AI_INVESTIGATION.md` | updated architecture, coverage semantics, completion status |

Existing application behavior (GUI workflows, providers, cases, evidence
stores, dashboards) is preserved; all changes are additive around the same
LogDataset/EventIndex/QueryEngine architecture.

---

## 5. Known limitations (honest disclosure)

1. **Benchmark questions run through the deterministic factual path.** The
   AI provider path (agentic planner + synthesis) is exercised by unit tests
   with scripted providers; scored LLM runs require a configured Live AI key
   and were not executed in this environment (no credentials available). The
   deterministic layer removes the counting hallucination class entirely;
   provider-side synthesis quality for analytical questions is unchanged
   except for injected deterministic counts and grounding.
2. **Question understanding uses standard vocabulary** (security-log phrase
   tables, IANA service ports, light stemming). Novel phrasings that match
   nothing fall back to the AI investigation runtime rather than guessing.
3. **Syslog missing-year repair** uses the current year (pre-existing
   behavior, retained for compatibility; documented as a limitation).
4. **`get_provider("NVIDIA NIM"/"Google Gemini")`** remains restricted to
   "Live AI" + "openai" (pre-existing; the GUI only offers Live AI).
5. **Evidence precision on abstention questions** is low by construction:
   refusal scaffolds observe whole referenced entity sets. Recall and
   validity are the gated metrics there.
6. **Frozen-app runtime data** is written next to the executable when
   writable, else under `%LOCALAPPDATA%\LogAsis` (pre-existing fallback).

## 6. Blocked items

- Scored LLM benchmark runs (need a configured Live AI provider/API key).
- Manual click-through verification of the packaged GUI on a physical
  display (headless sandbox cannot instantiate the window; the portable exe
  was verified to launch and write its diagnostics log).
