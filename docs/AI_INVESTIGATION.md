# LogAsis AI Investigation Architecture

## Overview

The AI analyst uses the **same** indexed Log Intelligence Engine as the UI. There is no separate AI scanning engine. Both use:

- LogDataset
- EventIndex
- QueryEngine
- AggregationEngine
- EvidenceStore
- CorrelationEngine

## Persistent session wiring

One uploaded log creates one `LogDataset`. The GUI passes it into every AI
question (`AIWorker` -> `LogInvestigatorAgent.answer(..., dataset=...)` ->
`AgenticInvestigationRuntime.run(..., dataset=...)`), which gives the
investigation three shared, build-once resources:

- `dataset.event_index` — evidence seeding and the read-only tools resolve
  candidates from the index instead of scanning the DataFrame per question.
- `dataset.get_tool_catalog()` — the EVID-xxx evidence-ID catalog is built
  once per dataset and reused for every question.
- `dataset.get_rag_index()` / `build_rag_context(..., index=...)` — the RAG
  index is built once per dataset; passing a shared index prevents
  per-question rebuilds.

Index-backed retrieval is verified for behavioral parity with the original
scanning scorer by tests (`TestIndexBackedRetrieval`,
`TestInvestigationToolLayerIndex` in `tests/test_ai.py`): same evidence IDs,
same ordering, same scoring rules — only the execution strategy changed.

If the shared index does not cover the same rows as the frame presented to
the AI (for example after an unexpected mutation), the code falls back to the
scanning path so evidence coverage is never reduced for speed.

## Investigation Pipeline

```
QUESTION
    |
    v
Question Understanding (deterministic)
    |
    v
Evidence Requirements
    |
    v
Query Plan (LLM or deterministic)
    |
    v
Query Engine (deterministic)
    |
    v
Evidence (from index)
    |
    v
Correlation (deterministic)
    |
    v
Verification (deterministic)
    |
    +---- insufficient evidence ----> PLAN AGAIN
    |
    v
LLM Synthesis
    |
    v
Claim Verification
    |
    v
Final Answer
```

## Fast Path vs Deep Path

### Fast Factual Path
For questions answerable with one or a few indexed operations:

```
Question -> Query -> Deterministic Result -> Verification -> Concise Answer
```

Example: "How many failed logins came from 10.0.0.5?"
- No LLM call needed for counting
- Deterministic result displayed immediately

### Deep Investigation Path
For questions involving why, how, attack chain, root cause, relationships:

```
 Planner -> Multiple Indexed Queries -> Correlation -> Timeline -> Evidence Verification -> LLM Synthesis
```

Providers with `supports_agentic_investigation` take this path for logs of any
size — index-backed tools keep the planner's queries off the full DataFrame,
so a large log does not reduce the answer to a bounded evidence sample.
Providers without that capability fall back to a bounded single-shot
evaluation for logs over 100 rows; see `AI-PROVIDER-COMPATIBILITY.md`.
Tool results that hit their result limit report `total_matches`, so the
planner and the answer's coverage accounting can see truncation instead of
mistaking a partial result for the full match set.

## Query Planning

The LLM may produce a JSON query plan:

```json
{
  "operation": "AND",
  "conditions": [
    {"field": "source_ip", "operator": "EXACT", "value": "10.0.0.5"},
    {"field": "action", "operator": "EXACT", "value": "successful_login"}
  ]
}
```

This is validated deterministically and compiled into index operations. The LLM never generates executable code.

## Claim Verification

Every final answer is decomposed into claims:

- **VERIFIED_FACT**: Directly supported by evidence
- **GROUNDED_INTERPRETATION**: Qualified inference from evidence
- **HYPOTHESIS**: Tentative explanation requiring more evidence
- **UNSUPPORTED**: No evidence found

Only VERIFIED_FACT and appropriately qualified GROUNDED_INTERPRETATION appear in the final answer.

## Anti-Hallucination Rules

- `successful_login` does NOT become `account compromised`
- `file read` does NOT become `file exfiltrated`
- `CVE-XXXX-XXXX appears` does NOT become `CVE was exploited`
- `sudo` does NOT become `privilege escalation attack`
- `suspicious command` does NOT become `malware`

## Coverage Accounting

Every answer tracks:
- total_events
- indexed_events
- query candidate_events
- retrieved_events
- correlated_events
- verified evidence
- excluded events
- coverage_status: COMPLETE, TARGETED, PARTIAL, UNKNOWN

## Provider Failure Handling

If the AI provider fails:
- Deterministic queries continue working
- No infinite retries on rate limits
- Malformed output: repair or retry once within strict budget
- Provider unavailable: return deterministic evidence with message "AI synthesis unavailable; deterministic evidence analysis completed."
