# LogAsis AI Investigation Architecture

## Overview

The AI analyst uses the **same** indexed Log Intelligence Engine as the UI. There is no separate AI scanning engine. Both use:

- LogDataset
- EventIndex
- QueryEngine
- AggregationEngine
- EvidenceStore
- CorrelationEngine
- Question understanding + deterministic QA engine (`core/question_understanding.py`, `core/deterministic_qa.py`)

## Persistent session wiring

One uploaded log creates one `LogDataset`. Uploads parse and index on a
background thread (`IngestionWorker`), so the window never freezes ("Not
responding") during ingestion. The GUI passes the dataset into every AI
question (`AIWorker` -> `LogInvestigatorAgent.answer(..., dataset=...)` ->
`AgenticInvestigationRuntime.run(..., dataset=...)`), which gives the
investigation shared, build-once resources:

- `dataset.event_index` — evidence seeding and the read-only tools resolve
  candidates from the index instead of scanning the DataFrame per question.
- `dataset.get_tool_catalog()` — the EVID-xxx evidence-ID catalog is built
  once per dataset and reused for every question.
- `dataset.get_rag_index()` / `build_rag_context(..., index=...)` — the RAG
  index is built once per dataset; passing a shared index prevents
  per-question rebuilds.

If the shared index does not cover the same rows as the frame presented to
the AI (for example after an unexpected mutation), the code falls back to the
scanning path so evidence coverage is never reduced for speed.

AI questions always analyze the **full loaded log**, never the Events-tab
filtered view. Prior questions in the same session are passed as
conversation context so contextual references ("this source") resolve the
way an analyst would carry context — without ever introducing ground-truth
information.

## Investigation Pipeline

```
UPLOAD
  -> PARSE (IngestionWorker, background thread)
  -> NORMALIZE (events_to_dataframe, UTC dtype, parse-failure flags)
  -> VALIDATE (counts vs manifest, identity mapping, stale-index checks)
  -> INDEX ONCE (EventIndex)
  -> QUESTION (arbitrary natural language)
        |
        v
  QUESTION UNDERSTANDING (deterministic: entities, intent, time, proof/causality)
        |
        +------------------------------------------+
        |                                          |
   factual/abstention                       analytical
        |                                          |
        v                                          v
  VALIDATED QUERY PLAN                    AGENTIC RUNTIME
  (QueryEngine.compile;                   (bounded steps/tools,
   fails closed on                          read-only tools incl.
   unknown fields)                          count_events)
        |                                          |
        v                                          v
  INDEXED EXECUTION                       DETERMINISTIC EVIDENCE
  over the COMPLETE                       + deterministic counts
  matching set                            + correlation/timeline
        |                                          |
        v                                          v
  COVERAGE CHECK  <------------------------+
        |
        v
  CLAIM VERIFICATION (claim_grounding; deterministic count corroboration)
        |
        v
  FINAL VALIDATION (fabricated IDs rejected; counts cross-checked)
        |
        v
  ANSWER + COVERAGE REPORT
```

## Fast Path vs Deep Path

### Deterministic factual path
For count/list/timeline questions and prove/cause (abstention) questions:

```
Question -> understanding -> validated plan -> indexed query over the full
dataset -> exact count / verified zero / refusal scaffold -> claims -> answer
```

- No provider call and no model arithmetic: the number in the answer is the
  query result over the complete matching set.
- A question naming a concrete identifier that exists in no indexed field is
  a **verified zero**, never "all other events".
- Abstention scaffolds report what the evidence shows (per-entity
  observations) and refuse unsupported conclusions (compromise, exfiltration,
  successful exploitation, causation) explicitly.

### Deep agentic path
For questions needing interpretation:

```
Planner -> indexed tools (search/count/timeline/correlate/entity) -> evidence
verification -> LLM synthesis -> claim grounding -> answer
```

- The runtime has a `count_events` tool whose result is **authoritative**:
  exact, exhaustive, never sampled. Deterministic counts are injected into
  the synthesis prompt and into claim verification.
- Providers with `supports_agentic_investigation` use this path for logs of
  any size. Tool results that hit their limit report `total_matches`, so
  truncation is visible to the planner and to coverage accounting.
- Bounded steps/tool calls; the agent can never claim "completed" merely by
  exhausting its budget (see completion status below).

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

This is validated deterministically (`QueryEngine.compile`) and compiled into
index operations. The LLM never generates executable code. Validation fails
closed: unknown fields, unsupported operators, or unparseable time bounds
produce an explicit error result, never a silently widened query. Bare
field/value mappings are compiled as leaf conditions (an earlier defect
compiled them as empty ANDs that matched every row).

## Claim Verification

Every final answer is decomposed into claims:

- **VERIFIED_FACT**: directly supported by actual source records or by a
  deterministic query result
- **GROUNDED_INTERPRETATION**: qualified inference anchored to cited evidence
- **HYPOTHESIS**: plausible explanation explicitly marked as not established
- **RECOMMENDATION**: advisory actions, kept separate from findings
- **INSUFFICIENT_CONTEXT**: observation whose security significance cannot be
  determined from the evidence
- **UNSUPPORTED_CLAIM / CONTRADICTED_CLAIM**: rejected; the reason is shown,
  the claim text is not

Set-level counts are verified against **deterministic full-dataset query
results** when available (the bounded evidence bundle alone cannot
corroborate or refute a dataset-level count). A claim contradicting a
deterministic count is rejected with the query result in the reason.

## Anti-Hallucination Rules

- `failed_login` / `successful_login` do NOT establish account compromise
- `file read` does NOT establish exfiltration
- `CVE appears` does NOT establish exploitation
- `sudo` use does NOT establish privilege escalation
- `suspicious command` does NOT establish malware
- `blocked connection` does NOT establish successful communication
- temporal proximity does NOT establish causation (causal claims require
  shared session/process/correlation linkage evidence)
- absence of matching events does NOT prove the event never occurred outside
  the dataset or logging coverage

## Completion status and coverage accounting

Investigation completion status (semantics):

- `COMPLETED_SUFFICIENT` — finished with sufficient evidence for the objective
- `COMPLETED_INSUFFICIENT` — finished, but the answer must disclose gaps
- `PARTIAL` — stopped at the step/tool budget; findings cover part of the objective
- `FAILED` — provider/parser/query/runtime error

Exhausting the tool-call budget is PARTIAL, never "completed".

Every answer tracks:

- total_events, indexed_events, candidate_events
- total_matching_events, retrieved_events, correlated_events
- verified_evidence, excluded_events
- failed_batches, truncated_results
- coverage_status: COMPLETE (exhaustive over the full dataset for the stated
  filters), TARGETED (scoped question answered exhaustively within its
  scope), PARTIAL, UNKNOWN
- completion_reason

Counts are never labelled exhaustive when they come from a truncated result.

## Provider Failure Handling

If the AI provider fails:
- Deterministic queries and the deterministic factual path continue working
- No infinite retries on rate limits (bounded retry with Retry-After)
- Malformed output: bounded repair pass; a provider response with no usable
  action fails the investigation explicitly (FAILED)
- Provider unavailable: deterministic evidence is still returned; factual
  questions need no provider at all
