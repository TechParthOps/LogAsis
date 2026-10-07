# AI Provider Compatibility

The current LogAsis AI Analyst uses one provider-independent investigation
runtime. Live providers share the same investigation state, read-only tools,
evidence model, grounding, and report model.

## Runtime routing

Providers that opt in via `supports_agentic_investigation` (currently
`LiveAIProvider` and `NvidiaNIMProvider`) use the shared investigation runtime
for logs of every size. Retrieval, the evidence catalog, and the read-only
tools are index-backed, so a large log never triggers a per-question full
scan or a second index build, and the planner can iterate (search, correlate,
inspect timeline) instead of answering from one bounded context.

Providers that do not opt in keep the compatibility path: logs up to 100 rows
also use the shared runtime, and larger logs use a bounded single-shot
evaluation (160 events, chunked synthesis only when the provider advertises
`supports_chunked_synthesis`). That path is intentionally limited — one
provider call over a bounded evidence sample — because such providers cannot
drive tool iteration.

## Answer stability

The installed build and a source run execute identical Python code, and every
deterministic layer (index, seed retrieval, tools, catalog, prompts, greedy
decoding) was verified byte-identical across processes. A hosted model can
still sample a different completion per request, so two processes asking the
same question could receive different wordings and different planner searches.

Two mechanisms keep answers stable:

- **Shared answer memo.** Accepted analyst answers are persisted to
  `%APPDATA%\LogAsis\ai_analysis_cache.json`, keyed by question, log content
  hash, provider, model, endpoint, and code version. The same question over
  the same log with the same model returns the identical grounded answer in
  the setup build and in `LogAsis.py`. Entries are version-gated and capped;
  a corrupt file is ignored. Set `LOGASIS_AI_CACHE=0` or delete the file to
  force fresh provider calls.
- **Pinned NIM seed.** Greedy NVIDIA analyst calls (`temperature=0.0`) also
  send a fixed OpenAI `seed`, which is as reproducible as the hosted model
  allows. Endpoints that reject the seed field automatically fall back to a
  seedless request.

Identical inputs therefore produce identical answers; only a first-time
question (or a changed log, model, or code version) reaches the provider, and
even then greedy decoding plus the fixed seed minimize variation.

## NVIDIA NIM

`NvidiaNIMProvider` uses the same OpenAI-compatible request path as the other
live providers. Model discovery is performed against the configured provider
catalog.

NVIDIA content-safety/classification models are rejected for the forensic
analyst role because they are specialized classifiers rather than general
investigation/chat models.

The provider layer keeps requests bounded so evidence, instructions, and the
model completion remain within the available context window.

## Credentials

API credentials are stored through the application's local secure credential
mechanism. Credentials and API keys must never be committed to Git.

## Provider failures

Provider failures are reported as provider failures. LogAsis does not silently
replace a failed live-AI response with a question-specific Python forensic
answer.

## Human-readable output

Provider responses may use structured data internally, but the analyst UI
renders validated results as human-readable security-analysis text. Raw
provider JSON is not the intended user-facing format.
