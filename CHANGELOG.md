# Changelog

## 0.9.7 — Stable AI answers across installs and runs

- Diagnosed why the installed app and `LogAsis.py` could answer the same
  question differently: retrieval, tools, evidence catalog, prompts, and
  greedy decoding are identical in both (verified byte-identical across
  processes and hash seeds), but the hosted model still sampled a different
  completion per request, which sent the planner down different searches.
- Persisted the AI answer memo to `%APPDATA%\LogAsis\ai_analysis_cache.json`:
  the same question over the same log with the same provider and model now
  returns the identical grounded answer in the setup build and in source
  runs. Entries are keyed by content hash and code version, version-gated,
  capped, and corruption-tolerant; `LOGASIS_AI_CACHE=0` (or deleting the
  file) forces fresh provider calls.
- Pinned a fixed OpenAI `seed` on greedy NVIDIA analyst calls to reduce
  first-run variation, with automatic seedless retry if an endpoint rejects
  the seed field.
- Bumped the AI session cache identity so pre-0.9.7 answers are not reused.

## 0.9.6 — Index-backed investigation runtime for logs of any size

- Routed AI investigation by provider capability instead of log size: providers
  with `supports_agentic_investigation` (Live AI, NVIDIA NIM) now use the
  shared agentic investigation runtime for logs of every size, so a large log
  no longer degrades to a single 160-event sample with no tool iteration.
- Providers without that capability keep the bounded single-shot large-log
  path (documented in `AI-PROVIDER-COMPATIBILITY.md`).
- Made tool truncation visible: `search_events` and `entity_context` report
  `total_matches`, truncation is recorded in investigation observations and
  `actions_taken`, and the planner is told when its result limit hid matches.
- Added planner finish guidance so an investigation does not stop while its
  own rationale still proposes a runnable search or lookup.
- Wired index-backed retrieval through the AI path: evidence seeding, the
  EVID-xxx catalog, the read-only investigation tools, and the RAG index are
  built once per uploaded log (`LogDataset`) and reused by every question,
  with behavioral parity to the original scanning scorer verified by tests.
- Replaced the training/dataset placeholders with working implementations:
  deterministic question generation from the event index, real evaluation
  metrics (no fabricated zeros), dataset preparation/validation with tamper
  checks, retrieval benchmarking, and CLI entry points.
- Fixed a GUI regression where the AI worker was only constructed when a
  filter was active, which raised `AttributeError` on the first AI question.
- Bumped the AI session cache identity so assessments generated before these
  routing and truncation changes are not reused.

## 0.9.5 — Human-readable AI output + LogAsis application icon

- Fixed large-log AI synthesis bypassing the grounding renderer and exposing
  provider JSON directly in the Analyst Assessment view.
- Updated all AI response paths to pass provider output through the common
  evidence-grounding and human-readable rendering pipeline.
- Removed the contradictory final-response instruction that asked providers to
  return JSON after instructing them not to expose JSON.
- Bumped the AI session cache identity so previously cached JSON responses are
  not reused after the presentation fix.
- Added a Windows `.ico` application icon generated from the text-free LogAsis
  mark and made both the application and main window prefer it over SVG.
- Added a Windows AppUserModelID so source launches can use the LogAsis taskbar
  identity instead of the generic Python application identity.
- No new runtime dependency is required for the icon or AI output fix.

## 0.9.4 — AI grounding repair + provider model guard

- Added one bounded AI grounding-repair pass when a non-empty provider answer
  omits usable evidence citations or all proposed claims fail grounding.
- Repair remains provider-generated and uses only deterministic investigation
  evidence; Python does not fabricate a forensic answer.
- Fixed Recommendation-labeled provider prose being incorrectly rendered as a
  verified fact.
- Bumped the AI session cache identity for the 0.9.4 grounding changes.
- Added a guard preventing NVIDIA NIM content-safety/moderation models from
  being selected for the forensic analyst role.

## 0.9.3 — Dynamic Log RAG + AI Investigation

- Removed the retired deterministic forensic answer engine from the production
  AI Analyst path.
- Added hybrid BM25 + TF-IDF retrieval and logical log chunking.
- Preserved arbitrary source fields and stable evidence IDs.
- Added safe citation recovery for compact provider responses.
- Rejected provider claims are not printed verbatim as forensic facts.
- Consolidated the production AI Analyst around a provider-directed
  investigation runtime.

## 0.9.2 — RAG/AI Analyst regression fixes

- Preserved provider wording/provenance compatibility for fact-question
  responses without allowing provider prose to override deterministic evidence.
- Preserved tool-oriented enumeration wording and the v0.9.1 dynamic RAG
  architecture.

## 0.9.1 — RAG / AI Analyst regression fixes

- Added source-file identity to AI analysis cache keys.
- Improved direct fact-question retrieval.
- Improved PowerShell download and destination-port evidence retrieval.
- Improved dynamic source-field exposure and grounding diagnostics.
- Preserved the provider-independent RAG architecture.

## 0.9.0 — AI-only investigation + dynamic RAG

- Removed the question-specific deterministic forensic answer layer from the
  AI Analyst path.
- Introduced provider-independent dynamic RAG and read-only investigation tools.
- Preserved arbitrary parsed source fields.
- Made evidence retrieval deterministic and auditable while leaving
  investigation planning and interpretation to the selected AI provider.
- Empty provider output is not converted into a fabricated forensic answer.

Earlier development releases are intentionally omitted from the public
release history to keep the repository focused on the current production
architecture.
