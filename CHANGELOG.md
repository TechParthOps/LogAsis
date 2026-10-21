# Changelog

## 0.10.0 — Multi-format log support and dynamic suggested questions

- **Any log type now gets correct answers.** The deterministic incident
  profiler is format-aware: the same intrusion grammar (authentication
  anomalies → attacker session → tooling → escalation → sensitive access) is
  recognized on Linux auditd/syslog evidence (sudo/sudoedit, /etc/shadow)
  AND on Windows evidence — 4625/4624/4648/4776 logon events (EVTX-to-JSON
  and Sysmon exports), encoded/hidden PowerShell, credential dumpers
  (mimikatz-style), LSASS access (Sysmon EventID 10) and dump/hive staging
  (EventID 11), certutil/bitsadmin/Invoke-WebRequest downloads, remote-exec
  tooling (psexec/wmic/winrs), persistence via scheduled tasks/registry run
  keys, account manipulation, and anti-forensics (shadow-copy deletion,
  event-log clearing).
- **Windows event-ID normalization**: the JSON parser now maps Windows
  Security event IDs to actions (4625 → failed_login, 4624/4648/4776 →
  successful_login, 4688/Sysmon 1 → process_create), so Windows brute-force
  and logon sequences are detected without any status text.
- **Dynamic suggested questions**: the AI Analyst's suggested-question
  buttons are now derived from the LOADED log (log type, available fields,
  incident profile) instead of a fixed auditd-oriented list. Windows/Sysmon
  logs get suspicious-process/credential-access/artifact questions; SSH/auth
  logs keep the compromise/CVE/root questions; web logs get error/route
  questions; firewall and DNS logs get traffic questions. The grid refreshes
  automatically on every log load.
- Suspicious-content-only captures (pure Sysmon, no authentication events)
  now produce deterministic summaries and suspicious-execution answers
  instead of falling through unanswered.
- Question understanding fixed: "What files did the attacker access?"
  no longer mis-routes to the attacker-IP conclusion; bare "attacker"
  mentions are treated as context when the question asks for a different
  value kind.
- 121 tests pass (26 incident-profile tests now cover Windows, Sysmon-only,
  and web-log suggestions).

## 0.9.9 — Deterministic incident profiler, correct incident answers

- New **deterministic incident profiler** (`core/incident_profile.py`): from
  any loaded log it derives the evidence-backed intrusion facts with no model
  involvement — compromised account and attacker source from the
  failed-then-successful login signature (ordered by row position, since
  real auditd captures are frequently timestamped within the same second),
  the attacker session scope, escalation executions, the resulting root
  shell, downloaded tooling/payloads, and root sensitive-file reads.
- The AI Analyst's deterministic layer now answers the incident questions
  **correctly on a real 83k-row auditd capture** (SSH brute force → linpeas
  → sudoedit exploit → root shell → /etc/shadow): "Which account was
  compromised?" names the brute-forced account with counts, "What
  attack type...?" reports brute force, "What is the attacker's IP?" names
  the source, "What file was exfiltrated once root was gained?" reports the
  root read of /etc/shadow, "What is the binary and PID used to gain
  root?" reports the sudoedit exploit execution and the uid=0 payload shell,
  "What tool was used to perform system enumeration?" identifies linpeas
  from the attacker-controlled URL, and "Summarize highest-risk findings" /
  "Explain critical activity" produce a deterministic numbered summary with
  an evidence chain.
- **Execution-based exploit signatures**: CVE mapping (CVE-2021-3156
  "Baron Samedit", CVE-2021-4034 PwnKit, CVE-2022-0847 Dirty Pipe) fires
  only when the exploit utility is actually executed. Enumeration-scanner
  privilege-boundary checks (`sudo -l`, `sudo -V`, `sudo -S -l`,
  `pkexec --version`) are flagged as checks and never presented as
  escalation or exploit evidence.
- Privilege-goal phrasing fixed: "gain root" / "root access" / "root was
  gained" no longer resolve as a `username=root` filter that silently
  narrowed answers to root's own records.
- The agentic AI investigation runtime is seeded with the incident profile
  facts and their evidence rows, so Live AI answers start from the same
  verified forensic context instead of re-deriving (or hallucinating) it.
- 112 tests pass (17 new incident-profile regression tests).

## 0.9.8.2 — Evidence-backed direct answers, provider failure resilience

- Conclusion questions now compute the **actual best-supported answer from
  the log** instead of a generic refusal: "Which account was compromised?"
  identifies the account with the failed-then-successful login sequence
  (with counts and source IPs), "What is the attacker's IP?" names the
  source with that signature, "What attack type was used to gain initial
  access?" reports the observed pattern (brute-force interpretation with its
  counts), and "What file was exfiltrated...?" lists the files/URLs that
  actually appear in transfer commands. Security labels stay qualified
  (evidence-backed interpretation, not asserted as proven).
- "What tool was used to..." questions now extract executed command tokens
  ranked by frequency instead of listing every daemon process.
- Evidence chains now point at the events that matter (the login-sequence
  and transfer-command records) rather than the first rows of the dataset,
  and whole-dataset identity dumps are capped.
- Fixed "AI ANALYSIS FAILED — no analyst text (finish_reason=length)":
  when a reasoning-style model exhausts the completion budget with hidden
  reasoning, the request is retried with a larger budget (up to 8192) before
  failing, and each planner step retries once with the normal budget.
- Verified end-to-end against a realistic auditd-style scenario (brute-force
  SSH then success then root commands): all five suggested questions produce
  distinct, evidence-backed answers. 95 tests pass; all benchmark release
  gates hold.

## 0.9.8.1 — Direct answers, per-question specificity, responsive UI, live model catalog

- AI Analyst now gives a **DIRECT ANSWER** first. When the actual answer is
  found in the loaded log (a count, an identified binary/PID/CVE/file/user,
  or a verified zero), the answer is short and no evidence listing is shown.
  An **EVIDENCE CHAIN** section appears only when no direct answer is
  available (abstentions, verified zeros, ambiguity); full grounding stays in
  the collapsible grounding panel.
- "What/which" questions are now answered as **extractions**, not generic
  event counts: "What CVE was exploited to gain root access?" reports the CVE
  identifiers present (or states none are recorded), "What is the binary and
  PID used to gain root?" reports observed process names and PIDs, and
  conclusion-shaped questions ("which account was compromised?", "what is
  the attacker's IP?") receive qualified direct answers that report what the
  log actually shows without asserting unproven security labels. Different
  questions no longer return the same generic answer.
- Remaining "Not responding" freezes fixed for large logs (100k+ events):
  investigation/operations/dashboard refreshes no longer run IOC extraction,
  detection engines, or report builders on the GUI thread (results come from
  the background analysis worker), and the Analyze button no longer copies
  the whole DataFrame on the GUI thread.
- AI analysis is faster: investigation budget reduced to 3 planning steps /
  6 tool calls, planner round-trips use a compact context and a bounded
  completion budget, a deterministic head start records authoritative counts
  before any planner call (often removing tool calls entirely), and the
  evidence catalog is warmed during upload in the background.
- Model selection is now fully dynamic: the config dialog fetches the
  provider's live model catalog on a background thread, shows only currently
  offered chat models (embeddings/rerankers/safety models filtered out), and
  automatically drops models the provider has removed — with a clear notice
  and a same-family replacement when a saved model was retired.
- Release gates re-verified after the changes: exact-count accuracy 1.0,
  citation validity 1.0, zero unsupported abstention assertions, evidence
  recall 1.0; test suite grown to 94 tests, all passing.

## 0.9.8 — Deterministic factual accuracy, evidence grounding hardening, benchmark tooling

- Added a deterministic factual answer layer (`core/question_understanding.py`,
  `core/deterministic_qa.py`): arbitrary count/list/timeline questions are
  answered by validated indexed queries over the complete dataset — no
  provider call and no model arithmetic. Prove/cause questions receive
  abstention scaffolds that refuse unsupported compromise, exfiltration,
  exploitation, and causation conclusions.
- Fixed `EventIndex.intersect` returning ALL rows when every condition set
  was empty (AND queries with one non-matching filter counted the wrong
  population).
- Fixed `QueryEngine` counts being corrupted by result limits (`count` now
  always reports the complete matching set; `returned_count`/`truncated`
  describe the bounded sample).
- Query plans now fail closed: unknown fields, unsupported operators, and
  bare field/value mappings no longer silently widen into "match everything".
- Timestamp handling hardened: malformed/mixed-format timestamps no longer
  crash ingestion; parse failures are flagged per record; timestamps
  normalize to UTC for sort/comparison safety.
- Investigation runtime gained a deterministic `count_events` tool, coverage
  accounting (`total_events` … `completion_reason`), and explicit completion
  status (`COMPLETED_SUFFICIENT`, `COMPLETED_INSUFFICIENT`, `PARTIAL`,
  `FAILED`); exhausting the tool budget is never reported as "completed".
- Claim grounding now verifies set-level counts against deterministic
  full-dataset query results (true counts beyond the evidence-bundle sample
  are accepted; contradicted counts are rejected), adds a causal-support gap
  (temporal proximity alone is insufficient), and adds a distinct HYPOTHESIS
  claim class.
- Rewrote `core/claim_verification.py` classification: claims are verified
  against actual record content instead of certainty keywords such as "is".
- Uploads now parse and index on a background thread (`IngestionWorker`);
  the window no longer shows "Not responding" while loading large logs.
- AI Analyst session context resolves contextual references ("this source")
  from earlier questions in the same session.
- Added the `training/` package (prepare / benchmark / evaluate /
  generate_questions / finetune_export) and an 83-test regression suite
  (`tests/`); all four release gates pass on the synthetic benchmark
  (exact-count accuracy 1.0, citation validity 1.0, zero unsupported
  abstention assertions, evidence recall 1.0). See
  `docs/ACCURACY_IMPROVEMENTS.md`.
- Added Windows packaging: PyInstaller spec + Inno Setup script
  (`packaging/build_setup_exe.ps1`) producing the LogAsis setup exe.

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
