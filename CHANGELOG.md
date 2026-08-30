# Changelog

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
