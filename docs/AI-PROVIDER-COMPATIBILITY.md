# AI Provider Compatibility

The current LogAsis AI Analyst uses one provider-independent investigation
runtime. Live providers share the same investigation state, read-only tools,
evidence model, grounding, and report model.

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
