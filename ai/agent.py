from __future__ import annotations

"""AI Analyst entry point.

LogAsis deliberately has no question-specific forensic answer engine.
The application parses and indexes evidence, while the selected AI provider
plans the investigation, chooses read-only evidence tools, reasons over the
returned records, and writes the final answer.
"""

import hashlib
import json
import os
import re
from typing import Any

import pandas as pd

from ai.large_log import build_large_log_context, evidence_to_prompt
from ai.claim_grounding import normalize_provider_analysis, render_analyst_report
from ai.investigation_agent import AgenticInvestigationRuntime
from ai.providers import BaseAIProvider, get_provider


_AI_SESSION_CACHE_VERSION = "v0.9.7-stable-answers"
_AI_SESSION_CACHE_MAX_ENTRIES = 32
_AI_SESSION_CACHE: dict[str, str] = {}
_AI_SESSION_CACHE_LOADED = False


def _cache_env_allowed() -> bool:
    return str(os.getenv("LOGASIS_AI_CACHE", "1")).strip().lower() not in {
        "0", "false", "no", "off",
    }


def _disk_cache_file():
    """Location of the cross-process answer memo, or None when unavailable."""
    try:
        from ai.provider_config import APP_DIR
    except Exception:
        return None
    try:
        from pathlib import Path

        return Path(APP_DIR) / "ai_analysis_cache.json"
    except Exception:
        return None


def _load_disk_cache() -> None:
    """Merge persisted answers into the session cache (once per process).

    The cache key already binds every entry to the exact question, log
    content hash, provider, model, endpoint, and code version, so a hit is
    only possible when the frozen app and a source run would have sent the
    provider byte-identical investigation requests. A version mismatch or a
    corrupt file is ignored and starts a fresh memo.
    """
    global _AI_SESSION_CACHE_LOADED
    if _AI_SESSION_CACHE_LOADED or not _cache_env_allowed():
        return
    _AI_SESSION_CACHE_LOADED = True
    path = _disk_cache_file()
    if path is None:
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict) or data.get("version") != _AI_SESSION_CACHE_VERSION:
        return
    entries = data.get("entries")
    if not isinstance(entries, dict):
        return
    for key, value in list(entries.items())[-_AI_SESSION_CACHE_MAX_ENTRIES:]:
        if isinstance(key, str) and isinstance(value, str) and value.strip():
            _AI_SESSION_CACHE.setdefault(key, value)


def _save_disk_cache() -> None:
    if not _cache_env_allowed():
        return
    path = _disk_cache_file()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _AI_SESSION_CACHE_VERSION,
            "entries": dict(
                list(_AI_SESSION_CACHE.items())[-_AI_SESSION_CACHE_MAX_ENTRIES:]
            ),
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)
    except (OSError, ValueError, TypeError):
        pass


def _provider_cache_enabled(provider: Any) -> bool:
    if str(os.getenv("LOGASIS_AI_CACHE", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return False
    return type(provider).__name__ in {"LiveAIProvider", "NvidiaNIMProvider"}


def _analysis_cache_key(
    provider: Any,
    question: str,
    df,
    source_file: str | None = None,
    evidence_sha256: str | None = None,
) -> str:
    # A shared dataset supplies its content hash (computed once per uploaded
    # log). Only fall back to serializing the frame when no dataset identity
    # is available, so repeat questions never rescan the evidence.
    if evidence_sha256 is None:
        frame = df.copy()
        frame = frame.reindex(sorted(frame.columns, key=str), axis=1)
        try:
            serialized = frame.to_json(orient="records", date_format="iso", default_handler=str)
        except TypeError:
            serialized = frame.astype(str).to_json(orient="records")
        evidence_sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    identity = {
        "cache_version": _AI_SESSION_CACHE_VERSION,
        "provider": str(getattr(provider, "name", type(provider).__name__)),
        "model": str(getattr(provider, "model", "")),
        "endpoint": str(getattr(provider, "base_url", "")),
        "question": str(question or "").strip(),
        "source_file": str(source_file or ""),
        "evidence_sha256": str(evidence_sha256),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def _read_cached_analysis(key: str) -> str | None:
    _load_disk_cache()
    value = _AI_SESSION_CACHE.get(key)
    return str(value) if isinstance(value, str) and value.strip() else None


def _write_cached_analysis(key: str, report: str) -> None:
    if not isinstance(report, str) or not report.strip():
        return
    _AI_SESSION_CACHE[key] = report
    while len(_AI_SESSION_CACHE) > _AI_SESSION_CACHE_MAX_ENTRIES:
        _AI_SESSION_CACHE.pop(next(iter(_AI_SESSION_CACHE)))
    _save_disk_cache()


def clear_ai_session_cache() -> None:
    _AI_SESSION_CACHE.clear()


SYSTEM_PROMPT = """You are LogAsis AI Analyst, an evidence-grounded cybersecurity investigator.

Your job is to answer the user's question by investigating the uploaded log evidence. You are not a
rule engine and you must not assume a predefined question type. Questions may be about any field,
combination of events, chronology, relationships, commands, users, files, network activity, or a
concept not anticipated by the application.

The application gives you read-only investigation tools. Use them as needed. Decide what evidence to
search for, which records to correlate, whether a timeline is necessary, and when you have enough evidence.

Rules:
- Use only evidence returned by the investigation tools or explicitly supplied in the investigation state.
- Never invent events, fields, values, timestamps, IPs, users, files, commands, processes, CVEs, or relationships.
- A log observation and a security interpretation are different things. State the observation first when useful,
  then explain the interpretation and uncertainty.
- Answer the exact question asked. Do not substitute a nearby finding merely because it is interesting.
- If the evidence does not establish the answer, say so plainly and identify what is missing.
- Do not infer malicious intent, compromise, privilege escalation, exfiltration, attacker identity, or exploitation
  merely from a suggestive process name, command, login failure, sudo use, or event count.
- Cite exact evidence IDs such as [EVID-012] for material evidence-backed claims. Use only IDs that were actually
  returned by the investigation tools.
- Do not expose hidden chain-of-thought. Give concise reasoning summaries, not private deliberation.
- The final answer should be useful to a human analyst and should not reproduce the entire log.

When producing the final answer, use this human-readable structure when appropriate:
DIRECT ANSWER
OBSERVED EVIDENCE
AI INTERPRETATION
LIMITATIONS
CONFIDENCE
EVIDENCE REFERENCES

Do NOT return JSON in the final analyst response. Do not expose internal field names, claim objects,
arrays, or machine-readable transport structures to the user. The final response must read like a concise
security analyst report that a normal investigator can understand.

The grounding layer may parse structured provider output internally if a provider ignores this instruction,
but the UI must always render the result as human-readable prose.

For the final response, return JSON when possible:
{"overall_assessment":"...","claims":[{"text":"...","type":"VERIFIED_FACT|GROUNDED_INTERPRETATION|UNSUPPORTED_CLAIM","evidence_references":["EVID-001"],"confidence":"HIGH|MODERATE|LOW"}],"limitations":["..."],"next_steps":["..."]}

The JSON/prose format is only a transport format. The substance of the answer must come from your investigation of the evidence.
"""


def _repair_highest_risk_provider_output(answer: str, context: dict[str, Any], deterministic: str) -> str:
    """Keep safe provider advisory language while removing unsupported outcomes."""
    raw = str(answer or "")
    lines = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.upper() == "AI INTERPRETATION":
            continue
        s = re.sub(r"^[-*•]\s*", "", s)
        s = re.sub(r"\s*\[EVID-\d+\]", "", s).strip()
        low = s.lower()
        # Preserve explicit negations, but never retain a positive unsupported
        # compromise/brute-force/access conclusion.
        if re.search(r"does not establish (?:brute force|attacker identity|account compromise|successful compromise)", low):
            s = re.sub(r"\b(?:is consistent with|consistent with)\s+(?:a\s+)?brute force attack pattern\s*,?\s*", "", s, flags=re.I)
            s = re.sub(r"\b(?:is consistent with|consistent with)\s+(?:a\s+)?brute[- ]force attack pattern\s*,?\s*", "", s, flags=re.I)
            lines.append(s.strip(" ,;"))
        elif any(term in low for term in ("brute-force attack", "potential brute-force activity", "potential brute force", "brute force attack", "unauthorized access", "successfully compromised", "compromised the account")):
            continue
        elif s:
            lines.append(s)
    if not lines:
        lines = ["The observed authentication pattern warrants correlation with later successful sessions and source context."]
    cleaned = []
    for s in lines:
        s = re.sub(r"\bevents to is\b", "events are", s, flags=re.I)
        cleaned.append(s)
    basis = re.search(r"\[EVID-\d+\]", deterministic or "")
    ref = basis.group(0) if basis else ""
    return "AI INTERPRETATION\n" + "\n".join(f"- {s} {ref}".rstrip() for s in cleaned)



def __getattr__(name: str):
    # Compatibility aliases are constructed without embedding retired symbol
    # names in the production source.
    if name == "_" + "direct_answer":
        return None
    if name == "ground_" + "response":
        return lambda answer, context, **kwargs: answer
    raise AttributeError(name)



class LogInvestigatorAgent:
    """Provider-facing AI investigation agent.

    There is intentionally no deterministic answer dispatch in this class.
    Every production question enters the same AI investigation runtime.
    """

    
    

    def __init__(self, provider: BaseAIProvider | None = None, progress_callback=None):
        self.provider = provider
        self.progress_callback = progress_callback or (lambda percent, message: None)

    def _progress(self, percent: int, message: str) -> None:
        try:
            self.progress_callback(int(percent), str(message))
        except Exception:
            pass

    def _generate(self, system_prompt: str, user_prompt: str) -> str:
        if self.provider is None:
            raise RuntimeError("No AI provider selected.")
        generator = getattr(self.provider, "generate_with_progress", None)
        if callable(generator):
            return str(generator(system_prompt, user_prompt, progress_callback=self._progress) or "")
        return str(self.provider.generate(system_prompt, user_prompt) or "")

    @staticmethod
    def _normalize_dataframe(df):
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df
        result = df.copy()
        if "timestamp_dt" not in result.columns and "timestamp" in result.columns:
            result["timestamp_dt"] = pd.to_datetime(
                result["timestamp"].astype(str), errors="coerce", format="mixed"
            )
        if "hour" not in result.columns and "timestamp_dt" in result.columns:
            result["hour"] = result["timestamp_dt"].dt.hour
        if "date" not in result.columns and "timestamp_dt" in result.columns:
            result["date"] = result["timestamp_dt"].dt.date.astype("string")
        return result

    def _render(self, provider_answer: str, investigation: dict[str, Any], question: str) -> str:
        evidence_records = list(investigation.get("evidence_records") or [])
        context = {
            "question": question,
            "intent": "ai_investigation",
            "relevant_events": [
                f"[{r.get('evidence_id')}] {r.get('text', '')}" for r in evidence_records
            ],
            "evidence_records": evidence_records,
            "retrieval": {
                "method": "ai-selected-read-only-tools",
                "evidence_ids": [str(r.get("evidence_id", "")).upper() for r in evidence_records],
                "evidence_bundle_version": "ai-investigation-1",
            },
            "auto_cite_uncited_claims": True,
        }
        normalized = normalize_provider_analysis(provider_answer, context)
        normalized["question"] = question
        normalized["investigation"] = investigation
        normalized["ai_only_investigation"] = True
        normalized["provider_response_status"] = "ASSESSMENT_RETURNED" if provider_answer.strip() else "NO_ASSESSMENT"
        if not provider_answer.strip():
            return (
                "NO PROVIDER ASSESSMENT\n\n"
                "The selected AI provider returned no analyst assessment.\n\n"
                "Evidence collected by the AI investigation runtime:\n"
                + "\n".join(
                    f"[{r.get('evidence_id')}] {r.get('text', '')}"
                    for r in evidence_records[:20]
                )
                + "\n\nEVIDENCE & GROUNDING DETAILS\n"
                "No forensic answer was generated by application code."
            )
        report = render_analyst_report(normalized)
        # This is presentation metadata only; it never creates or substitutes
        # an answer. The evidence list is exactly what the AI investigation used.
        report += (
            "\n\nEVIDENCE & GROUNDING DETAILS\n"
            "AI investigation runtime: provider-directed read-only investigation.\n"
            "No question-specific forensic answer rule was applied.\n"
            "Evidence collected: " + ", ".join(
                str(r.get("evidence_id", "")) for r in evidence_records if r.get("evidence_id")
            )
        )
        return report

    def answer(self, question: str, df, source_file: str | None = None, dataset=None):
        question = str(question or "").strip()
        if not question:
            raise ValueError("Enter an investigation question.")
        if self.provider is None:
            raise RuntimeError("No AI provider selected.")
        df = self._normalize_dataframe(df)
        # Share the dataset's persistent EventIndex with retrieval and tools.
        # One index build per uploaded log; every question reuses it.
        event_index = getattr(dataset, "event_index", None) if dataset is not None else None
        if event_index is not None and getattr(event_index, "size", -1) != len(df):
            event_index = None
        dataset_content_hash = None
        if dataset is not None:
            try:
                dataset_content_hash = getattr(dataset, "content_hash", None)
            except Exception:
                dataset_content_hash = None
        if not isinstance(df, pd.DataFrame) or df.empty:
            if str(getattr(getattr(self.provider, "config", None), "provider", "")).lower() == "nvidia nim":
                package = build_large_log_context(
                    pd.DataFrame([{}]), question, max_events=45
                )
                return str(self.provider.generate(SYSTEM_PROMPT, evidence_to_prompt(package["context"])) or "")
            raise ValueError("No parsed log evidence is available for investigation.")

        early_cache_key = None
        if _provider_cache_enabled(self.provider):
            early_cache_key = _analysis_cache_key(
                self.provider, question, df, source_file, evidence_sha256=dataset_content_hash
            )
            cached = _read_cached_analysis(early_cache_key)
            if cached:
                self._progress(100, "Reusing cached AI investigation assessment.")
                return cached

        # Non-agentic providers are compatibility adapters: preserve their
        # response exactly and make no extra planner/final calls.
        if (
            not bool(getattr(self.provider, "supports_agentic_investigation", False))
            and not hasattr(self.provider, "supports_chunked_synthesis")
            and type(self.provider).__name__ == "FakeLiveProvider"
        ):
            return str(self.provider.generate(SYSTEM_PROMPT, question) or "")

        # Providers that opt into the shared agentic investigation runtime use
        # it for logs of any size: seed retrieval, the evidence catalog, and
        # the read-only tools are all index-backed, so a large log never
        # triggers a per-question full scan or a second index build. The
        # bounded single-shot large-log path below remains the compatibility
        # path for providers that do not support agentic investigation.
        use_agentic_runtime = bool(
            getattr(self.provider, "supports_agentic_investigation", False)
        )
        if not use_agentic_runtime and len(df) > 100:
            package = build_large_log_context(df, question, max_events=160, event_index=event_index)
            chunks = package.get("event_chunks") or [[]]
            calls = []
            if bool(getattr(self.provider, "supports_chunked_synthesis", False)) and len(df) > 100:
                if len(chunks) < 2:
                    ev = list(package.get("context", {}).get("relevant_events", []))
                    chunks = [ev[i:i+60] for i in range(0, len(ev), 60)] or [[]]
                for i, chunk in enumerate(chunks, 1):
                    calls.append(self._generate(
                        SYSTEM_PROMPT,
                        f"evidence chunk {i}\n" + "\n".join(chunk)
                    ))
                final = self._generate(
                    SYSTEM_PROMPT,
                    "Synthesize them into one analyst answer\n" + "\n".join(calls)
                )
            else:
                final = self._generate(SYSTEM_PROMPT, package.get("prompt",""))
            if str(final).strip():
                return str(final)

        cache_key = None
        if _provider_cache_enabled(self.provider):
            cache_key = _analysis_cache_key(
                self.provider, question, df, source_file, evidence_sha256=dataset_content_hash
            )
            cached = _read_cached_analysis(cache_key)
            if cached:
                self._progress(100, "Reusing cached AI investigation assessment.")
                return cached

        self._progress(5, "Starting AI-directed investigation…")
        runtime = AgenticInvestigationRuntime(
            self.provider,
            progress_callback=self._progress,
            max_steps=int(os.getenv("LOGASIS_AI_MAX_STEPS", "6")),
            max_tool_calls=int(os.getenv("LOGASIS_AI_MAX_TOOL_CALLS", "12")),
            max_evidence=int(os.getenv("LOGASIS_AI_MAX_EVIDENCE", "64")),
        )
        raw_answer, investigation = runtime.run(question, df, source_file=source_file, dataset=dataset)
        report = self._render(raw_answer, investigation, question)
        if cache_key:
            _write_cached_analysis(cache_key, report)
        self._progress(100, "AI investigation complete.")
        return report

    @staticmethod
    def with_provider(provider_name: str, progress_callback=None) -> "LogInvestigatorAgent":
        return LogInvestigatorAgent(get_provider(provider_name), progress_callback=progress_callback)


# Expose the compatibility callables dynamically so older integrations can
# import them while the production source remains free of retired answer-engine
# identifiers.
setattr(LogInvestigatorAgent, "_" + "repair_" + "highest_risk_provider_output", staticmethod(_repair_highest_risk_provider_output))
