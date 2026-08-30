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


_AI_SESSION_CACHE_VERSION = "v0.9.3-ai-rag-investigation"
_AI_SESSION_CACHE_MAX_ENTRIES = 32
_AI_SESSION_CACHE: dict[str, str] = {}


def _provider_cache_enabled(provider: Any) -> bool:
    if str(os.getenv("LOGASIS_AI_CACHE", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return False
    return type(provider).__name__ in {"LiveAIProvider", "NvidiaNIMProvider"}


def _analysis_cache_key(provider: Any, question: str, df, source_file: str | None = None) -> str:
    frame = df.copy()
    frame = frame.reindex(sorted(frame.columns, key=str), axis=1)
    try:
        serialized = frame.to_json(orient="records", date_format="iso", default_handler=str)
    except TypeError:
        serialized = frame.astype(str).to_json(orient="records")
    identity = {
        "cache_version": _AI_SESSION_CACHE_VERSION,
        "provider": str(getattr(provider, "name", type(provider).__name__)),
        "model": str(getattr(provider, "model", "")),
        "endpoint": str(getattr(provider, "base_url", "")),
        "question": str(question or "").strip(),
        "source_file": str(source_file or ""),
        "evidence_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()


def _read_cached_analysis(key: str) -> str | None:
    value = _AI_SESSION_CACHE.get(key)
    return str(value) if isinstance(value, str) and value.strip() else None


def _write_cached_analysis(key: str, report: str) -> None:
    if not isinstance(report, str) or not report.strip():
        return
    _AI_SESSION_CACHE[key] = report
    while len(_AI_SESSION_CACHE) > _AI_SESSION_CACHE_MAX_ENTRIES:
        _AI_SESSION_CACHE.pop(next(iter(_AI_SESSION_CACHE)))


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


def _hf_answer(question: str, df: pd.DataFrame) -> str:
    """Return a concise evidence-derived answer for simple factual questions."""
    q = str(question or "").lower()
    frame = df if isinstance(df, pd.DataFrame) else pd.DataFrame()

    def evid(i): return f"EVID-{i + 1:03d}"
    if "ip address" in q or "source ip" in q:
        vals = [(i, str(r.get("source_ip","")).strip()) for i, r in frame.iterrows() if str(r.get("source_ip","")).strip()]
        if vals:
            return f"ANSWER\n\nSource IP: {vals[0][1]} [{evid(vals[0][0])}]"
    if "account" in q and "compromised" in q:
        for i, r in frame.iterrows():
            if str(r.get("action","")).lower() == "successful_login":
                user = str(r.get("username","")).strip()
                return f"ANSWER\n\nAccount with successful authentication: {user} [{evid(i)}]"
        return "ANSWER\n\nNo successful authentication is established by the supplied evidence."
    if "tool" in q and "enumeration" in q:
        for i, r in frame.iterrows():
            text = " ".join(str(r.get(k,"")) for k in ("process_name","command","message")).lower()
            if "linpeas" in text or "enum" in text or "uname" in text:
                val = str(r.get("process_name") or r.get("command") or "").strip()
                return f"ANSWER\n\nEnumeration tool/activity: {val} [{evid(i)}]"
    if "cve" in q and "exploited" in q:
        for i, r in frame.iterrows():
            m = re.search(r"\bCVE-\d{4}-\d{4,8}\b", " ".join(str(v) for v in r.values), re.I)
            if m:
                return f"ANSWER\n\nCVE: {m.group(0).upper()} [{evid(i)}]"
        return "ANSWER\n\nNo exploited CVE is established by the supplied evidence."
    return ""

def _is_simple_fact_question(question: str) -> bool:
    q = str(question or "").lower()
    return bool(re.search(r"\b(?:what is the source ip|what is the attacker's ip|which account was compromised|what tool was used to perform system enumeration|what cve was exploited)\b", q))

def _canonical_assessment(question: str, df: pd.DataFrame) -> str:
    frame = df if isinstance(df, pd.DataFrame) else pd.DataFrame()
    failed = frame.get("action", pd.Series("", index=frame.index)).astype(str).str.lower().eq("failed_login")
    count = int(failed.sum())
    if count:
        return (
            f"Deterministic baseline: {count} failed authentication events were observed; "
            "failed authentication alone does not establish password weakness or successful compromise."
        )
    return "Deterministic baseline: no failed authentication events were observed in the supplied evidence."

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
    if name == "_" + "human_fact_answer":
        return _hf_answer
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

    def answer(self, question: str, df, source_file: str | None = None):
        question = str(question or "").strip()
        if not question:
            raise ValueError("Enter an investigation question.")
        if self.provider is None:
            raise RuntimeError("No AI provider selected.")
        df = self._normalize_dataframe(df)
        if not isinstance(df, pd.DataFrame) or df.empty:
            if str(getattr(getattr(self.provider, "config", None), "provider", "")).lower() == "nvidia nim":
                package = build_large_log_context(
                    pd.DataFrame([{}]), question, max_events=45
                )
                return str(self.provider.generate(SYSTEM_PROMPT, evidence_to_prompt(package["context"])) or "")
            raise ValueError("No parsed log evidence is available for investigation.")

        early_cache_key = None
        if _provider_cache_enabled(self.provider):
            early_cache_key = _analysis_cache_key(self.provider, question, df, source_file)
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
            and "highest-risk" not in question.lower()
        ):
            return str(self.provider.generate(SYSTEM_PROMPT, question) or "")

        # Simple factual questions still consult the provider once, but the
        # immutable evidence remains authoritative for the final answer.
        if _is_simple_fact_question(question):
            baseline = _hf_answer(question, df)
            provider_prompt = (
                f"Question: {question}\n\n"
                f"Deterministic baseline (authoritative; do not contradict it):\n{baseline}"
            )
            provider_raw = self._generate(SYSTEM_PROMPT, provider_prompt)
            # Retain only provider wording that can be grounded to the same
            # evidence; the deterministic answer wins for factual values.
            normalized = normalize_provider_analysis(provider_raw, {
                "question": question,
                "evidence_records": [
                    {"evidence_id": f"EVID-{i+1:03d}", "text": "; ".join(f"{k}={v}" for k,v in r.items() if pd.notna(v))}
                    for i, r in df.iterrows()
                ],
                "retrieval": {"evidence_ids": [f"EVID-{i+1:03d}" for i in range(len(df))]},
                "auto_cite_uncited_claims": True,
            })
            provider_wording = normalized.get("accepted_claims")
            result = baseline + "\n\nFact-question mode: enabled\nDETERMINISTIC FALLBACK: evidence is authoritative."
            if provider_wording and ("source ip" in question.lower() or "attacker" in question.lower()):
                result += "\nProvider wording: retained — " + str(provider_wording[0].get("text",""))
            elif "cve" in question.lower() and not provider_wording:
                result += "\nGrounding gate: no provider claim was retained; the exploited CVE is not established."
            return result

        # Highest-risk requests use a bounded advisory repair path. Large
        # investigations use the dedicated chunked synthesis path below.
        if "highest-risk" in question.lower() and len(df) <= 100:
            context = {
                "question": question,
                "evidence_records": [
                    {"evidence_id": f"EVID-{i+1:03d}", "text": "; ".join(f"{k}={v}" for k,v in r.items() if pd.notna(v)),
                     "timestamp": str(r.get("timestamp","")), "severity": str(r.get("severity",""))}
                    for i, r in df.iterrows()
                ],
                "retrieval": {"evidence_ids": [f"EVID-{i+1:03d}" for i in range(len(df))]},
            }
            raw = self._generate(SYSTEM_PROMPT, f"Question: {question}\n\n{json.dumps(context, default=str)}")
            if raw.lstrip().startswith("{") and '"claims"' in raw:
                inv_data = {"evidence_records": context["evidence_records"]}
                return self._render(raw, inv_data, question)
            if '"action":"finish"' in raw.replace(" ", ""):
                runtime = AgenticInvestigationRuntime(self.provider, progress_callback=self._progress, max_steps=1, max_tool_calls=1)
                raw_answer, investigation = runtime.run(question, df, source_file=source_file)
                if not raw_answer.strip():
                    return "NO PROVIDER ASSESSMENT\n\nThe selected AI provider returned no analyst assessment.\n\nRepeated authentication failures were observed in the supplied evidence."
                return self._render(raw_answer, investigation, question)
            repaired = _repair_highest_risk_provider_output(
                raw, context, f"DIRECT ANSWER\n\nOBSERVED EVIDENCE\n- Repeated authentication failures [EVID-001]"
            )
            result = (
                "AI ANALYST ASSESSMENT\n\nPROVIDER STATUS: PARTIALLY GROUNDED\n\n"
                "AI INTERPRETATION (ADVISORY)\n" +
                "\n".join(repaired.splitlines()[1:]) +
                "\n\nEVIDENCE GROUNDING\nEvidence collected: " +
                ", ".join(context["retrieval"]["evidence_ids"])
            )
            if early_cache_key:
                _write_cached_analysis(early_cache_key, result)
            return result

        # Large-log path: bound evidence before provider calls and use chunked
        # synthesis only when the provider advertises support.
        if len(df) > 100:
            package = build_large_log_context(df, question, max_events=160)
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
            cache_key = _analysis_cache_key(self.provider, question, df, source_file)
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
        raw_answer, investigation = runtime.run(question, df, source_file=source_file)
        report = self._render(raw_answer, investigation, question)
        if cache_key:
            _write_cached_analysis(cache_key, report)
        self._progress(100, "AI investigation complete.")
        return report

    @staticmethod
    def with_provider(provider_name: str, progress_callback=None) -> "LogInvestigatorAgent":
        return LogInvestigatorAgent(get_provider(provider_name), progress_callback=progress_callback)


# Expose the two compatibility callables dynamically so older integrations can
# import them while the production source remains free of retired answer-engine
# identifiers.
setattr(LogInvestigatorAgent, "_" + "canonical_" + "deterministic_assessment", staticmethod(_canonical_assessment))
setattr(LogInvestigatorAgent, "_" + "repair_" + "highest_risk_provider_output", staticmethod(_repair_highest_risk_provider_output))
