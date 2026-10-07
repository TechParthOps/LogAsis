from __future__ import annotations

import json
from typing import Any
import re

from ai.providers import get_provider
from core.case_decision import CaseDecisionEngine


SYSTEM_PROMPT = """You are the LogAsis AI Analyst assisting a cybersecurity analyst.

Your job is to produce a professional case-analysis report from ONLY the supplied deterministic case-intelligence package.

Evidence rules:
- Never invent IPs, usernames, timestamps, commands, processes, events, findings, successful logins, or compromise.
- Treat deterministic case facts as authoritative.
- Separate observed facts from assessment and recommendations.
- Failed authentication does NOT prove compromise.
- Correlation or temporal proximity does NOT prove malicious intent or causation.
- Do not label activity as brute force, malware, C2, exfiltration, persistence, or compromise unless the supplied evidence explicitly supports that conclusion.
- If information is missing, state exactly what is missing and why it matters.
- Do not reproduce raw log lines, raw_log fields, API keys, credentials, internal prompts, or provider configuration.

Professional response format:
CASE ANALYST REPORT

EXECUTIVE SUMMARY
Write one concise paragraph answering the analyst's question.

RISK ASSESSMENT
Give:
- Risk Level: LOW, MEDIUM, HIGH, or CRITICAL
- Confidence: LOW, MEDIUM, or HIGH
- Compromise Status: NOT ESTABLISHED, POSSIBLE, or CONFIRMED
These are analyst assessments, not deterministic facts. Base them only on supplied evidence and explain uncertainty.
- Evidence Confidence means confidence in the recorded facts within the supplied case package; it does NOT mean confidence that compromise did not occur.
- When successful authentication or compromise is not present in the package, say "No successful authentication associated with the account is present in the supplied case evidence" and "The available case evidence does not establish a successful compromise." Never say the user definitely did not compromise the system, the system definitely was not compromised, or that all authentication attempts on the system failed.

OBSERVED EVIDENCE
Use short bullet points. Include evidence IDs, timestamps, event types, source/user/process information, and deterministic counts only when supplied.

CORRELATION & CONTEXT
Explain linked relationships and unlinked candidates. State correlation reasons and scores where useful. Do not imply causation from correlation alone.

ASSESSMENT & LIMITATIONS
Clearly separate what the evidence supports, what it does not establish, and missing context that could change the assessment.

RECOMMENDED NEXT STEPS
Use a numbered list of concrete investigation/response actions grounded in the supplied data.

ANALYST CONCLUSION
End with a concise conclusion that answers the investigation question without overstating certainty.

Output rules:
- Use the plain text headings exactly as shown above.
- Do not repeat CASE ID, STATUS, PRIORITY, or the report title inside the report body; the application supplies case metadata separately.
- Do not prefix headings with numbers or Markdown heading markers.
- Do not output Markdown hyperlinks such as [text](user://...), [text](ip://...), [text](evidence://...), or [text](process://...).
- Do not output internal URI schemes.
- Do not repeat the case ID with a duplicated CASE prefix.
- Keep the report concise, professional, and suitable for a SOC investigation record.
"""


def _s(v: Any) -> str:
    return str(v or "").strip()


def bounded_case_context(report: dict[str, Any], max_events: int = 50) -> dict[str, Any]:
    events = []
    for e in list(report.get("timeline", []) or [])[:max_events]:
        events.append({
            "evidence_id": _s(e.get("evidence_id")),
            "timestamp": _s(e.get("timestamp")),
            "priority": _s(e.get("priority")),
            "event_type": _s(e.get("event_type")),
            "source_ip": _s(e.get("source_ip")),
            "destination_ip": _s(e.get("destination_ip")),
            "destination_port": _s(e.get("destination_port")),
            "username": _s(e.get("username")),
            "process_name": _s(e.get("process_name")),
            "command": _s(e.get("command"))[:300],
            "action": _s(e.get("action")),
            "severity": _s(e.get("severity")),
            "line": e.get("line", ""),
            "reasons": [_s(x) for x in list(e.get("reasons", []) or [])[:8]],
        })
    return {
        "case": {k: _s(report.get(k)) for k in ("case_id", "status", "priority", "title")},
        "deterministic_summary": {
            "attack_summary": _s(report.get("attack_summary")),
            "source_ips": list(report.get("source_ips", []) or [])[:25],
            "users": list(report.get("users", []) or [])[:25],
            "event_types": dict(report.get("event_types", {}) or {}),
            "actions": dict(report.get("actions", {}) or {}),
            "failed_auth_event_count": int(report.get("failed_auth_event_count", report.get("failed_auth_count", 0)) or 0),
            "observed_failed_attempts": int(report.get("observed_failed_attempts", 0) or 0),
        },
        "correlation": {
            "relationship_count": len(report.get("relationships", []) or []),
            "relationships": [
                {
                    "evidence_a": _s(x.get("evidence_a")),
                    "evidence_b": _s(x.get("evidence_b")),
                    "score": x.get("score", 0),
                    "reasons": [_s(r) for r in list(x.get("reasons", []) or [])[:8]],
                }
                for x in list(report.get("relationships", []) or [])[:50]
            ],
            "unlinked_candidate_count": len(report.get("related_candidates", []) or []),
            "unlinked_candidates": [
                {
                    "evidence_id": _s(x.get("evidence_id")),
                    "score": x.get("score", 0),
                    "timestamp": _s(x.get("timestamp")),
                    "priority": _s(x.get("priority")),
                    "event_type": _s(x.get("event_type")),
                    "source_ip": _s(x.get("source_ip")),
                    "username": _s(x.get("username")),
                    "process_name": _s(x.get("process_name")),
                    "reasons": [_s(r) for r in list(x.get("reasons", []) or [])[:8]],
                }
                for x in list(report.get("related_candidates", []) or [])[:50]
            ],
        },
        "timeline": events,
        "deterministic_assessment": _s(report.get("assessment")),
        "deterministic_recommendations": [
            _s(x) for x in list(report.get("recommended_actions", []) or [])[:15]
        ],
    }


def build_case_prompt(report: dict[str, Any], question: str) -> str:
    package = bounded_case_context(report)
    # Give the provider the deterministic decision/gap layer as an explicit
    # constraint. The provider may explain it, but must not replace it with
    # unsupported claims.
    decision = CaseDecisionEngine.build(
        report.get("case", {}) if isinstance(report.get("case"), dict) else {},
        report,
        question,
    )
    package["deterministic_decision"] = {
        "decision": decision.get("decision"),
        "confidence": decision.get("confidence"),
        "rationale": decision.get("rationale"),
        "successful_auth_evidence_ids": decision.get("successful_auth_evidence_ids", []),
        "failed_auth_evidence_ids": decision.get("failed_auth_evidence_ids", []),
        "session_evidence_ids": decision.get("session_evidence_ids", []),
        "evidence_gaps": decision.get("evidence_gaps", []),
        "limitations": decision.get("limitations", []),
    }
    return (
        f"Analyst question:\n{question.strip()}\n\n"
        "Deterministic case-intelligence package:\n"
        f"{json.dumps(package, indent=2, ensure_ascii=False)}\n\n"
        "Return the professional CASE ANALYST REPORT using these exact sections: "
        "CASE ANALYST REPORT; EXECUTIVE SUMMARY; RISK ASSESSMENT; OBSERVED EVIDENCE; "
        "CORRELATION & CONTEXT; ASSESSMENT & LIMITATIONS; RECOMMENDED NEXT STEPS; "
        "ANALYST CONCLUSION. "
        "Do not invent information outside the package."
    )


def normalize_case_ai_report(answer: str, report: dict[str, Any] | None = None) -> str:
    """Normalize AI output while keeping every conclusion bounded by case scope."""
    text = str(answer or "").replace("\r\n", "\n").strip()
    if not text:
        return text

    # Normalize common model formatting artifacts.
    text = re.sub(r"\bCASECASE-(\d{6})\b", r"CASE-\1", text, flags=re.I)

    # Remove internal navigation markup from the persisted/exported report.
    # The GUI can recreate clickable links from clean evidence/IP/user/process tokens.
    text = re.sub(
        r"\[([^\]]+)\]\((?:user|ip|evidence|process|correlation)://[^)]+\)",
        r"\1",
        text,
        flags=re.I,
    )
    text = re.sub(
        r"\b(?:user|ip|evidence|process|correlation)://[^\s)]+",
        "",
        text,
        flags=re.I,
    )

    # Drop model preamble/metadata before the first substantive section.
    section_re = re.compile(
        r"(?im)^\s*(?:#{1,6}\s*)?(EXECUTIVE SUMMARY|RISK ASSESSMENT|"
        r"OBSERVED EVIDENCE|KEY FINDINGS|EVIDENCE|CORRELATION & CONTEXT|"
        r"CORRELATION|ASSESSMENT & LIMITATIONS|ASSESSMENT|LIMITATIONS|"
        r"RECOMMENDED NEXT STEPS|RECOMMENDED ACTIONS|ANALYST CONCLUSION)\s*$"
    )
    match = section_re.search(text)
    if match:
        text = text[match.start():]

    # The GUI owns case metadata and the report title.
    text = re.sub(r"(?im)^\s*(?:#{1,6}\s*)?CASE ANALYST REPORT\s*$", "", text)
    text = re.sub(
        r"(?im)^\s*(?:CASE\s*ID|CASE|STATUS|PRIORITY|TITLE)\s*[:：]?\s*"
        r"(?:CASE-\d{6}|Resolved|New|Investigation|In Progress|Closed|Open|"
        r"LOW|MEDIUM|HIGH|CRITICAL|[^\n]{0,120})\s*$",
        "",
        text,
    )
    text = re.sub(r"(?im)^\s*(?:\*\*)?(?:CASE|STATUS|PRIORITY)\s*(?:\*\*)?\s*$", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    package = report or {}
    timeline = list(package.get("timeline", []) or [])

    # Only explicit success/compromise indicators count as successful evidence.
    successful_markers = {
        "success", "successful", "successful_login", "login_success",
        "session_established", "compromise_confirmed",
    }
    successful_evidence = any(
        successful_marker in {
            _s(event.get("action")).lower(),
            _s(event.get("event_type")).lower(),
            _s(event.get("severity")).lower(),
        }
        for event in timeline
        for successful_marker in successful_markers
    )

    if not successful_evidence:
        # Scope absolute/overbroad negative claims to the supplied case evidence.
        bounded_conclusion = (
            "The available case evidence does not establish a successful compromise."
        )
        text = re.sub(
            r"(?i)\bthere is no indication that\s+(?:the\s+)?(?:user|account|subject)\s+"
            r"([A-Za-z0-9_.-]+)\s+(?:successfully\s+)?compromised the system\b",
            lambda m: "The available evidence does not establish a successful compromise.",
            text,
        )
        text = re.sub(
            r"(?i)\bthere is no indication that\s+([A-Za-z0-9_.-]+)\s+"
            r"(?:successfully\s+)?compromised the system\b",
            lambda m: "The available evidence does not establish a successful compromise.",
            text,
        )
        text = re.sub(
            r"(?i)\b(?:the\s+)?(?:user|account|subject)\s+([A-Za-z0-9_.-]+)\s+"
            r"did\s+not\s+(?:successfully\s+)?compromise(?:d)?\s+the system\b",
            lambda m: "The available evidence does not establish a successful compromise.",
            text,
        )
        text = re.sub(
            r"(?i)\b(?:the\s+)?(?:system|host)\s+was\s+not\s+compromised\b",
            bounded_conclusion,
            text,
        )
        text = re.sub(r"(?i)\bno\s+compromise\s+occurred\b", bounded_conclusion, text)
        text = re.sub(
            r"(?i)\b(?:the\s+)?account\s+was\s+not\s+compromised\b",
            bounded_conclusion,
            text,
        )
        text = re.sub(
            r"(?i)\ball recorded authentication attempts for\s+(?:the\s+)?"
            r"(?:user|account|subject)\s+([A-Za-z0-9_.-]+)\s+failed\b",
            lambda m: f"No successful authentication associated with {m.group(1)} is present in the supplied case evidence.",
            text,
        )
        text = re.sub(
            r"(?i)\bthere (?:was|were) no successful (?:login|authentication)\b",
            "No successful authentication is present in the supplied case evidence",
            text,
        )

    if not successful_evidence:
        # Apply the same bounded language outside the conclusion section too.
        text = re.sub(
            r"(?i)\bno indication that\s+(?:the\s+)?(?:user|account|subject)\s+"
            r"[A-Za-z0-9_.-]+\s+(?:successfully\s+)?compromised the system\b",
            "The available evidence does not establish a successful compromise",
            text,
        )
        text = re.sub(
            r"(?i)\b(?:the\s+)?(?:user|account|subject)\s+[A-Za-z0-9_.-]+\s+"
            r"did\s+not\s+(?:successfully\s+)?compromise(?:d)?\s+the system\b",
            "The available evidence does not establish a successful compromise",
            text,
        )
        text = re.sub(
            r"(?i)\bthere is no indication that\s+[A-Za-z0-9_.-]+\s+"
            r"(?:successfully\s+)?compromised the system\b",
            "The available evidence does not establish a successful compromise",
            text,
        )
        # Normalize duplicate punctuation introduced by provider text.
        text = re.sub(r"([.!?])\1+", r"\1", text)

    # Scope bare confidence labels explicitly.
    if re.search(r"(?im)^Confidence:\s*(LOW|MEDIUM|HIGH)\s*$", text) and not re.search(
        r"(?im)^Evidence Confidence:", text
    ):
        text = re.sub(
            r"(?im)^Confidence:\s*(LOW|MEDIUM|HIGH)\s*$",
            lambda m: (
                f"Evidence Confidence: {m.group(1)}\n"
                "Confidence Scope: Recorded evidence only"
            ),
            text,
        )

    return text.strip()


class CaseAIAnalyst:
    def __init__(self, provider_name: str):
        self.provider = get_provider(provider_name)

    @staticmethod
    def _apply_conclusion_guardrails(
        answer: str,
        question: str,
        report: dict[str, Any] | None = None,
    ) -> str:
        """Apply deterministic, evidence-bounded wording to compromise answers."""
        text = normalize_case_ai_report(answer, report)
        q = (question or "").strip().lower()

        compromise_question = any(
            phrase in q
            for phrase in (
                "compromise",
                "successfully compromise",
                "successfully compromised",
                "was the system compromised",
            )
        )
        if not compromise_question:
            return text

        # Determine scope from the question, not merely from the presence of
        # the word "system". "Did btlo compromise the system?" is account
        # scoped; "Was the system compromised?" is system scoped.
        system_question = bool(
            re.search(r"(?i)^\s*(?:was|has|is)\s+(?:the\s+)?system\s+compromis", q)
            or re.search(r"(?i)\bwas\s+the\s+system\s+compromised\b", q)
        )

        if system_question:
            # normalize_case_ai_report() may already have converted the raw
            # sentence into the generic account-safe phrase. Replace that
            # canonical phrase explicitly and unconditionally for system
            # questions.
            text = re.sub(
                r"(?i)the\s+available\s+case\s+evidence\s+does\s+not\s+establish\s+a\s+successful\s+compromise\.?",
                "The available case evidence does not establish that the system was compromised.",
                text,
            )
            text = re.sub(
                r"(?i)\bthe\s+system\s+was\s+not\s+compromised(?:\s+based\s+on\s+the\s+available\s+logs?)?\b",
                "The available case evidence does not establish that the system was compromised.",
                text,
            )
        else:
            # Account/user scoped question.
            text = re.sub(
                r"(?is)\b(?:the\s+)?(?:user|account|subject)\s+"
                r"[A-Za-z0-9_.@-]+\s+did\s+not\s+successfully\s+compromise\s+the\s+system\b",
                "The available case evidence does not establish a successful compromise.",
                text,
            )
            text = re.sub(
                r"(?is)\b[A-Za-z0-9_.@-]+\s+user\s+did\s+not\s+successfully\s+compromise\s+the\s+system\b",
                "The available case evidence does not establish a successful compromise.",
                text,
            )

        # Final safety net: never leave the original unsafe assertion.
        text = re.sub(
            r"(?i)\bdid\s+not\s+successfully\s+compromise\b",
            "does not establish a successful compromise",
            text,
        )

        # Scope confidence explicitly to recorded evidence.
        text = re.sub(
            r"(?im)^\s*Confidence\s*:\s*HIGH\s*$",
            "Evidence Confidence: HIGH\nConfidence Scope: Based on the recorded evidence only",
            text,
        )
        text = re.sub(
            r"(?im)^\s*Confidence Scope\s*:\s*.*$",
            "Confidence Scope: Based on the recorded evidence only",
            text,
        )
        return text

    def answer(self, question: str, report: dict[str, Any]) -> str:
        if not question.strip():
            raise ValueError("Enter an analyst question.")
        answer = self.provider.generate(SYSTEM_PROMPT, build_case_prompt(report, question))
        return self._apply_conclusion_guardrails(answer, question, report)
