from __future__ import annotations
import json, re, urllib.request

class CaseAIAnalyst:
    @staticmethod
    def _apply_conclusion_guardrails(answer, question):
        q=question.lower()
        if any(x in q for x in ["compromise","compromised","breach","breached","successfully compromise"]):
            answer=re.sub(r"\bthe\s+system\s+was\s+not\s+compromised\b", "the available case evidence does not establish that the system was compromised", answer, flags=re.I)
            answer=re.sub(r"\b(?:the\s+)?(?:\w+\s+)?did\s+not\s+successfully\s+compromise(?:d)?\s+the\s+system\b",
                          "the available case evidence does not establish a successful compromise", answer, flags=re.I)
            answer=re.sub(r"\bdid\s+not\s+establish\s+a\s+successful\s+compromise\b",
                          "does not establish a successful compromise", answer, flags=re.I)
            if "does not establish a successful compromise" not in answer.lower() and "does not establish that the system was compromised" not in answer.lower():
                answer += "\n\nConclusion scope: The available case evidence does not establish a successful compromise."
        if re.search(r"\bconfidence\s*:\s*high\b",answer,re.I) and "recorded evidence" not in answer.lower():
            answer=answer.replace("Confidence: HIGH","Evidence Confidence: HIGH\nConfidence Scope: Based on the recorded evidence only")
        return answer.strip()

    @staticmethod
    def deterministic(question, case, intelligence, evidence):
        q=question.lower()
        failed=intelligence["failed_auth_event_count"]
        attempts=intelligence["observed_failed_attempts"]
        success=intelligence["successful_auth_event_count"]
        if any(x in q for x in ["compromise","compromised","breach","successfully"]):
            if success:
                conclusion="Successful authentication evidence is present in the supplied case evidence; compromise should be investigated further."
                status="ESTABLISHED"
            else:
                conclusion="The available case evidence does not establish a successful compromise."
                status="NOT ESTABLISHED"
            return f"""Case Analyst Report

Executive Summary
Based on the supplied case evidence, {conclusion.lower()}

Risk Assessment
- Risk Level: {intelligence['risk_level']}
- Evidence Confidence: {intelligence['evidence_confidence']}
- Confidence Scope: Based on the recorded evidence only
- Compromise Status: {status}

Evidence Summary
- Failed authentication events: {failed}
- Observed failed attempts: {attempts}
- Successful authentication events: {success}
- Source IPs: {', '.join(intelligence['source_ips']) or 'None recorded'}
- Users: {', '.join(intelligence['users']) or 'None recorded'}

Assessment & Limitations
The supplied evidence supports only the events present in this case. Missing successful-authentication, session, network, or process-parent context limits conclusions outside the captured evidence. Temporal proximity alone does not establish causation or malicious intent.

Recommended Next Steps
1. Review surrounding successful and failed authentication events.
2. Validate source-host authorization.
3. Review process and parent-process context for command execution events.
4. Preserve relevant evidence and analyst notes.

Analyst Conclusion
{conclusion} All conclusions are bounded to the supplied case evidence."""
        return f"""Case Analyst Report

Investigation Question
{question}

Executive Summary
The deterministic case intelligence identifies {len(evidence)} linked evidence records. The available evidence should be reviewed in context before drawing conclusions.

Observed Evidence
""" + "\n".join(f"- {e.evidence_id}: {e.event_type} | {e.priority} | {e.timestamp} | {e.process or 'N/A'}" for e in evidence) + """

Assessment & Limitations
The analysis is bounded to the supplied case evidence and does not infer facts that are not recorded.

Recommended Next Steps
1. Review the case timeline.
2. Review correlation relationships.
3. Validate relevant host, user, IP, and process context."""

    @classmethod
    def analyze(cls, question, case, intelligence, evidence, provider="Live AI", model=""):
        # Legacy compatibility surface: runtime AI is handled by ai.case_agent.
        # This module is deterministic-only and no longer contacts local LLMs.
        base = cls.deterministic(question, case, intelligence, evidence)
        return cls._apply_conclusion_guardrails(base, question)
