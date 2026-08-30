from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any


class CaseIntelligence:
    """Deterministic case-level intelligence for analyst review.

    This module deliberately avoids declaring an event malicious. It converts
    structured evidence and correlation results into a concise, explainable
    analyst summary.
    """

    def __init__(self, correlation_engine):
        self.correlation_engine = correlation_engine

    @staticmethod
    def _clean(value: Any) -> str:
        return str(value or "").strip()

    def build(self, case: dict[str, Any], evidence=None) -> dict[str, Any]:
        """Build deterministic intelligence.

        ``evidence`` is an optional legacy 4.x argument.  When supplied, it is
        treated as the linked evidence set directly; otherwise the configured
        correlation engine is used.  This keeps the modern API while preserving
        the historical ``build(case, evidence)`` contract.
        """
        if evidence is None:
            result = self.correlation_engine.correlate_case(case)
        else:
            # Legacy callers supplied EvidenceRecord objects directly.  Convert
            # them to the canonical dictionaries consumed by this module.
            timeline = []
            for item in (evidence or []):
                if hasattr(item, "to_dict"):
                    timeline.append(item.to_dict())
                elif isinstance(item, dict):
                    timeline.append(dict(item))
                else:
                    timeline.append(dict(vars(item)))
            timeline.sort(key=lambda e: self._clean(e.get("timestamp")))
            relationships = []
            try:
                correlated = self.correlation_engine.correlate_case(
                    {**case, "evidence": timeline}
                )
                if isinstance(correlated, dict):
                    relationships = correlated.get("relationships", []) or []
            except (AttributeError, TypeError, KeyError):
                # A legacy correlation callback may not implement the modern
                # case contract.  The direct evidence path remains valid.
                relationships = []
            users = sorted({self._clean(e.get("username")) for e in timeline if self._clean(e.get("username"))})
            source_ips = sorted({self._clean(e.get("source_ip")) for e in timeline if self._clean(e.get("source_ip"))})
            result = {
                "timeline": timeline,
                "relationships": relationships,
                "related_candidates": [],
                "summary": {
                    "users": users,
                    "source_ips": source_ips,
                },
            }
        timeline = result["timeline"]
        summary = result["summary"]

        event_types = Counter(self._clean(e.get("event_type")).upper() for e in timeline if self._clean(e.get("event_type")))
        actions = Counter(self._clean(e.get("action")).lower() for e in timeline if self._clean(e.get("action")))
        users = summary["users"]
        source_ips = summary["source_ips"]

        def is_failed_auth(event: dict[str, Any]) -> bool:
            action = self._clean(event.get("action")).lower()
            if action == "failed_login":
                return True
            event_type = self._clean(event.get("event_type")).upper()
            text = " ".join([
                self._clean(event.get("message")),
                self._clean(event.get("raw_log")),
                " ".join(str(x) for x in (event.get("reasons", []) or [])),
            ]).lower()
            return event_type == "USER_AUTH" and ("res=failed" in text or "failed authentication" in text)

        failed_auth = sum(1 for e in timeline if is_failed_auth(e))
        auth_events = sum(1 for e in timeline if self._clean(e.get("event_type")).upper() == "USER_AUTH")
        exec_events = sum(1 for e in timeline if self._clean(e.get("event_type")).upper() in {"EXECVE", "PROCESS_CREATE", "SYSCALL"})

        # Some audit records summarize a burst of attempts in a reason such as
        # "Repeated failures from 192.168.4.155 (174 attempts)".  Keep this
        # separate from the number of evidence records so the report does not
        # imply that two records necessarily mean two actual attempts.
        observed_attempt_counts = []
        for event in timeline:
            text = " ".join([
                self._clean(event.get("message")),
                self._clean(event.get("raw_log")),
                " ".join(str(x) for x in (event.get("reasons", []) or [])),
            ])
            patterns = (
                r"\((\d+)\s+attempts?\)",
                r"\bat\s+least\s+(\d+)\s+failed\s+attempts?\b",
                r"\b(\d+)\s+failed\s+attempts?\b",
            )
            for pattern in patterns:
                for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                    observed_attempt_counts.append(int(match.group(1)))
        observed_failed_attempts = max(observed_attempt_counts, default=failed_auth)

        if failed_auth >= 2:
            if observed_failed_attempts > failed_auth:
                attack_summary = (
                    f"Repeated authentication failures were observed against "
                    f"{', '.join(users) or 'the account(s) in evidence'}"
                    f" from {', '.join(source_ips) or 'an identified source'}; "
                    f"the evidence summarizes at least {observed_failed_attempts} failed attempts."
                )
            else:
                attack_summary = "Repeated authentication failures were observed in the case evidence."
        elif failed_auth == 1 and auth_events:
            attack_summary = "An authentication failure was observed in the case evidence."
        elif auth_events and exec_events:
            attack_summary = "Authentication and process-execution activity were observed in the same case."
        elif exec_events:
            attack_summary = "Process or command execution activity was observed in the case evidence."
        elif timeline:
            attack_summary = "Security-relevant activity was collected in the case for analyst review."
        else:
            attack_summary = "No linked evidence is currently available for assessment."

        assessment_parts = []
        if failed_auth >= 2:
            assessment_parts.append("The evidence indicates repeated authentication activity")
            if source_ips:
                assessment_parts.append(f"associated with {', '.join(source_ips)}")
            if users:
                assessment_parts.append(f"against account(s) {', '.join(users)}")
            assessment_parts[-1] += "."
            if observed_failed_attempts > failed_auth:
                assessment_parts.append(
                    f"The linked evidence summarizes at least {observed_failed_attempts} failed attempts, "
                    "which is distinct from the number of evidence records."
                )
        elif timeline:
            assessment_parts.append("The linked evidence contains activity that warrants analyst validation.")

        if result["relationships"]:
            assessment_parts.append(
                f"{len(result['relationships'])} explainable relationship(s) were identified among linked evidence."
            )
        if result["related_candidates"]:
            assessment_parts.append(
                f"{len(result['related_candidates'])} additional evidence candidate(s) may be related but remain unlinked."
            )

        if not assessment_parts:
            assessment_parts.append("Insufficient linked evidence for a meaningful assessment.")

        actions_list = []
        if source_ips:
            actions_list.append("Validate whether the observed source host(s) are authorized.")
        if failed_auth or auth_events:
            actions_list.append("Review surrounding successful and failed authentication events.")
        if exec_events:
            actions_list.append("Review the executed process/command and its parent process context.")
        if result["related_candidates"]:
            actions_list.append("Review potential related evidence before linking it to the case.")
        actions_list.append("Preserve relevant evidence and analyst notes before changing case status.")

        # Deterministic uncertainty/limitations. These are facts about the
        # coverage of the case package, not claims about what did or did not
        # happen outside the supplied evidence.
        uncertainty = []
        if failed_auth:
            uncertainty.append(
                "The observed failed authentication activity does not prove compromise."
            )
        if any(
            self._clean(e.get("event_type")).upper() in {"EXECVE", "PROCESS_CREATE", "SYSCALL"}
            and not self._clean(e.get("username"))
            for e in timeline
        ):
            uncertainty.append(
                "Some process-execution evidence lacks a username, limiting attribution."
            )
        if any(
            self._clean(e.get("event_type")).upper() == "USER_AUTH"
            and not self._clean(e.get("source_ip"))
            for e in timeline
        ):
            uncertainty.append(
                "Some authentication evidence lacks a source IP, limiting source attribution."
            )
        # Keep this limitation explicit even when the correlation engine finds
        # no formal relationship.  A case package can contain multiple event
        # types that happen close together without establishing that one caused
        # another.  This wording is intentionally stable because it is also part
        # of the public CaseIntelligence contract used by the test suite and by
        # exported analyst reports.
        uncertainty.append(
            "The available evidence does not prove causation between observed events."
        )
        if result["relationships"]:
            uncertainty.append(
                "Temporal correlation does not by itself establish causation or malicious intent."
            )
        uncertainty.append(
            "The assessment is limited to the evidence currently linked to this case."
        )

        # Evidence-backed findings are deliberately phrased as scoped findings.
        # Each finding carries the exact evidence IDs that support it so the UI
        # and exported report can provide provenance without asking the AI to
        # reconstruct the chain of evidence.
        findings = []
        failed_ids = [
            str(e.get("evidence_id", "")).strip()
            for e in timeline
            if is_failed_auth(e) and str(e.get("evidence_id", "")).strip()
        ]
        if failed_auth:
            findings.append({
                "finding_id": "F-001",
                "classification": "OBSERVED",
                "confidence": "HIGH",
                "statement": (
                    f"{observed_failed_attempts} failed authentication attempt(s) are "
                    "represented by the linked evidence."
                    if observed_failed_attempts != failed_auth
                    else f"{failed_auth} failed authentication evidence event(s) are linked to the case."
                ),
                "evidence_ids": failed_ids,
            })
        if result["relationships"]:
            rel_ids = []
            for rel in result["relationships"]:
                for key in ("evidence_a", "evidence_b"):
                    value = str(rel.get(key, "")).strip()
                    if value and value not in rel_ids:
                        rel_ids.append(value)
            findings.append({
                "finding_id": "F-002",
                "classification": "CORRELATION",
                "confidence": "MEDIUM",
                "statement": (
                    f"{len(result['relationships'])} deterministic relationship(s) "
                    "were identified; correlation does not prove causation."
                ),
                "evidence_ids": rel_ids,
            })
        findings.append({
            "finding_id": f"F-{len(findings)+1:03d}",
            "classification": "LIMITATION",
            "confidence": "HIGH",
            "statement": "The available evidence does not prove causation between observed events.",
            "evidence_ids": [str(e.get("evidence_id", "")).strip() for e in timeline if str(e.get("evidence_id", "")).strip()],
        })

        return {
            "case_id": case.get("case_id", ""),
            "status": case.get("status", "New"),
            "priority": case.get("priority", "MEDIUM"),
            "title": case.get("title", ""),
            "attack_summary": attack_summary,
            "source_ips": source_ips,
            "users": users,
            "event_types": dict(event_types),
            "actions": dict(actions),
            "timeline": timeline,
            "relationships": result["relationships"],
            "relationship_count": len(result["relationships"]),
            "related_candidates": result["related_candidates"],
            "related_candidate_count": len(result["related_candidates"]),
            "uncertainty": uncertainty,
            "assessment": " ".join(assessment_parts),
            "recommended_actions": actions_list,
            "findings": findings,
            "provenance": {
                f["finding_id"]: list(f.get("evidence_ids", []) or [])
                for f in findings
            },
            # Backward-compatible event count: number of linked evidence records
            # classified as failed authentication.
            "failed_auth_count": failed_auth,
            "failed_auth_event_count": failed_auth,
            "observed_failed_attempts": observed_failed_attempts,
        }

    @staticmethod
    def export_json(path: str | Path, report: dict[str, Any]) -> None:
        """Export a deterministic case-intelligence report as JSON."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def render(report: dict[str, Any]) -> str:
        lines = [
            f"CASE INTELLIGENCE — {report.get('case_id', 'N/A')}",
            "=" * 72,
            "",
            f"Status: {report.get('status', 'N/A')}",
            f"Priority: {report.get('priority', 'N/A')}",
            f"Title: {report.get('title', 'N/A')}",
            "",
            "ATTACK SUMMARY",
            "-" * 72,
            report.get("attack_summary", "N/A"),
            "",
            "OBSERVED ENTITIES",
            "-" * 72,
            f"Source IPs: {', '.join(report.get('source_ips', [])) or 'None'}",
            f"Users: {', '.join(report.get('users', [])) or 'None'}",
            f"Authentication evidence events: {report.get('failed_auth_event_count', report.get('failed_auth_count', 0))}",
            f"Observed failed attempts: {report.get('observed_failed_attempts', report.get('failed_auth_count', 0))}",
            f"Event types: {', '.join(f'{k} ({v})' for k, v in report.get('event_types', {}).items()) or 'None'}",
            "",
            "TIMELINE",
            "-" * 72,
        ]

        timeline = report.get("timeline", [])
        if timeline:
            for item in timeline:
                lines.append(
                    f"{item.get('timestamp', 'N/A')} | "
                    f"{item.get('priority', 'N/A')} | "
                    f"{item.get('event_type', 'N/A')} | "
                    f"{item.get('process_name', '') or 'N/A'} | "
                    f"{item.get('evidence_id', 'N/A')}"
                )
        else:
            lines.append("No linked evidence.")

        lines.extend([
            "",
            "CORRELATION",
            "-" * 72,
            f"Linked relationships: {len(report.get('relationships', []))}",
            f"Potential unlinked candidates: {len(report.get('related_candidates', []))}",
        ])
        for rel in report.get("relationships", []):
            lines.append(
                f"• {rel.get('evidence_a')} <-> {rel.get('evidence_b')} "
                f"(score {rel.get('score')}) — " + "; ".join(rel.get("reasons", []))
            )

        lines.extend([
            "",
            "EVIDENCE-BACKED FINDINGS",
            "-" * 72,
        ])
        for finding in report.get("findings", []):
            refs = ", ".join(finding.get("evidence_ids", []) or []) or "None"
            lines.append(
                f"{finding.get('finding_id', 'F-???')} | "
                f"{finding.get('classification', 'N/A')} | "
                f"{finding.get('confidence', 'N/A')} | "
                f"{finding.get('statement', '')}"
            )
            lines.append(f"  Evidence: {refs}")
        if not report.get("findings"):
            lines.append("No evidence-backed findings were generated.")

        lines.extend([
            "",
            "ANALYST ASSESSMENT",
            "-" * 72,
            report.get("assessment", "N/A"),
            "",
            "UNCERTAINTY / LIMITATIONS",
            "-" * 72,
        ])
        uncertainty = report.get("uncertainty", [])
        if uncertainty:
            for item in uncertainty:
                lines.append(f"• {item}")
        else:
            lines.append("No additional deterministic limitations were identified.")

        lines.extend([
            "",
            "RECOMMENDED ACTIONS",
            "-" * 72,
        ])
        for index, action in enumerate(report.get("recommended_actions", []), start=1):
            lines.append(f"{index}. {action}")

        lines.extend([
            "",
            "NOTE",
            "-" * 72,
            "This assessment is deterministic and explainable. It does not by itself declare activity malicious or confirm compromise.",
        ])
        return "\n".join(lines)
