from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any


class CaseDecisionEngine:
    """Deterministic decision and evidence-gap assessment for a case question.

    This engine does not infer compromise from temporal proximity, failed
    authentication, or process execution alone.  It separates observed facts
    from the evidence required to establish a stronger conclusion.
    """

    SUCCESS_WORDS = ("success", "successful", "accepted", "granted", "opened", "logged in", "login succeeded")
    FAILURE_WORDS = ("failed", "failure", "denied", "invalid", "rejected", "authentication failure")
    SESSION_TYPES = {"USER_LOGIN", "LOGIN", "SESSION_OPEN", "SESSION_START", "SESSION"}
    AUTH_TYPES = {"USER_AUTH", "AUTH", "AUTHENTICATION"}
    EXEC_TYPES = {"EXECVE", "PROCESS_CREATE", "SYSCALL"}

    @staticmethod
    def _text(event: dict[str, Any]) -> str:
        return " ".join(
            str(event.get(key, "") or "")
            for key in ("event_type", "action", "message", "raw_log", "command", "result", "status")
        ).lower()

    @staticmethod
    def _eid(event: dict[str, Any]) -> str:
        return str(event.get("evidence_id", "") or "").strip()

    @classmethod
    def _is_success_auth(cls, event: dict[str, Any]) -> bool:
        if str(event.get("event_type", "") or "").upper() not in cls.AUTH_TYPES:
            return False
        text = cls._text(event)
        if any(word in text for word in cls.FAILURE_WORDS):
            return False
        return any(word in text for word in cls.SUCCESS_WORDS) or str(event.get("action", "")).lower() in {
            "successful_login", "auth_success", "login_success", "accepted"
        }

    @classmethod
    def _is_failed_auth(cls, event: dict[str, Any]) -> bool:
        if str(event.get("event_type", "") or "").upper() not in cls.AUTH_TYPES:
            return str(event.get("action", "") or "").lower() == "failed_login"
        text = cls._text(event)
        return str(event.get("action", "") or "").lower() == "failed_login" or any(word in text for word in cls.FAILURE_WORDS)

    @classmethod
    def _is_session(cls, event: dict[str, Any]) -> bool:
        et = str(event.get("event_type", "") or "").upper()
        action = str(event.get("action", "") or "").strip().lower()
        result = str(event.get("result", "") or "").strip().lower()
        status = str(event.get("status", "") or "").strip().lower()
        text = cls._text(event)

        if et in {"SESSION_OPEN", "SESSION_START", "SESSION"}:
            return not any(word in text for word in cls.FAILURE_WORDS)

        explicit = {"session_open", "session_start", "session_created", "session_create", "session_established", "login_session_open", "opened", "created"}
        if action in explicit:
            return True
        if et in {"USER_LOGIN", "LOGIN"} and (result in explicit or status in explicit):
            return True

        return any(term in text for term in ("session opened", "session start", "session created", "session established", "new session"))

    @classmethod
    def _is_success_privilege(cls, event: dict[str, Any]) -> bool:
        text = cls._text(event)
        action = str(event.get("action", "") or "").strip().lower()
        result = str(event.get("result", "") or "").strip().lower()
        status = str(event.get("status", "") or "").strip().lower()
        et = str(event.get("event_type", "") or "").upper()

        if any(word in text for word in cls.FAILURE_WORDS):
            return False
        if not any(term in text for term in ("sudo", "privilege", "elevat", "root", "euid=0", "uid=0")):
            return False
        if action in {"sudo_success", "privilege_escalation_success", "privilege_success", "elevation_success"}:
            return True
        if result in {"success", "successful", "yes", "granted", "accepted"} or status in {"success", "successful", "yes", "granted", "accepted"}:
            return et in {"SYSCALL", "USER_CMD", "PRIVILEGE", "PRIVILEGE_ESCALATION", "SUDO", "USER_ACCT", "AUTH", "USER_AUTH"} or "privilege" in text or "elevat" in text
        if "success=yes" in text and any(term in text for term in ("sudo", "privilege", "elevat", "euid=0")):
            return True
        return any(term in text for term in ("privilege escalation successful", "privilege elevation successful", "sudo succeeded", "sudo successful", "elevation succeeded", "elevated privileges successfully"))

    @classmethod
    def build(cls, case: dict[str, Any], intelligence: dict[str, Any] | None = None, question: str = "") -> dict[str, Any]:
        intelligence = intelligence or {}
        timeline = list(intelligence.get("timeline", []) or [])
        q = str(question or "").strip()
        q_lower = q.lower()
        compromise_question = any(term in q_lower for term in ("compromise", "compromised", "breach", "access", "intrusion"))

        failed_auth = [e for e in timeline if cls._is_failed_auth(e)]
        successful_auth = [e for e in timeline if cls._is_success_auth(e)]
        sessions = [e for e in timeline if cls._is_session(e)]
        successful_priv = [e for e in timeline if cls._is_success_privilege(e)]
        exec_events = [e for e in timeline if str(e.get("event_type", "") or "").upper() in cls.EXEC_TYPES]

        supporting = []
        if successful_auth:
            supporting.extend(cls._eid(e) for e in successful_auth if cls._eid(e))
        if sessions:
            supporting.extend(cls._eid(e) for e in sessions if cls._eid(e))
        if successful_priv:
            supporting.extend(cls._eid(e) for e in successful_priv if cls._eid(e))

        observed = []
        if failed_auth:
            observed.extend(cls._eid(e) for e in failed_auth if cls._eid(e))
        if exec_events:
            observed.extend(cls._eid(e) for e in exec_events if cls._eid(e))
        observed = list(dict.fromkeys(observed))
        supporting = list(dict.fromkeys(supporting))

        gaps: list[dict[str, Any]] = []
        if (failed_auth or successful_auth) and not successful_auth:
            gaps.append({
                "gap_id": "G-001",
                "category": "AUTHENTICATION",
                "severity": "HIGH",
                "description": "No successful authentication event is linked to the case.",
                "recommended_action": "Search surrounding authentication records for a successful login from the observed source/user.",
            })
        if (failed_auth or successful_auth) and not sessions:
            gaps.append({
                "gap_id": "G-002",
                "category": "SESSION",
                "severity": "HIGH",
                "description": "No confirmed session creation or login-session event is linked to the case.",
                "recommended_action": "Review USER_LOGIN, session-open, SSH session, or equivalent records around the authentication events.",
            })
        if any("sudo" in cls._text(e) or "privilege" in cls._text(e) for e in timeline) and not successful_priv:
            gaps.append({
                "gap_id": "G-003",
                "category": "PRIVILEGE",
                "severity": "MEDIUM",
                "description": "Privilege-related activity is present, but successful privilege elevation is not established.",
                "recommended_action": "Review sudo/authentication result fields and the resulting process identity.",
            })
        if any(not str(e.get("source_ip", "") or "").strip() for e in failed_auth + successful_auth):
            gaps.append({
                "gap_id": "G-004",
                "category": "SOURCE_ATTRIBUTION",
                "severity": "MEDIUM",
                "description": "At least one authentication event lacks a source IP.",
                "recommended_action": "Correlate host, network, SSH, or upstream authentication logs to establish source attribution.",
            })
        if exec_events and any(not str(e.get("username", "") or "").strip() for e in exec_events):
            gaps.append({
                "gap_id": "G-005",
                "category": "PROCESS_ATTRIBUTION",
                "severity": "MEDIUM",
                "description": "At least one execution event lacks a username.",
                "recommended_action": "Review UID/AUID, parent process, session, and process-accounting context.",
            })

        if successful_auth and (sessions or successful_priv):
            decision = "CONFIRMED" if compromise_question else "SUPPORTED"
            confidence = "HIGH"
            rationale = "Successful authentication is supported by session or successful privilege/context evidence linked to the case."
        elif successful_auth:
            decision = "NOT_ESTABLISHED"
            confidence = "MEDIUM"
            rationale = "A successful authentication event is present, but the supplied evidence does not establish a resulting session, command execution, or compromise."
        elif failed_auth:
            decision = "NOT_ESTABLISHED"
            confidence = "HIGH"
            rationale = "The linked authentication evidence records failures, but no successful authentication or confirmed session is linked to the case."
        elif timeline:
            decision = "INSUFFICIENT_EVIDENCE"
            confidence = "MEDIUM"
            rationale = "The case contains security-relevant activity, but the linked evidence does not contain a sufficient authentication/session basis for the requested decision."
        else:
            decision = "INSUFFICIENT_EVIDENCE"
            confidence = "LOW"
            rationale = "No linked evidence is available to support the requested decision."

        return {
            "case_id": case.get("case_id", ""),
            "question": q,
            "decision": decision,
            "confidence": confidence,
            "rationale": rationale,
            "observed_evidence_ids": observed,
            "decision_supporting_evidence_ids": supporting,
            "successful_auth_evidence_ids": [cls._eid(e) for e in successful_auth if cls._eid(e)],
            "failed_auth_evidence_ids": [cls._eid(e) for e in failed_auth if cls._eid(e)],
            "session_evidence_ids": [cls._eid(e) for e in sessions if cls._eid(e)],
            "successful_privilege_evidence_ids": [cls._eid(e) for e in successful_priv if cls._eid(e)],
            "evidence_gaps": gaps,
            "recommended_actions": [g["recommended_action"] for g in gaps],
            "limitations": [
                "This decision is limited to evidence currently linked to the case.",
                "Temporal proximity, correlation, failed authentication, and command execution alone do not establish compromise or causation.",
            ],
        }

    @staticmethod
    def export_json(path: str | Path, decision: dict[str, Any]) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(decision, indent=2, ensure_ascii=False), encoding="utf-8")
