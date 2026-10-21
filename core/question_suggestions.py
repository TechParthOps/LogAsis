"""Dynamic suggested questions for the AI Analyst.

Suggested questions must match the loaded evidence, not a fixed list. This
module derives up to 12 analyst questions from the loaded dataset: the log
profile (Windows/Sysmon, SSH/auth, web, firewall, DNS, generic), the fields
that actually exist, and the deterministic incident profile. Every question
is answerable by the deterministic layer or the grounded AI runtime against
the current log.
"""

from __future__ import annotations

from typing import Any

# Baseline questions that work on every log with authentication activity
# (any platform): the deterministic layer answers these from the failed ->
# successful login signature and the incident profile.
_COMMON_TAIL = [
    "Summarize highest-risk findings",
    "Explain critical activity",
    "What evidence supports the top finding?",
]


def _has_field(df, schema, name: str) -> bool:
    try:
        if name in df.columns:
            return bool(df[name].fillna("").astype(str).str.strip().ne("").any())
    except Exception:
        return False
    return False


def _facet_has(schema, field: str, *needles: str) -> bool:
    try:
        values = schema.distinct(field) if field in schema.fields else []
    except Exception:
        return False
    lowered = [str(v).lower() for v in values[:200]]
    return any(any(n in v for n in needles) for v in lowered)


def suggest_questions(df, dataset) -> list[str]:
    """Return up to 12 suggested questions tailored to the loaded log."""
    if df is None or len(df) == 0:
        return []

    from core.question_understanding import QuestionSchema

    schema = QuestionSchema(dataset.event_index)
    columns = {str(c) for c in df.columns}

    profile = None
    getter = getattr(dataset, "get_incident_profile", None)
    if callable(getter):
        try:
            profile = getter()
        except Exception:
            profile = None
    has_incident = bool(profile is not None and getattr(profile, "has_incident", False))
    is_windows = bool(profile is not None and getattr(profile, "is_windows", False))

    event_type_field = schema.canonical_field("event_type") or "event_type"
    action_field = schema.canonical_field("action") or "action"
    has_auth_actions = bool(
        _facet_has(schema, action_field, "failed_login", "successful_login")
        or (_facet_has(schema, event_type_field, "4624", "4625", "user_auth", "user_login"))
    )
    has_web = bool(
        "status_code" in columns
        or _facet_has(schema, event_type_field, "http")
        or ("uri" in columns or "url" in columns)
    )
    has_dns = _facet_has(schema, event_type_field, "dns") or "query_name" in columns
    has_firewall = bool(
        _facet_has(schema, action_field, "blocked", "deny", "allow", "drop")
        and ("destination_ip" in columns or "destination_port" in columns)
        and not has_web
    )
    has_event_ids = bool("event_id" in columns)
    has_commands = _has_field(df, schema, "command")
    has_parent = _has_field(df, schema, "parent_image")

    questions: list[str] = []

    # --- incident-centered questions (any platform) --------------------------
    has_suspicious_content = bool(
        profile is not None and (
            getattr(profile, "suspicious_executions", None)
            or getattr(profile, "credential_access", None)
            or getattr(profile, "downloaded_tools", None)
        )
    )
    if has_incident:
        questions.extend([
            "Which account was compromised?",
            "What attack type was used to gain initial access?",
            "What is the attacker's IP address?",
            "Identify suspicious users",
        ])
        if is_windows:
            questions.extend([
                "What suspicious process was executed and what is its PID?",
                "What credential access or dumping activity is present?",
                "What tool was used to perform system enumeration?",
                "What files or artifacts did the attacker access or stage?",
            ])
        else:
            questions.extend([
                "What is the name of the binary and PID used to gain root?",
                "What CVE was exploited to gain root access?",
                "What tool was used to perform system enumeration?",
                "What file was exfiltrated once root was gained?",
            ])
    elif has_suspicious_content:
        # Suspicious executions without an authentication sequence (e.g. a
        # Sysmon-only capture): center the questions on what was found.
        questions.extend([
            "What suspicious process was executed and what is its PID?",
            "What credential access or dumping activity is present?",
            "What files or artifacts did the attacker access or stage?",
            "Which parent process spawned the suspicious child processes?",
        ])
    else:
        # No recognizable intrusion: ask what the log CAN answer.
        if has_auth_actions:
            questions.extend([
                "How many failed logins are in this log?",
                "Which account has the most failed logins?",
                "What is the most active source IP and what did it do?",
                "Identify suspicious users",
            ])
        elif has_web:
            questions.extend([
                "How many client errors (4xx) are in this log?",
                "Which IP address sent the most requests?",
                "Which URLs were requested most often?",
                "Are there suspicious scanning or injection attempts?",
            ])
        elif has_firewall:
            questions.extend([
                "How many blocked connections are in this log?",
                "Which destination ports are contacted most?",
                "What is the top talker by connection count?",
                "Are there repeated denied connections from one source?",
            ])
        elif has_dns:
            questions.extend([
                "Which domains are queried most often?",
                "How many unique domains were queried?",
                "Are there queries to suspicious or long random domains?",
                "Which client generated the most DNS queries?",
            ])
        else:
            questions.extend([
                "What are the most important security findings in this log?",
                "What event types appear in this log?",
                "How many events involve the most frequent user?",
                "Which sources appear in this log and how often?",
            ])

    # --- log-type-specific additions ----------------------------------------
    if is_windows or (has_event_ids and not has_auth_actions and not has_web):
        questions.append("Summarize the suspicious process executions in this log")
        if has_parent:
            questions.append("Which parent process spawned the suspicious child processes?")
    if has_web:
        questions.append("Which request paths received the most errors?")
    if has_dns:
        questions.append("Which client queried the most unique domains?")

    # --- common closing questions -------------------------------------------
    for q in _COMMON_TAIL:
        questions.append(q)

    # Dedupe, preserve order, cap at 12.
    seen: set[str] = set()
    ordered: list[str] = []
    for q in questions:
        if q.lower() in seen:
            continue
        seen.add(q.lower())
        ordered.append(q)
        if len(ordered) >= 12:
            break
    return ordered
