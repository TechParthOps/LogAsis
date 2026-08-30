from __future__ import annotations

import re
from typing import Any

import pandas as pd

from core.analytics import investigation_candidates, peak_hour, summary


_SUSPICIOUS_COMMAND_PATTERNS = (
    (r"powershell(?:\.exe)?", "PowerShell execution"),
    (r"(?i)(?:^|\s)-enc(?:odedcommand)?(?:\s|$)", "Encoded PowerShell command"),
    (r"(?i)(?:cmd(?:\.exe)?|command\.com)", "Command shell execution"),
    (r"(?i)(?:certutil(?:\.exe)?|bitsadmin(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?)", "Living-off-the-land utility"),
    (r"(?i)(?:wget|curl)\s+", "Command-line download/transfer utility"),
    (r"(?i)(?:/bin/(?:ba)?sh|/bin/zsh|/usr/bin/sudo)", "Unix shell/privileged execution"),
)

_SUSPICIOUS_PATH_PATTERNS = (
    (r"(?i)\\(?:users\\[^\\]+\\)?appdata\\local\\temp\\", "Executable under Windows Temp/AppData"),
    (r"(?i)(?:/tmp/|/var/tmp/)", "Executable or file under temporary directory"),
    (r"(?i)\\downloads\\", "Execution from Downloads directory"),
)

_SUSPICIOUS_URL_PATTERN = re.compile(
    r"(?i)(?:\.\./|%2e|union(?:\+|%20)select|<script|/etc/passwd|cmd=|powershell)"
)


def _text(row: pd.Series, *columns: str) -> str:
    parts = []
    for column in columns:
        value = row.get(column, "")
        if value is not None and not pd.isna(value):
            text = str(value).strip()
            if text:
                parts.append(text)
    return " ".join(parts)


def _score_event(row: pd.Series, context: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    severity = str(row.get("severity", "") or "").lower()
    severity_points = {"critical": 40, "high": 30, "medium": 10}
    if severity in severity_points:
        score += severity_points[severity]
        reasons.append(f"{severity.title()} log severity")

    action = str(row.get("action", "") or "").lower()
    event_type = str(row.get("event_type", "") or "").lower()
    event_id = str(row.get("event_id", "") or "").strip()
    command = _text(row, "command", "process_name", "parent_command")
    path_text = _text(row, "process_name", "command", "parent_image", "parent_command")
    message = _text(row, "message", "raw_log")
    web_text = _text(row, "url", "uri", "query", "request", "message")

    if action == "failed_login" or "failed login" in event_type:
        score += 25
        reasons.append("Failed authentication attempt")

        ip = str(row.get("source_ip", "") or "").strip()
        failed_by_ip = context.get("failed_by_ip", {}).get(ip, 0)
        if ip and failed_by_ip >= 10:
            score += 20
            reasons.append(f"Repeated failures from {ip} ({failed_by_ip} attempts)")

    if action in {"process_create", "command_exec"} or event_id == "1" or "processcreate" in event_type:
        score += 5
        reasons.append("Process/command execution event")

    if event_id == "3" or "network" in event_type:
        score += 5
        reasons.append("Network activity")

    for pattern, reason in _SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command):
            score += 15
            reasons.append(reason)

    for pattern, reason in _SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, path_text):
            score += 20
            reasons.append(reason)

    if _SUSPICIOUS_URL_PATTERN.search(web_text):
        score += 25
        reasons.append("Suspicious URL/request pattern")

    if row.get("destination_ip", "") not in ("", None) and not pd.isna(row.get("destination_ip", "")):
        score += 3
        reasons.append("External/network destination present")

    if row.get("hashes", "") not in ("", None) and not pd.isna(row.get("hashes", "")):
        score += 2
        reasons.append("File hash available for verification")

    # Do not let a huge raw message by itself make an event suspicious.
    if "access denied" in message.lower() and action not in {"failed_login", "failed"}:
        score += 10
        reasons.append("Access denied indicator")

    if score >= 60:
        priority = "CRITICAL"
    elif score >= 35:
        priority = "HIGH"
    elif score >= 15:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    # De-duplicate reasons while preserving order.
    reasons = list(dict.fromkeys(reasons))
    return {
        "score": int(score),
        "priority": priority,
        "reasons": reasons,
    }


def investigation_events(df: pd.DataFrame, minimum_score: int = 15) -> list[dict[str, Any]]:
    """Return deterministic, explainable investigation candidates.

    The scoring is deliberately local and rule-based. It does not claim that an
    event is malicious; it ranks events that deserve analyst attention.
    """
    if df.empty:
        return []

    failed_by_ip: dict[str, int] = {}
    if "action" in df.columns and "source_ip" in df.columns:
        failed = df[df["action"].astype(str).str.lower() == "failed_login"]
        for ip, count in failed["source_ip"].replace("", pd.NA).dropna().value_counts().items():
            failed_by_ip[str(ip)] = int(count)

    context = {"failed_by_ip": failed_by_ip}
    results: list[dict[str, Any]] = []

    for _, row in df.iterrows():
        scored = _score_event(row, context)
        if scored["score"] < minimum_score:
            continue

        results.append({
            "line": int(row.get("line", 0) or 0),
            "timestamp": str(row.get("timestamp", "") or ""),
            "event_type": str(row.get("event_type", "") or ""),
            "event_id": str(row.get("event_id", "") or ""),
            "priority": scored["priority"],
            "score": scored["score"],
            "source_ip": str(row.get("source_ip", "") or ""),
            "destination_ip": str(row.get("destination_ip", "") or ""),
            "username": str(row.get("username", "") or ""),
            "process_name": str(row.get("process_name", "") or ""),
            "command": str(row.get("command", "") or ""),
            "parent_image": str(row.get("parent_image", "") or ""),
            "parent_command": str(row.get("parent_command", "") or ""),
            "destination_port": str(row.get("destination_port", "") or ""),
            "hashes": str(row.get("hashes", "") or ""),
            "action": str(row.get("action", "") or ""),
            "severity": str(row.get("severity", "") or ""),
            "message": str(row.get("message", "") or ""),
            "reasons": scored["reasons"],
        })

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda item: (
        priority_order.get(item["priority"], 9),
        -item["score"],
        item["line"],
    ))
    return results


def build_event_investigation(row: pd.Series, context_df: pd.DataFrame | None = None) -> dict[str, Any]:
    """Build a human-readable evidence package for one selected event."""
    context = {}
    if context_df is not None and not context_df.empty:
        failed_by_ip: dict[str, int] = {}
        if "action" in context_df.columns and "source_ip" in context_df.columns:
            failed = context_df[
                context_df["action"].astype(str).str.lower() == "failed_login"
            ]
            for ip, count in failed["source_ip"].replace("", pd.NA).dropna().value_counts().items():
                failed_by_ip[str(ip)] = int(count)
        context["failed_by_ip"] = failed_by_ip

    scored = _score_event(row, context)
    fields = {
        "Timestamp": row.get("timestamp", ""),
        "Event Type": row.get("event_type", ""),
        "Event ID": row.get("event_id", ""),
        "Source IP": row.get("source_ip", ""),
        "Destination IP": row.get("destination_ip", ""),
        "Destination Port": row.get("destination_port", ""),
        "User": row.get("username", ""),
        "Process": row.get("process_name", ""),
        "Command": row.get("command", ""),
        "Parent Process": row.get("parent_image", ""),
        "Parent Command": row.get("parent_command", ""),
        "PID": row.get("pid", ""),
        "PPID": row.get("ppid", ""),
        "Action": row.get("action", ""),
        "Log Severity": row.get("severity", ""),
        "Hashes": row.get("hashes", ""),
        "Record": row.get("line", ""),
    }
    fields = {
        key: ("N/A" if value is None or pd.isna(value) or str(value).strip() == "" else str(value))
        for key, value in fields.items()
    }

    return {
        "score": scored["score"],
        "priority": scored["priority"],
        "reasons": scored["reasons"] or ["No deterministic suspicious indicator matched."],
        "fields": fields,
        "message": str(row.get("message", "") or "").strip(),
        "raw_log": str(row.get("raw_log", "") or ""),
    }


def build_investigation_report(df):
    stats = summary(df)
    candidates = investigation_candidates(df)

    scored_events = investigation_events(df)

    report = {
        "summary": stats,
        "peak_hour": peak_hour(df),
        "candidate_ips": candidates["candidate_ips"],
        "candidate_users": candidates["candidate_users"],
        "suspicious_sequences": candidates["suspicious_sequences"],
        "investigation_events": scored_events,
        "critical_count": sum(e["priority"] == "CRITICAL" for e in scored_events),
        "high_count": sum(e["priority"] == "HIGH" for e in scored_events),
        "medium_count": sum(e["priority"] == "MEDIUM" for e in scored_events),
    }

    return report
