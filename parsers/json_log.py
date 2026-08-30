from __future__ import annotations

import json
import re
from typing import Any


# Common Windows/Sysmon field aliases. The parser keeps the original JSON fields
# as well, while normalising the fields used by LogAsis analytics and AI.
ALIASES = {
    "timestamp": ("UtcTime", "UTCTime", "Timestamp", "TimeCreated", "time", "timestamp", "EventTime"),
    "event_id": ("EventID", "EventId", "event_id", "eventId", "id"),
    "event_type": ("EventType", "event_type", "Channel", "Provider", "RuleName", "event_type_name"),
    "source_ip": ("SourceIp", "SourceIP", "src_ip", "srcIp", "SourceAddress", "ClientAddress", "IpAddress", "src"),
    "destination_ip": ("DestinationIp", "DestinationIP", "dst_ip", "dstIp", "DestinationAddress", "dest"),
    "source_port": ("SourcePort", "src_port", "srcPort"),
    "destination_port": ("DestinationPort", "dst_port", "dstPort"),
    "parent_image": ("ParentImage", "ParentProcessName", "ParentExecutable", "ParentImageName"),
    "parent_command": ("ParentCommandLine", "ParentCommand", "ParentProcessCommandLine"),
    "protocol": ("Protocol", "protocol"),
    "hashes": ("Hashes", "hashes", "Hash"),
    "rule_name": ("RuleName", "rule_name", "Rule"),
    "username": ("User", "UserName", "Username", "TargetUserName", "SubjectUserName", "AccountName", "user", "username"),
    "process_name": ("Image", "ProcessName", "process_name", "Executable", "Application", "ImageName"),
    "command": ("CommandLine", "command", "Command", "ProcessCommandLine", "cmdline"),
    "pid": ("ProcessId", "ProcessID", "pid", "NewProcessId"),
    "ppid": ("ParentProcessId", "ParentProcessID", "ppid"),
    "action": ("Action", "action", "EventType", "Operation", "Status"),
    "severity": ("Severity", "Level", "severity", "RiskLevel"),
    "message": ("Message", "message", "Description", "EventDescription"),
}


def _norm_key(key: Any) -> str:
    text = str(key).strip()
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "field"


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = _norm_key(key)
            full = f"{prefix}_{name}" if prefix else name
            if isinstance(child, dict):
                out.update(_flatten(child, full))
            elif isinstance(child, list):
                if all(isinstance(item, dict) for item in child):
                    for idx, item in enumerate(child):
                        out.update(_flatten(item, f"{full}_{idx}"))
                else:
                    out[full] = ", ".join(str(x) for x in child)
            else:
                out[full] = child
    else:
        out[prefix or "value"] = value
    return out


def _find_value(flat: dict[str, Any], aliases: tuple[str, ...]) -> str:
    lower = {str(k).lower(): v for k, v in flat.items()}
    for alias in aliases:
        key = alias.lower()
        if key in lower and lower[key] not in (None, ""):
            return str(lower[key])
    # Also match suffixes such as EventData_CommandLine.
    for alias in aliases:
        key = alias.lower()
        for candidate, value in lower.items():
            if candidate.endswith("_" + key) and value not in (None, ""):
                return str(value)
    return ""


def _load_records(text: str) -> list[dict[str, Any]]:
    """Load JSON event records from arrays, wrappers, NDJSON and nested exports."""
    stripped = text.lstrip("\ufeff \t\r\n")
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []

        # NDJSON: one JSON value per line.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
            elif isinstance(value, list):
                records.extend(item for item in value if isinstance(item, dict))
        if records:
            return records

        # Concatenated / pretty-printed JSON objects.
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(stripped):
            while pos < len(stripped) and stripped[pos].isspace():
                pos += 1
            if pos >= len(stripped):
                break
            try:
                value, end = decoder.raw_decode(stripped, pos)
            except json.JSONDecodeError:
                pos += 1
                continue
            if isinstance(value, dict):
                records.append(value)
            elif isinstance(value, list):
                records.extend(item for item in value if isinstance(item, dict))
            pos = end
        return records

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if not isinstance(data, dict):
        return []

    # Prefer explicit event-list wrappers.
    wrapper_keys = (
        "events", "Events", "event", "Event", "records", "Records",
        "data", "Data", "items", "Items", "results", "Results",
        "logs", "Logs", "entries", "Entries",
    )
    for key in wrapper_keys:
        value = data.get(key)
        if isinstance(value, list):
            items = [item for item in value if isinstance(item, dict)]
            if items:
                return items

    # Find the largest nested list of dictionaries. This handles exports such
    # as {"Events": {"Event": [{...}, {...}]}}.
    candidates: list[list[dict[str, Any]]] = []

    def find_lists(node: Any):
        if isinstance(node, dict):
            for child in node.values():
                if isinstance(child, list):
                    items = [x for x in child if isinstance(x, dict)]
                    if items:
                        candidates.append(items)
                if isinstance(child, (dict, list)):
                    find_lists(child)
        elif isinstance(node, list):
            for child in node:
                if isinstance(child, (dict, list)):
                    find_lists(child)

    find_lists(data)
    if candidates:
        return max(candidates, key=len)

    # A single event object is still one event.
    return [data]


def _event_type(flat: dict[str, Any]) -> str:
    event_id = _find_value(flat, ALIASES["event_id"])
    channel = _find_value(flat, ("Channel", "channel"))
    provider = _find_value(flat, ("Provider", "provider"))
    if event_id:
        return f"EventID {event_id}"
    if channel:
        return channel
    return provider or "json"


def _action(flat: dict[str, Any], event_type: str) -> str:
    explicit = _find_value(flat, ALIASES["action"]).lower()
    if explicit in {"failed", "failure", "fail", "denied", "blocked"}:
        return "failed"
    if explicit in {"success", "successful", "allowed", "accepted"}:
        return "success"
    text = " ".join(str(v) for v in flat.values()).lower()
    if any(x in text for x in ("failed password", "authentication failure", "logon failure", "access denied")):
        return "failed_login"
    if any(x in text for x in ("accepted password", "successful logon", "logon success")):
        return "successful_login"
    if event_type.lower() in {"processcreate", "process_creation"} or "process create" in text:
        return "process_create"
    return explicit


def parse_json_log(text: str) -> list[dict[str, Any]]:
    records = _load_records(text)
    events: list[dict[str, Any]] = []
    for line_no, record in enumerate(records, start=1):
        flat = _flatten(record)
        event_type = _event_type(flat)
        normalized = {
            "timestamp": _find_value(flat, ALIASES["timestamp"]),
            "event_type": event_type,
            "event_id": _find_value(flat, ALIASES["event_id"]),
            "source_ip": _find_value(flat, ALIASES["source_ip"]),
            "source_port": _find_value(flat, ALIASES["source_port"]),
            "destination_ip": _find_value(flat, ALIASES["destination_ip"]),
            "destination_port": _find_value(flat, ALIASES["destination_port"]),
            "username": _find_value(flat, ALIASES["username"]),
            "process_name": _find_value(flat, ALIASES["process_name"]),
            "command": _find_value(flat, ALIASES["command"]),
            "parent_image": _find_value(flat, ALIASES["parent_image"]),
            "parent_command": _find_value(flat, ALIASES["parent_command"]),
            "rule_name": _find_value(flat, ALIASES["rule_name"]),
            "hashes": _find_value(flat, ALIASES["hashes"]),
            "protocol": _find_value(flat, ALIASES["protocol"]),
            "pid": _find_value(flat, ALIASES["pid"]),
            "ppid": _find_value(flat, ALIASES["ppid"]),
            "uid": _find_value(flat, ("uid", "UserId")),
            "euid": _find_value(flat, ("euid", "EffectiveUserId")),
            "auid": _find_value(flat, ("auid", "AuditUserId")),
            "audit_serial": _find_value(flat, ("audit_serial", "serial", "Serial")),
            "audit_session": _find_value(flat, ("audit_session", "session_id", "sessionid", "ses", "SessionId", "SessionID")),
            "action": _action(flat, event_type),
            "severity": _find_value(flat, ALIASES["severity"]).lower(),
            "message": _find_value(flat, ALIASES["message"]),
            "line": line_no,
            "raw_log": json.dumps(record, ensure_ascii=False),
        }
        # Preserve every source field for type-specific tables and investigation.
        normalized.update(flat)
        # JSON exports (Sysmon, EVTX-to-JSON, etc.) rarely carry an explicit
        # Message/Description field the way plain-text/audit logs do -- for
        # those, message is left empty above. Without this, evidence
        # retrieval scoring (ai/context.py:_event_text), which searches a
        # fixed set of common fields, has nothing to full-text search for
        # anything living in a JSON-specific field (TargetFilename, Hashes,
        # Details, Signature, etc.), so those events become effectively
        # invisible to retrieval even though the data is present. Synthesize
        # a readable fallback message from every populated field so JSON logs
        # get the same full-text searchability plain-text logs get for free
        # from their raw line.
        if not normalized["message"]:
            normalized["message"] = "; ".join(
                f"{k}={v}" for k, v in flat.items()
                if str(v).strip() and str(v).strip().lower() not in {"nan", "none", "null"}
            )[:2000]
        events.append(normalized)
    return events


class JsonLogParser:
    def parse(self, text: str):
        return parse_json_log(text)
