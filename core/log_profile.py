from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+")

JSON_WRAPPER_KEYS = (
    "events", "event", "records", "record", "data", "items", "results",
    "logs", "log", "entries", "documents", "hits",
)

SYSMON_MARKERS = {
    "eventid", "event_id", "image", "commandline", "parentimage",
    "parentcommandline", "destinationip", "destinationport", "sourceip",
    "sourceport", "processid", "parentprocessid", "rulename",
    "hashes", "protocol",
}

WINDOWS_MARKERS = {
    "channel", "provider", "timecreated", "computer", "eventdata",
    "system", "security", "execution", "level",
}


def _norm_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def _collect_dicts(value: Any, limit: int = 200) -> list[dict[str, Any]]:
    """Collect representative dictionaries from arbitrarily nested JSON."""
    found: list[dict[str, Any]] = []

    def walk(node: Any):
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            found.append(node)
            for child in node.values():
                if len(found) >= limit:
                    break
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                if len(found) >= limit:
                    break
                if isinstance(child, (dict, list)):
                    walk(child)

    walk(value)
    return found


def _json_records(text: str) -> list[dict[str, Any]]:
    """Extract event-like JSON objects from arrays, wrappers, NDJSON and concatenated JSON."""
    stripped = text.lstrip("\ufeff \t\r\n")
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        # First try NDJSON.
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
            return records[:200]

        # Then support concatenated / pretty-printed JSON values.
        decoder = json.JSONDecoder()
        pos = 0
        length = len(stripped)
        while pos < length:
            while pos < length and stripped[pos].isspace():
                pos += 1
            if pos >= length:
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
        return records[:200]

    # Standard top-level array.
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)][:200]

    # Common wrappers, including wrappers whose event list is nested one level
    # below Event/Events/Data/etc.
    if isinstance(data, dict):
        for key in JSON_WRAPPER_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                dict_items = [item for item in value if isinstance(item, dict)]
                if dict_items:
                    return dict_items[:200]
            if isinstance(value, dict):
                nested = _collect_dicts(value, 200)
                if nested:
                    return nested[:200]

        # Find the largest list of dictionaries anywhere in the object.
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
            return max(candidates, key=len)[:200]

        return [data]

    return []


def _representative_keys(records: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for record in records[:50]:
        for item in _collect_dicts(record, 30):
            keys.update(_norm_key(k) for k in item.keys())
    return keys


def detect_log_profile(path: str, text: str) -> dict[str, str]:
    suffix = Path(path).suffix.lower()
    sample = text[:10000]

    if suffix in {".json", ".ndjson"} or sample.lstrip().startswith(("{", "[")):
        records = _json_records(text)
        keys = _representative_keys(records)
        blob = " ".join(json.dumps(r, ensure_ascii=False)[:3000].lower() for r in records[:20])

        sysmon_hits = len(keys & {_norm_key(k) for k in SYSMON_MARKERS})
        windows_hits = len(keys & {_norm_key(k) for k in WINDOWS_MARKERS})

        if sysmon_hits >= 2 or "sysmon" in blob:
            return {"id": "sysmon_json", "name": "Windows Sysmon JSON", "parser": "json"}
        if windows_hits >= 2 or any(k in keys for k in {"channel", "provider", "timecreated"}):
            return {"id": "windows_json", "name": "Windows Event JSON", "parser": "json"}
        return {"id": "generic_json", "name": "Generic JSON", "parser": "json"}

    nonempty = [line for line in sample.splitlines() if line.strip()][:20]
    syslog_hits = sum(bool(SYSLOG_RE.match(line)) for line in nonempty)
    if syslog_hits >= max(1, len(nonempty) // 3):
        return {"id": "syslog", "name": "Syslog / Linux Audit", "parser": "syslog"}

    return {"id": "generic_text", "name": "Generic Text Log", "parser": "syslog"}
