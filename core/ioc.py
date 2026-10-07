from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

# IOC extraction is deliberately deterministic and conservative.  It identifies
# observable values; it does not decide whether an IOC is malicious.
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
URL_RE = re.compile(r"https?://[^\s<>'\"`]+", re.I)
HASH_RE = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])"
)
DOMAIN_RE = re.compile(
    r"(?<![@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w])"
)
# Domain syntax alone is not enough for log data: Linux shared libraries,
# service names and package namespaces frequently look like domains.
BLOCKED_DOMAIN_SUFFIXES = {
    "so", "dll", "exe", "bin", "service", "socket", "target",
    "conf", "cfg", "ini", "json", "log", "txt", "xml", "yaml", "yml",
}

IOC_TYPES = ("ipv4", "domain", "url", "hash", "username", "process")
IOC_TYPE_LABELS = {
    "ipv4": "IPv4",
    "domain": "Domain",
    "url": "URL",
    "hash": "Hash",
    "username": "Username",
    "process": "Process",
}
HASH_ALGORITHMS = {32: "MD5", 40: "SHA1", 64: "SHA256"}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _event_ref(event: dict[str, Any]) -> dict[str, Any]:
    """Return a stable, human-readable pointer back to the source event."""
    return {
        "evidence_id": _text(event.get("evidence_id")),
        "line": event.get("line", ""),
        "timestamp": _text(event.get("timestamp")),
    }


def _iter_event_text(events: Iterable[dict[str, Any]]):
    # Keep the extraction scope explicit. Generic JSON source fields are
    # already normalized into these fields by the parsers.
    fields = (
        "source_ip", "destination_ip", "username", "process_name",
        "command", "message", "raw_log", "url", "uri", "query_name",
        "hashes",
    )
    for event in events:
        field_values: dict[str, str] = {}
        for key in fields:
            value = _text(event.get(key))
            if value:
                field_values[key] = value
        yield field_values, event


def _looks_like_domain(value: str) -> bool:
    """Reject common non-domain tokens that happen to contain a dot."""
    normalized = value.lower().rstrip(".")
    labels = normalized.split(".")
    if len(labels) < 2:
        return False
    suffix = labels[-1]
    if suffix in BLOCKED_DOMAIN_SUFFIXES:
        return False
    # Shared-library / binary names and Linux service/package namespaces are
    # common false positives. A hostname label cannot contain an underscore.
    if any("_" in label for label in labels):
        return False
    if any(label in {"org", "com", "net", "edu"} for label in labels[:-1]) and len(labels) == 2:
        # e.g. org.freedesktop / com.redhat: these are namespaces, not FQDNs.
        return False
    if any(label.endswith((".so", ".dll", ".exe")) for label in labels):
        return False
    return True


def _process_is_investigative_ioc(event: dict[str, Any]) -> bool:
    """Only promote a process into the IOC inventory when context is suspicious.

    Ordinary process names are event metadata, not indicators. Promotion is
    deliberately narrow and deterministic; it is not a malware verdict.
    """
    process = _text(event.get("process_name")).lower()
    context = " ".join(_text(event.get(k)) for k in ("command", "message", "raw_log")).lower()
    if not process or not context:
        return False
    suspicious_markers = (
        " -e ", " --exec", " /bin/sh", " /bin/bash", " /bin/zsh",
        "powershell", "cmd.exe", "nc -", "ncat ", "socat ",
        "python -c", "perl -e", "ruby -e", "bash -c", "sh -c",
        "| /bin/", "&& /bin/", "; /bin/",
    )
    return any(marker in f" {context} " for marker in suspicious_markers)


def _touch(
    bucket: dict[str, dict[str, Any]],
    key: str,
    *,
    event: dict[str, Any],
    source_fields: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = bucket.setdefault(
        key,
        {
            "value": key,
            "occurrences": 0,
            "evidence_ids": [],
            "timestamps": [],
            "event_refs": [],
            "source_fields": [],
        },
    )
    record["occurrences"] += 1

    ref = _event_ref(event)
    if ref not in record["event_refs"]:
        record["event_refs"].append(ref)

    evidence_id = ref["evidence_id"]
    # Old callers use line:<n> as a deterministic source reference when the
    # event has not yet been promoted into the EvidenceStore.
    if not evidence_id:
        evidence_id = f"line:{ref['line']}"
    if evidence_id and evidence_id not in record["evidence_ids"]:
        record["evidence_ids"].append(evidence_id)

    timestamp = ref["timestamp"]
    if timestamp and timestamp not in record["timestamps"]:
        record["timestamps"].append(timestamp)

    for field in source_fields:
        if field not in record["source_fields"]:
            record["source_fields"].append(field)

    if extra:
        record.update(extra)
    return record


def extract_iocs(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Extract deterministic IOCs and preserve source-event relationships.

    Returned records contain:
      - value / occurrences
      - evidence_ids / event_refs
      - timestamps / source_fields
      - IP privacy scope or hash algorithm where applicable

    No threat-intelligence or maliciousness claim is made by extraction alone.
    """
    buckets: dict[str, dict[str, dict[str, Any]]] = {
        key: {} for key in IOC_TYPES
    }

    for field_values, event in _iter_event_text(events):
        all_text = " ".join(field_values.values())
        all_source_fields = list(field_values)

        for raw in IP_RE.findall(all_text):
            if _valid_ip(raw):
                _touch(
                    buckets["ipv4"], raw, event=event,
                    source_fields=all_source_fields,
                    extra={"private": _is_private(raw)},
                )

        # URLs may occur in commands/messages/raw logs. Do not use the
        # process_name field as an extraction source.
        for field, text in field_values.items():
            if field == "process_name":
                continue
            for raw in URL_RE.findall(text):
                raw = raw.rstrip(".,);]")
                _touch(buckets["url"], raw, event=event, source_fields=[field])

        for raw in HASH_RE.findall(all_text):
            normalized = raw.lower()
            _touch(
                buckets["hash"], normalized, event=event,
                source_fields=all_source_fields,
                extra={"algorithm": HASH_ALGORITHMS.get(len(raw), "UNKNOWN")},
            )

        # Domain extraction is field-aware. In particular, process_name is
        # excluded because values such as ld-linux-x86-64.so are binaries,
        # not domains.
        for field, text in field_values.items():
            if field == "process_name":
                continue
            for raw in DOMAIN_RE.findall(text):
                if _looks_like_domain(raw):
                    normalized = raw.lower().rstrip(".")
                    _touch(buckets["domain"], normalized, event=event, source_fields=[field])

        user = _text(event.get("username"))
        if user:
            _touch(
                buckets["username"],
                user,
                event=event,
                source_fields=["username"],
            )

        process = _text(event.get("process_name"))
        if process and _process_is_investigative_ioc(event):
            _touch(
                buckets["process"], process, event=event,
                source_fields=["process_name"],
                extra={"ioc_context": "suspicious execution context"},
            )

    return {
        key: sorted(
            records.values(),
            key=lambda item: (-int(item.get("occurrences", 0)), str(item.get("value", "")).lower()),
        )
        for key, records in buckets.items()
    }


def summarize_iocs(iocs: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    return {key: len(iocs.get(key, [])) for key in IOC_TYPES}


def flatten_iocs(iocs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Flatten the grouped IOC inventory for tables, search and export."""
    rows = []
    for ioc_type in IOC_TYPES:
        for record in iocs.get(ioc_type, []) or []:
            row = dict(record)
            row["type"] = ioc_type
            row["type_label"] = IOC_TYPE_LABELS[ioc_type]
            rows.append(row)
    return rows


def filter_iocs(
    iocs: dict[str, list[dict[str, Any]]],
    *,
    query: str = "",
    ioc_type: str = "All",
) -> list[dict[str, Any]]:
    """Search the current IOC inventory without re-running extraction."""
    query = _text(query).lower()
    normalized_type = _text(ioc_type).lower()

    if normalized_type in IOC_TYPE_LABELS:
        allowed = {normalized_type}
    elif normalized_type in {label.lower() for label in IOC_TYPE_LABELS.values()}:
        allowed = {
            key for key, label in IOC_TYPE_LABELS.items()
            if label.lower() == normalized_type
        }
    else:
        allowed = set(IOC_TYPES)

    rows = []
    for row in flatten_iocs(iocs):
        if row["type"] not in allowed:
            continue
        if query:
            searchable = " ".join(
                [
                    str(row.get("value", "")),
                    str(row.get("algorithm", "")),
                    " ".join(row.get("source_fields", []) or []),
                    " ".join(row.get("evidence_ids", []) or []),
                ]
            ).lower()
            if query not in searchable:
                continue
        rows.append(row)

    return sorted(
        rows,
        key=lambda item: (
            -int(item.get("occurrences", 0)),
            item.get("type_label", ""),
            str(item.get("value", "")).lower(),
        ),
    )


def find_ioc(
    iocs: dict[str, list[dict[str, Any]]],
    ioc_type: str,
    value: str,
) -> dict[str, Any] | None:
    """Return one IOC record using exact, normalized matching."""
    target_type = _text(ioc_type).lower()
    target_value = _text(value)
    if target_type not in IOC_TYPES:
        for key, label in IOC_TYPE_LABELS.items():
            if label.lower() == target_type:
                target_type = key
                break

    for record in iocs.get(target_type, []) or []:
        current = _text(record.get("value"))
        if target_type in {"domain", "hash"}:
            if current.lower() == target_value.lower():
                return record
        elif current == target_value:
            return record
    return None
