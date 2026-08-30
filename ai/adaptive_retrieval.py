from __future__ import annotations

"""Format-agnostic forensic retrieval.

This module deliberately does not contain question-specific handlers.  It uses
three things that are stable across log vendors:
  1. the user's language,
  2. the discovered field/schema names, and
  3. a small vendor-neutral security vocabulary.

The parser is responsible for preserving source fields; this layer decides
which records are relevant to an arbitrary investigation question.
"""

import re
from typing import Any

import pandas as pd


_STOP = {
    "what", "which", "where", "when", "why", "how", "does", "did", "is", "are", "was", "were",
    "the", "a", "an", "this", "that", "these", "those", "from", "with", "for", "to", "of", "in",
    "on", "at", "by", "and", "or", "as", "be", "been", "being", "can", "could", "would", "should",
    "please", "tell", "show", "give", "me", "there", "any", "all", "most", "important", "relevant",
    "evidence", "activity", "log", "logs", "event", "events", "associated", "observed", "attempts",
}

# Generic security vocabulary. This is intentionally about *observable log
# language*, not application business rules. It lets a phrase such as
# "reverse shell" find nc/TCPClient/dev-tcp even when those exact words are
# absent from the log.
_CONCEPTS: dict[str, tuple[str, ...]] = {
    "reverse shell": (
        "reverse-shell", "connect back", "callback", "nc", "ncat", "netcat", "socat",
        "/dev/tcp", "tcpclient", "socket", "bash -i", "sh -i", "powershell", "invoke-command",
    ),
    "bind shell": ("bind-shell", "nc", "ncat", "netcat", "socat", "listen", "-l", "-lvnp"),
    "shell": ("bash", "sh", "cmd.exe", "powershell", "pwsh", "zsh", "ksh", "nc", "ncat", "netcat", "socat"),
    "network": ("source_ip", "destination_ip", "source_port", "destination_port", "src_ip", "dst_ip", "socket", "connection", "connect"),
    "port": ("source_port", "destination_port", "src_port", "dst_port", "port", "tcp", "udp"),
    "account": ("username", "user", "account", "user_name", "targetusername", "subjectusername", "login", "authentication"),
    "user": ("username", "user", "account", "targetusername", "subjectusername", "acct"),
    "ip": ("source_ip", "destination_ip", "src_ip", "dst_ip", "remote_ip", "client_ip", "addr", "rhost"),
    "command": ("command", "commandline", "cmdline", "processcommandline", "execve", "command_exec"),
    "process": ("process", "process_name", "image", "parentimage", "pid", "processid", "executable"),
    "file": ("file", "filename", "targetfilename", "path", "objectname", "filepath", "file_name"),
    "registry": ("registry", "reg", "registrykey", "targetobject", "objectname", "registry.value", "hklm", "hkcu"),
    "domain": ("domain", "hostname", "host", "fqdn", "dns", "queryname"),
    "dns": ("dns", "queryname", "query", "domain", "hostname"),
    "download": ("download", "invoke-webrequest", "invoke-restmethod", "wget", "curl", "outfile", "url", "transfer"),
    "exfiltration": ("upload", "uploaded", "transfer", "scp", "sftp", "rsync", "curl", "wget", "ftp", "put", "stor"),
    "privilege": ("root", "uid=0", "euid=0", "sudo", "su", "pkexec", "doas", "setuid", "escalation"),
    "persistence": ("service", "scheduledtask", "run key", "registry", "startup", "cron", "at", "systemd"),
    "credential": ("password", "credential", "token", "hash", "ntlm", "kerberos", "ticket", "secret"),
    "authentication": ("login", "authentication", "auth", "accepted", "failed", "password", "session"),
    "process creation": ("processcreate", "process_creation", "process start", "newprocessid", "parentprocessid", "image"),
    # High-level risk language is generic security vocabulary, not an
    # application-specific question handler. It lets retrieval use explicit
    # severity/alert fields when a question asks about risk or findings.
    "risk": ("high", "critical", "severity", "risk", "alert", "finding"),
    "highest risk": ("high", "critical", "severity", "risk", "alert", "finding"),
    "compromised": ("successful_login", "accepted", "session", "authentication", "login"),
}

_FIELD_HINTS = {
    "ip": ("ip", "addr", "address", "host"),
    "port": ("port",),
    "user": ("user", "account", "acct", "principal"),
    "command": ("command", "cmd", "exec", "argv", "argument"),
    "process": ("process", "image", "executable", "binary", "pid"),
    "file": ("file", "filename", "path", "object", "target"),
    "registry": ("registry", "targetobject", "objectname", "key"),
    "domain": ("domain", "host", "hostname", "fqdn", "queryname"),
    "dns": ("dns", "query", "queryname"),
    "hash": ("hash", "sha", "md5", "sha1", "sha256"),
    "time": ("time", "timestamp", "date"),
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _tokens(text: str) -> list[str]:
    raw = re.findall(r"[A-Za-z0-9_./:-]{2,}", str(text or "").lower())
    return [x for x in raw if x not in _STOP]


def _field_tokens(name: str) -> set[str]:
    parts = re.findall(r"[a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", str(name).lower()))
    return set(parts)


def _concept_terms(question: str) -> list[str]:
    q = _norm(question)
    out: list[str] = []
    for phrase, terms in _CONCEPTS.items():
        if phrase in q or any(tok in q for tok in phrase.split()):
            for term in terms:
                if term not in out:
                    out.append(term)
    # Direct question tokens are always retained.
    for token in _tokens(q):
        if token not in out:
            out.append(token)
    return out[:120]


def infer_target_fields(df: pd.DataFrame, question: str) -> list[str]:
    """Infer likely answer-bearing fields from the live schema.

    No vendor field names are required: normalized names and arbitrary source
    fields are both considered.  The result is a ranking, not a hard filter.
    """
    if df is None or df.empty:
        return []
    q_tokens = set(_tokens(question))
    q_lower = _norm(question)
    ranked: list[tuple[float, str]] = []
    for col in df.columns:
        name = str(col)
        if name in {"timestamp_dt", "hour", "date", "raw_log"}:
            continue
        ft = _field_tokens(name)
        score = 0.0
        score += 5.0 * len(q_tokens & ft)
        for concept, hints in _FIELD_HINTS.items():
            if concept in q_lower or concept in q_tokens:
                score += 4.0 * sum(1 for h in hints if h in name.lower() or h in ft)
        # Prefer fields that actually contain values.
        try:
            nonempty = int(df[name].fillna("").astype(str).str.strip().ne("").sum())
            score += min(3.0, nonempty / max(1, len(df)) * 3.0)
        except Exception:
            pass
        # Do not treat mere presence of a value as evidence that a field answers
        # the question. A field needs meaningful schema/question overlap.
        if score >= 5.0:
            ranked.append((score, name))
    ranked.sort(key=lambda x: (-x[0], x[1].lower()))
    return [name for _, name in ranked[:20]]


def _row_blob(row: pd.Series) -> str:
    parts = []
    for key in row.index:
        if str(key) in {"timestamp_dt", "hour", "date", "raw_log"}:
            continue
        value = row.get(key, "")
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"nan", "nat", "none"}:
            parts.append(f"{key}={text}")
    return " ".join(parts).lower()



def _source_value(row: pd.Series, canonical: str) -> str:
    """Read a normalized field or an arbitrary vendor/source alias."""
    aliases = {
        "source_ip": ("source_ip", "SourceIp", "SourceIP", "src_ip", "srcIp", "SourceAddress", "ClientAddress", "addr", "rhost"),
        "destination_ip": ("destination_ip", "DestinationIp", "DestinationIP", "dst_ip", "dstIp", "DestinationAddress", "dest"),
        "source_port": ("source_port", "SourcePort", "src_port", "srcPort"),
        "destination_port": ("destination_port", "DestinationPort", "dst_port", "dstPort"),
        "username": ("username", "UserName", "Username", "User", "TargetUserName", "SubjectUserName", "AccountName", "acct"),
        "process_name": ("process_name", "ProcessName", "Image", "Executable", "Application"),
        "command": ("command", "CommandLine", "Command", "ProcessCommandLine", "cmdline"),
        "pid": ("pid", "ProcessId", "ProcessID", "NewProcessId"),
        "ppid": ("ppid", "ParentProcessId", "ParentProcessID"),
    }
    names = aliases.get(canonical, (canonical,))
    lowered = {str(k).lower(): k for k in row.index}
    for alias in names:
        key = lowered.get(alias.lower())
        if key is not None:
            value = row.get(key, "")
            if value is not None and str(value).strip().lower() not in {"", "nan", "none", "nat"}:
                return str(value)
    # Handle flattened JSON fields such as EventData_DestinationPort.
    for key in row.index:
        key_text = str(key).lower()
        if any(key_text.endswith("_" + alias.lower()) for alias in names):
            value = row.get(key, "")
            if value is not None and str(value).strip().lower() not in {"", "nan", "none", "nat"}:
                return str(value)
    return ""

def _numeric_port(value: Any) -> bool:
    text = str(value or "").strip()
    if not text.isdigit():
        return False
    try:
        return 0 < int(text) <= 65535
    except ValueError:
        return False


def score_row(row: pd.Series, question: str, target_fields: list[str] | None = None) -> float:
    q_tokens = _tokens(question)
    qset = set(q_tokens)
    q = _norm(question)
    concepts = _concept_terms(q)
    blob = _row_blob(row)
    score = 0.0

    # Exact phrase and token relevance.
    if q and q in blob:
        score += 40
    for token in q_tokens:
        if token in blob:
            score += 4

    # Security concept matches are stronger than generic words.
    for term in concepts:
        if len(term) >= 3 and term in blob:
            score += 7

    # The question's likely answer-bearing field gets a substantial boost.
    for field in target_fields or []:
        value = row.get(field, "")
        if value is None or not str(value).strip():
            continue
        ft = _field_tokens(field)
        overlap = len(qset & ft)
        score += 9 + min(9, overlap * 3)
        if "port" in qset and "port" in field.lower() and _numeric_port(value):
            score += 22

    # Preserve explicit network/shell relationships without assuming a format.
    if "port" in qset:
        port_values = []
        for key in row.index:
            if "port" in str(key).lower() and _numeric_port(row.get(key, "")):
                port_values.append(str(row.get(key)).strip())
        if port_values:
            score += 18

    if "reverse" in qset and "shell" in qset:
        if re.search(r"\b(?:nc|ncat|netcat|socat)\b|/dev/tcp|tcpclient|bash\s+-i|sh\s+-i|powershell.*socket|cmd\.exe", blob, re.I):
            score += 70
    if "shell" in qset and re.search(r"\b(?:bash|sh|cmd(?:\.exe)?|powershell|pwsh|nc|ncat|netcat|socat)\b", blob, re.I):
        score += 25

    return score


def adaptive_retrieve(df: pd.DataFrame, question: str, max_events: int = 40) -> dict[str, Any]:
    """Return a deterministic, schema-aware evidence bundle for any question."""
    if df is None or df.empty:
        return {
            "method": "adaptive-schema-aware-v1",
            "target_fields": [], "query_terms": _tokens(question),
            "seed_candidates": 0, "expanded_candidates": 0,
            "selected_evidence_ids": [], "evidence_records": [],
        }

    target_fields = infer_target_fields(df, question)
    scored: list[tuple[float, int, pd.Series]] = []
    for pos, (_, row) in enumerate(df.iterrows()):
        score = score_row(row, question, target_fields)
        if score > 0:
            scored.append((score, pos, row))

    scored.sort(key=lambda x: (-x[0], x[1]))
    seed_count = len(scored)

    # Select a dynamic relevance band instead of every row with score > 0.
    # A focused question with a clear best match should not drag routine rows
    # into the model context just because they share generic words such as
    # "user" or "process". Conversely, a question with several equally strong
    # matches keeps all of those matches. No question-specific intent is used.
    if scored:
        best = float(scored[0][0])
        if len(scored) == 1:
            selected = scored[:max(1, int(max_events))]
        else:
            # Keep records in roughly the strongest 78% of the score range.
            # A small absolute floor prevents weak lexical noise from becoming
            # evidence when the best match is itself modest.
            threshold = max(8.0, best * 0.81)
            focused = [item for item in scored if float(item[0]) >= threshold]
            # If the score distribution is genuinely flat, do not discard the
            # available evidence merely because of the ratio threshold.
            if len(focused) == 0:
                focused = scored[:1]
            selected = focused[:max(1, int(max_events))]
    else:
        selected = []

    # Context expansion is relationship-based and format agnostic. It brings in
    # neighboring events sharing a process/user/IP or occurring close in time.
    selected_positions = {p for _, p, _ in selected}
    anchor_rows = [row for _, _, row in selected[:8]]
    # Relationship expansion is useful when several strong anchors exist.
    # If retrieval has identified a single clear answer-bearing record, expanding
    # by shared username/process/IP would reintroduce unrelated routine events.
    if anchor_rows and len(selected) > 1 and len(selected) < max_events:
        for pos, (_, row) in enumerate(df.iterrows()):
            if pos in selected_positions:
                continue
            related = False
            for anchor in anchor_rows:
                for field in ("source_ip", "destination_ip", "username", "process_name", "pid", "ppid"):
                    a, b = _norm(anchor.get(field, "")), _norm(row.get(field, ""))
                    if a and b and a == b:
                        related = True
                        break
                if related:
                    break
            if related:
                selected.append((max(1.0, score_row(row, question, target_fields) * 0.45), pos, row))
                selected_positions.add(pos)
                if len(selected) >= max_events:
                    break

    records = []
    for score, pos, row in selected[:max_events]:
        source_fields = {}
        for key in row.index:
            if str(key) in {"timestamp_dt", "hour", "date", "raw_log"}:
                continue
            value = row.get(key, "")
            if value is None:
                continue
            text = str(value).strip()
            if text and text.lower() not in {"nan", "nat", "none"}:
                source_fields[str(key)] = text[:700]
        records.append({
            "evidence_id": f"EVID-{pos + 1:03d}",
            "source_position": int(pos),
            "text": _row_text_fallback(row),
            "line": str(row.get("line", "")),
            "source_fields": source_fields,
            "timestamp": str(row.get("timestamp", "")),
            "event_type": str(row.get("event_type", "")),
            "action": str(row.get("action", "")),
            "severity": str(row.get("severity", "")),
            "source_ip": _source_value(row, "source_ip"),
            "destination_ip": _source_value(row, "destination_ip"),
            "source_port": _source_value(row, "source_port"),
            "destination_port": _source_value(row, "destination_port"),
            "username": _source_value(row, "username"),
            "process_name": _source_value(row, "process_name"),
            "command": _source_value(row, "command")[:500],
            "pid": _source_value(row, "pid"),
            "ppid": _source_value(row, "ppid"),
            "uid": str(row.get("uid", "")),
            "euid": str(row.get("euid", "")),
            "_retrieval_score": round(float(score), 3),
        })

    return {
        "method": "adaptive-schema-aware-v1",
        "target_fields": target_fields,
        "query_terms": _concept_terms(question)[:30],
        "seed_candidates": seed_count,
        "expanded_candidates": len(selected),
        "selected_evidence_ids": [r["evidence_id"] for r in records],
        "evidence_records": records,
    }


def _row_text_fallback(row: pd.Series) -> str:
    parts = []
    for key in row.index:
        if str(key) in {"timestamp_dt", "hour", "date", "raw_log"}:
            continue
        value = row.get(key, "")
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"nan", "nat", "none"}:
            parts.append(f"{key}={text[:700]}")
    return "; ".join(parts)
