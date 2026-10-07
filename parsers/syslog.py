from __future__ import annotations

import re
from datetime import datetime
from typing import List

from core.event_model import LogEvent


SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<message>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PID_RE = re.compile(r"\bpid[=:](\d+)|\[(\d+)\]", re.I)
AUDIT_TYPE_RE = re.compile(r"\btype=(?P<type>[A-Z0-9_]+)\b")
AUDIT_TS_RE = re.compile(r"\bmsg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
# Auditd fields can contain a0..a31 and several numeric process/account fields.
AUDIT_FIELD_RE = re.compile(
    r'(?<![A-Za-z0-9_])(?P<key>addr|rhost|hostname|acct|comm|exe|terminal|res|op|name|COMMAND|'
    r'a\d+|pid|ppid|uid|euid|suid|fsuid|auid|ses|argc|exit|success)='
    r'(?P<val>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,]+)',
    re.I,
)
USER_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ", re.I),
    re.compile(r"Accepted (?:password|publickey) for (\S+) from ", re.I),
    re.compile(r"sudo:\s+(\S+)\s*:", re.I),
]


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    elif len(value) >= 1 and value[-1] in {'"', "'"} and value[0] not in {'"', "'"}:
        value = value[:-1]
    return value.replace(r'\\"', '"').replace(r"\\'", "'")


def _decode_audit_arg(value: str) -> str:
    """Decode common auditd hex-encoded EXECVE arguments without corrupting normal text."""
    value = _unquote(value)
    # auditd can emit an argument as hexadecimal bytes. Only decode when the
    # bytes are overwhelmingly printable UTF-8/ASCII; ordinary commands such
    # as 'deadbeef' must remain untouched.
    if len(value) >= 8 and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        try:
            raw = bytes.fromhex(value)
            decoded = raw.decode("utf-8")
            printable = sum(ch.isprintable() or ch in "\t\r\n" for ch in decoded)
            if decoded and printable / len(decoded) >= 0.90:
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return value


def _audit_fields(message: str) -> dict[str, str]:
    fields = {}
    for match in AUDIT_FIELD_RE.finditer(message):
        fields[match.group("key").lower()] = _unquote(match.group("val"))
    return fields


def _audit_type(message: str) -> str:
    match = AUDIT_TYPE_RE.search(message)
    return match.group("type") if match else ""


def _audit_meta(message: str) -> tuple[str, str]:
    match = AUDIT_TS_RE.search(message)
    if not match:
        return "", ""
    return match.group("epoch"), match.group("serial")


def _source_ip(message: str, fields: dict[str, str]) -> str:
    for key in ("addr", "rhost"):
        value = fields.get(key, "")
        if IP_RE.fullmatch(value or ""):
            return value
    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", message, re.I)
    return match.group(1) if match else ""


def _username(message: str, fields: dict[str, str]) -> str:
    if fields.get("acct") and fields["acct"] not in {"?", "(unknown)", "unknown"}:
        return fields["acct"]
    for pattern in USER_PATTERNS:
        match = pattern.search(message)
        if match:
            return match.group(1)
    return ""


def _command_and_process(message: str, fields: dict[str, str], audit_type: str = "") -> tuple[str, str]:
    process = fields.get("comm", "")
    exe = fields.get("exe", "")
    if not process and exe:
        process = exe.rsplit("/", 1)[-1]

    sudo_match = re.search(r'\bCOMMAND=("[^\"]*"|\'[^\']*\'|\S+)', message, re.I)
    if sudo_match:
        command = _unquote(sudo_match.group(1))
        process = process or "sudo"
        return command, process

    args = []
    if audit_type not in {"EXECVE", "USER_CMD"}:
        return "", process

    arg_keys = sorted(
        (key for key in fields if re.fullmatch(r"a\d+", key, re.I)),
        key=lambda key: int(key[1:]),
    )
    for key in arg_keys:
        value = fields.get(key, "")
        if value != "":
            args.append(_decode_audit_arg(value))

    sudo_match = re.search(r'\bCOMMAND=("[^\"]*"|\'[^\']*\'|\S+)', message, re.I)
    if sudo_match:
        command = _unquote(sudo_match.group(1))
        process = process or "sudo"
        return command, process

    command = " ".join(args).strip()
    return command, process


def _action(message: str, audit_type: str, fields: dict[str, str]) -> str:
    m = message.lower()
    res = fields.get("res", "").lower()
    if "failed password" in m or "authentication failure" in m:
        return "failed_login"
    if "accepted password" in m or "accepted publickey" in m:
        return "successful_login"
    if audit_type in {"USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ"}:
        if res in {"failed", "failure", "no"}:
            return "failed_login"
        if res in {"success", "yes"}:
            return "successful_login"
    if audit_type in {"EXECVE", "USER_CMD"}:
        return "command_exec"
    if "sudo:" in m or (audit_type in {"USER_START", "USER_END"} and "sudo" in m):
        return "command_exec"
    return ""


def _severity(message: str, action: str, audit_type: str) -> str:
    m = message.lower()
    if action == "failed_login":
        return "high"
    if action == "successful_login":
        return "medium"
    if action == "command_exec":
        return "medium"
    if audit_type in {"USER_AUTH", "USER_LOGIN"}:
        return "medium"
    if any(x in m for x in ("permission denied", "authentication failure")):
        return "medium"
    return "low"


def _audit_record_index(lines: list[tuple[int, str]]) -> dict[str, dict[str, str]]:
    """Build a serial->SYSCALL metadata index so EXECVE gets its real PID/UID context."""
    index: dict[str, dict[str, str]] = {}
    for _, raw in lines:
        message = SYSLOG_RE.match(raw).group("message") if SYSLOG_RE.match(raw) else raw
        audit_type = _audit_type(message)
        if audit_type != "SYSCALL":
            continue
        _, serial = _audit_meta(message)
        if not serial:
            continue
        fields = _audit_fields(message)
        index[serial] = fields
    return index


def parse_syslog(text: str) -> List[LogEvent]:
    events = []
    raw_lines = [(line_no, raw.rstrip("\r\n")) for line_no, raw in enumerate(text.splitlines(), start=1) if raw.strip()]
    syscall_index = _audit_record_index(raw_lines)

    for line_no, raw in raw_lines:
        match = SYSLOG_RE.match(raw)
        if match:
            message = match.group("message")
            timestamp = f"{match.group('month')} {match.group('day')} {match.group('time')}"
        else:
            message = raw
            timestamp = ""

        audit_type = _audit_type(message)
        fields = _audit_fields(message)
        epoch, serial = _audit_meta(message)

        if epoch:
            try:
                timestamp = datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S.%f")
            except (ValueError, OverflowError, OSError):
                pass

        # Correlate EXECVE with its SYSCALL record. This fixes the common case
        # where EXECVE contains argv/comm but the PID and effective UID live on
        # the matching SYSCALL record.
        syscall = syscall_index.get(serial, {}) if serial else {}
        merged = dict(syscall)
        merged.update(fields)

        source_ip = _source_ip(message, fields)
        username = _username(message, fields)
        action = _action(message, audit_type, fields)

        pid = merged.get("pid", "")
        ppid = merged.get("ppid", "")
        uid = merged.get("uid", "")
        euid = merged.get("euid", "")
        auid = merged.get("auid", "")
        audit_session = merged.get("ses", "")

        if not pid:
            pid_match = PID_RE.search(message)
            if pid_match:
                pid = pid_match.group(1) or pid_match.group(2) or ""

        command, process_name = _command_and_process(message, fields, audit_type)
        if not process_name and merged.get("comm"):
            process_name = merged["comm"]
        if not process_name and merged.get("exe"):
            process_name = merged["exe"].rsplit("/", 1)[-1]

        if not process_name and ":" in message:
            prefix = message.split(":", 1)[0].strip()
            if prefix and len(prefix) < 40 and " " not in prefix:
                process_name = prefix

        event_type = audit_type or ("authentication" if action in {"failed_login", "successful_login"} else "syslog")
        if "sudo:" in message:
            event_type = "privilege"
            process_name = process_name or "sudo"

        events.append(
            LogEvent(
                timestamp=timestamp,
                event_type=event_type,
                source_ip=source_ip,
                username=username,
                process_name=process_name,
                command=command,
                pid=str(pid),
                ppid=str(ppid),
                uid=str(uid),
                euid=str(euid),
                auid=str(auid),
                audit_serial=str(serial),
                audit_session=str(audit_session),
                action=action,
                severity=_severity(message, action, audit_type),
                message=message,
                line=line_no,
                raw_log=raw,
            )
        )

    return events


class SyslogParser:
    def parse(self, text: str):
        return parse_syslog(text)
