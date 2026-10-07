from __future__ import annotations
import json, re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

@dataclass
class Event:
    record: int
    timestamp: str = ""
    event_type: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: str = ""
    user: str = ""
    process: str = ""
    parent_process: str = ""
    command: str = ""
    action: str = ""
    severity: str = "low"
    message: str = ""
    fields: dict[str, Any] | None = None

    def to_dict(self):
        d = asdict(self)
        d["fields"] = self.fields or {}
        return d

def _first(d, *keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return ""

def _parse_audit_line(line: str, record: int) -> Event:
    def val(pattern):
        m = re.search(pattern, line, re.I)
        return m.group(1) if m else ""
    ts = val(r"audit\(([^:]+)")
    if ts and "." in ts:
        try:
            ts = datetime.fromtimestamp(float(ts.split(":")[0])).isoformat()
        except Exception:
            pass
    event_type = val(r"type=([A-Z_]+)")
    user = val(r'acct="([^"]+)"') or val(r'acct=([^\s]+)')
    exe = val(r'exe="([^"]+)"')
    addr = val(r'addr=([^\s]+)')
    res = val(r"res=([^\s']+)")
    action = "failed_login" if res.lower() in {"failed", "failure"} else ("successful_login" if res.lower() in {"success", "successful"} else "")
    severity = "high" if event_type == "USER_AUTH" and action == "failed_login" else "medium" if event_type in {"EXECVE","SYSCALL"} else "low"
    command = val(r'command="([^"]+)"') or val(r'cmd="([^"]+)"')
    process = Path(exe).name if exe else ""
    if not process and event_type == "EXECVE":
        process = val(r'comm="?([^"\s]+)')
    return Event(record, ts, event_type, addr, "", "", user, process, "", command, action, severity, line, {})

def _from_dict(d, record):
    return Event(
        record=record,
        timestamp=str(_first(d,"timestamp","time","@timestamp","datetime")),
        event_type=str(_first(d,"event_type","eventType","EventType","type","EventID")),
        source_ip=str(_first(d,"source_ip","sourceIp","src_ip","src","SourceIp","SourceIP","addr")),
        destination_ip=str(_first(d,"destination_ip","destinationIp","dst_ip","dst","DestinationIp","DestinationIP")),
        destination_port=str(_first(d,"destination_port","destinationPort","dst_port","DestinationPort")),
        user=str(_first(d,"user","username","User","account","acct")),
        process=str(_first(d,"process","Process","Image","exe","process_name")),
        parent_process=str(_first(d,"parent_process","ParentProcess","ParentImage")),
        command=str(_first(d,"command","Command","CommandLine","commandline")),
        action=str(_first(d,"action","Action","result")),
        severity=str(_first(d,"severity","Severity","priority") or "low").lower(),
        message=str(_first(d,"message","Message","raw","msg") or json.dumps(d, ensure_ascii=False)),
        fields=d,
    )

def parse_file(path: str) -> list[Event]:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    events = []
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        for i, item in enumerate(data, 1):
            events.append(_from_dict(item if isinstance(item,dict) else {"message":str(item)}, i))
        return events
    if stripped.startswith("{") and "\n" not in stripped[:500]:
        try:
            data = json.loads(text)
            if isinstance(data, dict) and isinstance(data.get("events"), list):
                return [_from_dict(x, i) for i,x in enumerate(data["events"],1)]
            return [_from_dict(data, 1)]
        except json.JSONDecodeError:
            pass
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            if line.lstrip().startswith("{"):
                events.append(_from_dict(json.loads(line), i))
            else:
                events.append(_parse_audit_line(line, i))
        except Exception:
            events.append(Event(i, message=line))
    return events
