from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class LogEvent:
    timestamp: Optional[str] = None
    event_type: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    process_name: str = ""
    command: str = ""
    pid: str = ""
    ppid: str = ""
    uid: str = ""
    euid: str = ""
    auid: str = ""
    audit_serial: str = ""
    audit_session: str = ""
    action: str = ""
    severity: str = ""
    message: str = ""
    line: int = 0
    raw_log: str = ""

    def to_dict(self):
        return asdict(self)
