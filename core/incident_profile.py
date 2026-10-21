"""Deterministic incident profiling for LogAsis.

Given a loaded dataset, derives the strongest evidence-backed incident facts
without any model involvement and without embedding ground-truth knowledge:

- authentication anomalies (failed-then-success groups by account and source)
- the compromised account and the attacker source
- the attacker session scope (uid/auid/source) so command-based questions are
  answered about the *incident*, not 80k rows of routine system activity
- privilege-escalation activity (escalation utilities, resulting root shell)
- recognizable exploit signatures mapped to their standard CVE
- downloaded tooling (enumeration tools fetched and run)
- sensitive-file access performed as root

Everything is derived from the actual records; the CVE mapping is an explicit
signature table of well-known exploit command shapes, and answers that use it
say so ("signature mapping, not a string found in the log").

Detection rules validated against real-world auditd capture:

- EXECUTION-based matching everywhere. Privilege-boundary checks emitted by
  enumeration scanners (``sudo -l``, ``sudo -V``, ``sudo -S -l``,
  ``pkexec --version``) run the utility but prove nothing about escalation,
  so they are flagged as checks and never treated as exploit signatures.
- Sequence detection orders events by ROW POSITION. Auditd timestamps are
  frequently recorded within the same second (and out of order), so
  timestamp comparison is only a fallback.
- Downloaded tools and exploit staging run as the *attacker* user
  (pre-escalation), so content detection scans every attacker-scope row,
  not just root rows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Escalation/shell utilities (standard Unix privilege boundaries).
_ESCALATION_BINARIES = ("sudoedit", "sudo", "su", "pkexec", "doas", "runuser")

# Invocation forms that only INSPECT privilege settings (used by enumeration
# scanners such as linpeas). They execute the binary but are not attempts to
# gain privileges and must never be presented as escalation evidence.
_BENIGN_CHECK_RE = re.compile(
    r"(?:^|\s)--?(?:V|l|h|version|help|list|validate)(?:\s|$)",
    re.I,
)

# Read/copy programs used when touching sensitive files. Search/pattern tools
# (grep/sed/awk/find/ls) are excluded: their output merely *mentions* paths
# (e.g. linpeas checks) and would otherwise be reported as file access.
_DIRECT_READ_TOOLS = (
    "cat", "head", "tail", "less", "more", "cp", "tar", "zip", "gzip",
    "base64", "xxd", "dd", "scp", "sftp", "curl", "wget", "nc", "ncat",
    "netcat", "rsync", "openssl", "sqlite3", "mysql", "psql", "python",
    "python3", "sh", "bash", "install",
)

# Archive extensions are payloads, not enumeration tools.
_ARCHIVE_SUFFIX_RE = re.compile(r"\.(tar|tar\.gz|tgz|gz|zip|rar|7z|xz|bz2)$", re.I)

# Sensitive paths whose access matters in an investigation.
_SENSITIVE_PATH_RE = re.compile(
    r"(/etc/shadow\b|/etc/gshadow\b|/etc/sudoers\b|/etc/passwd\b|"
    r"/root/\.ssh\b|/\.ssh\b|id_rsa\b|id_ed25519\b|authorized_keys\b|"
    r"/etc/ssh/sshd_config\b|\.git-credentials\b|/var/lib/mysql\b|\.kube/config\b)",
    re.I,
)

# Well-known exploit command signatures -> standard CVE. Detection is
# EXECUTION-based (the exploit utility is the invoked program), so mere
# mentions inside scanner output (linpeas greps/lists) are not matches. These
# are arm's-length public identifiers for a *command shape* observed in the
# log, never a claim about the log text itself.
_SUDOEDIT_EXPLOIT_RE = re.compile(r"-s\b", re.I)
_SUDO_LONGARG_RE = re.compile(r"\bsudo\s+-s\s+\S{24,}", re.I)
_LIBNSS_RE = re.compile(r"libnss_[A-Za-z0-9_]+|/X/X\.so|P0P_?SH[I1]?LL|libnss_X", re.I)

_CVE_SIGNATURES: list[dict[str, Any]] = [
    {
        "cve": "CVE-2021-3156",
        "description": "sudo/sudoedit heap-based buffer overflow (\"Baron Samedit\")",
        "bins": ("sudoedit",),
        "extra": _SUDOEDIT_EXPLOIT_RE,
    },
    {
        "cve": "CVE-2021-3156",
        "description": "sudo heap-based buffer overflow (\"Baron Samedit\")",
        "bins": ("sudo",),
        "extra": _SUDO_LONGARG_RE,
    },
    {
        "cve": "CVE-2021-4034",
        "description": "pkexec PwnKit local privilege escalation",
        "bins": ("pkexec",),
        "extra": None,
    },
    {
        "cve": "CVE-2022-0847",
        "description": "Dirty Pipe local privilege escalation",
        "bins": ("dirtypipe", "dirty_pipe", "dirtypipe-exploit"),
        "extra": None,
    },
]

_UNSET_UIDS = {"0", "-1", "4294967295"}

# Sentinel distinguishing "profile built, no incident found" from "not built
# yet", so repeated questions never rebuild the profile unnecessarily.
_NO_INCIDENT = object()

# --- Windows / cross-platform detection -------------------------------------
# Windows auth event IDs with a fixed meaning (mirrors parsers/json_log.py).
_WINDOWS_FAILED_EVENT_IDS = {"4625"}
_WINDOWS_SUCCESS_EVENT_IDS = {"4624", "4648", "4776"}

# Suspicious execution shapes on Windows (DEFEND-style signatures). Each is
# an executed-command pattern, never a mere mention inside an unrelated
# command's arguments.
_SUSPICIOUS_WINDOWS: list[dict[str, Any]] = [
    {"label": "encoded/hidden PowerShell",
     "re": re.compile(r"powers?(?:hell|shell)?(?:\.exe)?\b[^\n]*(?:-{1,2}enc(?:odedcommand)?\b|-{1,2}w\b\s*(?:hidden|1)\b|-{1,2}nop\b|iex\b|invoke-expression\b|downloadstring\b|frombase64string\b)", re.I)},
    {"label": "credential dumper (mimikatz-style)",
     "re": re.compile(r"\bmimikatz\b|sekurlsa::|lsadump::|logonpasswords\b|trustkeys\b", re.I)},
    {"label": "LSASS memory dump",
     "re": re.compile(r"comsvcs\.dll[, ]+minidump|procdump(?:\.exe)?\b[^\n]*lsass|lsass\.dmp|rank\b\s*minidump", re.I)},
    {"label": "download via certutil/bitsadmin",
     "re": re.compile(r"certutil(?:\.exe)?\b[^\n]*-urlcache|bitsadmin(?:\.exe)?\b[^\n]*/transfer|start-bitstransfer\b", re.I)},
    {"label": "remote execution tooling",
     "re": re.compile(r"\bpsexec(?:\.exe)?\b|\bwmic\b[^\n]*process\s+call\s+create|\bwinrs\b|\binvoke-command\b|\bpaexec\b|\bsmbexec\b|\bwmiexec\b", re.I)},
    {"label": "persistence via scheduled task/registry",
     "re": re.compile(r"schtasks(?:\.exe)?\b[^\n]*/create|reg(?:\.exe|add)?\b[^\n]*currentversion\\?run\b|\bnew-service\b|\bat\s+\d{1,2}:\d{2}\b", re.I)},
    {"label": "account/group manipulation",
     "re": re.compile(r"\bnet(?:\.exe)?\s+(?:user|localgroup)\b[^\n]*/(?:add|delete)|\badd-localgroupmember\b|\bnew-localuser\b", re.I)},
    {"label": "anti-forensics / shadow copies",
     "re": re.compile(r"vssadmin(?:\.exe)?\b[^\n]*delete\s+shadows|bcdedit(?:\.exe)?\b[^\n]*recoveryenabled\s+no|wevtutil(?:\.exe)?\b[^\n]*cl\b|clear-eventlog\b", re.I)},
    {"label": "UAC bypass / token manipulation",
     "re": re.compile(r"\bfodhelper\b|\beventvwr\b[^\n]*bypass|make_token\b|\bgetsyste\b|invoke-tokenmanipulation\b", re.I)},
]

# Windows files/artifacts whose access or staging matters.
_SENSITIVE_WINDOWS_RE = re.compile(
    r"(lsass\.dmp\b|ntds\.dit\b|\bsam\b(?:\.save|\s+hive|\s+file|\b)|\bsystem\b(?:\s+hive|\s+file)|"
    r"\\windows\\system32\\config\\|repair\\sam\b|\.dmp\b|inject(?:ed)?\.ps1\b)",
    re.I,
)

# Windows download tool shapes -> URL extraction (in addition to wget/curl).
_WINDOWS_DOWNLOAD_RE = re.compile(
    r"(invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
    r"certutil\b[^\n]*-urlcache|bitsadmin\b[^\n]*/transfer|start-bitstransfer|"
    r"mshta\b|curl|wget)[^\n]*?(https?://\S+)",
    re.I,
)

# Unix root-equivalent: uid/euid "SYSTEM"/"S-1-5-18" or elevation via sudo-like.
_WINDOWS_SYSTEM_UIDS = {"system", "s-1-5-18", "s-1-5-18-..."}

# Windows event-id -> incident meaning, applied when the action column is empty.
_EVENT_ID_FAILED = "4625"
_EVENT_ID_SUCCESS = {"4624", "4648", "4776"}


@dataclass
class IncidentProfile:
    has_incident: bool = False
    platform: str = ""  # "unix" | "windows" | ""
    compromised_user: str = ""
    attacker_ip: str = ""
    failed_count: int = 0
    success_count: int = 0
    first_failure_position: int = -1
    login_positions: list[int] = field(default_factory=list)  # winning group's login rows (bounded)
    last_incident_position: int = -1
    attacker_identities: set[str] = field(default_factory=set)  # uid/auid values
    scope_positions: list[int] = field(default_factory=list)
    root_positions: list[int] = field(default_factory=list)
    escalation: list[dict[str, Any]] = field(default_factory=list)
    suspicious_executions: list[dict[str, Any]] = field(default_factory=list)
    credential_access: list[dict[str, Any]] = field(default_factory=list)
    root_commands: list[dict[str, Any]] = field(default_factory=list)
    root_shell: dict[str, Any] | None = None
    cve_matches: list[dict[str, Any]] = field(default_factory=list)
    downloaded_tools: list[dict[str, Any]] = field(default_factory=list)
    payload_downloads: list[dict[str, Any]] = field(default_factory=list)
    sensitive_reads: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_incident": self.has_incident,
            "platform": self.platform,
            "compromised_user": self.compromised_user,
            "attacker_ip": self.attacker_ip,
            "failed_count": self.failed_count,
            "success_count": self.success_count,
            "login_positions": self.login_positions[:20],
            "attacker_identities": sorted(self.attacker_identities),
            "escalation": self.escalation[:10],
            "suspicious_executions": self.suspicious_executions[:10],
            "credential_access": self.credential_access[:6],
            "root_shell": dict(self.root_shell) if self.root_shell else None,
            "root_commands": self.root_commands[:12],
            "cve_matches": self.cve_matches[:6],
            "downloaded_tools": self.downloaded_tools[:6],
            "payload_downloads": self.payload_downloads[:6],
            "sensitive_reads": self.sensitive_reads[:6],
            "scope_size": len(self.scope_positions),
            "notes": list(self.notes),
        }

    # -- convenience accessors used by the deterministic QA layer ----------

    @property
    def top_escalation(self) -> dict[str, Any] | None:
        """The strongest escalation attempt: first non-check invocation."""
        for entry in self.escalation:
            if not entry.get("check"):
                return entry
        return self.escalation[0] if self.escalation else None

    @property
    def top_suspicious_execution(self) -> dict[str, Any] | None:
        return self.suspicious_executions[0] if self.suspicious_executions else None

    @property
    def top_cve_match(self) -> dict[str, Any] | None:
        return self.cve_matches[0] if self.cve_matches else None

    @property
    def root_sensitive_reads(self) -> list[dict[str, Any]]:
        return [r for r in self.sensitive_reads if r.get("as_root")]

    @property
    def is_windows(self) -> bool:
        return self.platform == "windows"


def _first_token(command: str) -> str:
    text = str(command or "").strip().strip("\"'")
    if not text:
        return ""
    token = text.split()[0]
    return token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()


def build_incident_profile(df, index, schema) -> IncidentProfile:
    """Derive the incident profile deterministically from the loaded data.

    Format-aware: the same intrusion grammar (authentication anomalies ->
    attacker session -> tooling -> privilege escalation -> sensitive access)
    is recognized on Linux auditd/syslog evidence (sudo/sudoedit, /etc/shadow)
    and on Windows / Sysmon / EVTX-JSON evidence (4625/4624 logon events,
    encoded PowerShell, LSASS access, credential dumping).
    """
    profile = IncidentProfile()
    if df is None or len(df) == 0:
        return profile

    def columns_for(field_name: str | None):
        if not field_name or field_name not in df.columns:
            return None
        return df[field_name].fillna("").astype(str)

    action_field = schema.canonical_field("action") or "action"
    user_field = schema.canonical_field("user") or schema.canonical_field("username")
    ip_field = schema.canonical_field("source_ip")
    event_id_field = columns_for("event_id")
    target_image_field = columns_for("targetimage")
    uid_col = columns_for("uid")
    euid_col = columns_for("euid")
    auid_col = columns_for("auid")
    command_col = columns_for("command")
    pid_series = df["pid"].astype(str) if "pid" in df.columns else None

    # --- platform detection --------------------------------------------------
    window_hits = 0
    unix_hits = 0
    if event_id_field is not None:
        window_hits += int(event_id_field.str.extract(r"^(\d{1,5})$", expand=False).isin(
            _WINDOWS_SUCCESS_EVENT_IDS | _WINDOWS_FAILED_EVENT_IDS | {"4688", "1102", "7045"}
        ).sum())
    for col in ("process_name", "command", "parent_image"):
        series = columns_for(col)
        if series is None:
            continue
        window_hits += int(series.str.contains(
            r"(?:\\.exe\b|\\Device\\|\\Windows\\|powershell)", case=False, regex=True
        ).sum())
    if uid_col is not None:
        unix_hits += int(uid_col.isin({"0", "1000", "1001", "1002"}).sum())
    profile.platform = "windows" if window_hits > unix_hits else "unix"

    # --- authentication anomalies -------------------------------------------
    failed_positions: list[int] = []
    success_positions: list[int] = []
    if action_field in schema.fields:
        failed_positions = list(index.exact(action_field, "failed_login"))
        success_positions = list(index.exact(action_field, "successful_login"))
        # Windows EVTX exports: the fixed-meaning logon event IDs carry the
        # outcome when the action column is unpopulated.
        if not failed_positions and not success_positions and event_id_field is not None:
            event_ids = event_id_field.str.extract(r"^(\d{1,5})$", expand=False)
            failed_positions = [
                int(p) for p in df.index[event_ids.isin(_WINDOWS_FAILED_EVENT_IDS)]
            ]
            success_positions = [
                int(p) for p in df.index[event_ids.isin(_WINDOWS_SUCCESS_EVENT_IDS)]
            ]

    if failed_positions and user_field:
        users = columns_for(user_field)
        ips = columns_for(ip_field) if ip_field else None
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for pos in failed_positions:
            user = str(users.iloc[pos]) if users is not None else ""
            ip = str(ips.iloc[pos]) if ips is not None else ""
            key = (user, ip)
            entry = groups.setdefault(key, {"failed": 0, "last_fail_pos": -1})
            entry["failed"] += 1
            entry["last_fail_pos"] = max(entry["last_fail_pos"], int(pos))
        # A group is a brute-force candidate when it has a meaningful failure
        # volume and the same account later succeeds (ORDER BY ROW POSITION —
        # auditd timestamps are frequently all within the same second).
        success_by_user: dict[str, list[int]] = {}
        if users is not None:
            for pos in success_positions:
                success_by_user.setdefault(str(users.iloc[pos]), []).append(int(pos))
        candidates = []
        for (user, ip), entry in groups.items():
            if entry["failed"] < 3:
                continue
            successes_after = [
                p for p in success_by_user.get(user, [])
                if p > entry["last_fail_pos"]
            ]
            candidates.append((entry["failed"], user, ip, entry, successes_after))
        if candidates:
            candidates.sort(key=lambda c: (-c[0], c[1]))
            failed_count, user, ip, entry, successes_after = candidates[0]
            profile.has_incident = True
            profile.compromised_user = user
            profile.attacker_ip = ip
            profile.failed_count = failed_count
            profile.success_count = len(successes_after) or len(success_by_user.get(user, []))
            group_positions = [
                int(p) for p in failed_positions
                if (str(users.iloc[p]) if users is not None else "") == user
                and (str(ips.iloc[p]) if ips is not None else "") == ip
            ]
            profile.first_failure_position = min(group_positions, default=-1)
            # Bounded evidence rows for the winning group: first failures plus
            # the successes that came after them.
            profile.login_positions = sorted(
                group_positions[:12] + sorted(successes_after)[:8]
            )

    # --- attacker session scope ---------------------------------------------
    if profile.has_incident:
        # Collect the numeric identities (uid/auid) seen for the compromised
        # account and the attacker source, so later activity by the same
        # session can be scoped.
        scope_mask = None
        if user_field:
            users = columns_for(user_field)
            scope_mask = users == profile.compromised_user
        if ip_field:
            ips = columns_for(ip_field)
            ip_mask = ips == profile.attacker_ip
            scope_mask = ip_mask if scope_mask is None else (scope_mask | ip_mask)
        if scope_mask is not None and uid_col is not None:
            for value in set(uid_col[scope_mask]):
                if value and value not in _UNSET_UIDS:
                    profile.attacker_identities.add(value)
        if scope_mask is not None and auid_col is not None:
            for value in set(auid_col[scope_mask]):
                if value and value not in _UNSET_UIDS:
                    profile.attacker_identities.add(value)

        # Expansive but bounded scope: rows whose user/uid/auid/ip matches the
        # attacker session.
        scope_series = None
        for col in ([user_field] if user_field else []) + ["uid", "euid", "auid", "source_ip"]:
            if col not in df.columns:
                continue
            values = df[col].fillna("").astype(str)
            if col in {user_field, "source_ip"}:
                target = profile.compromised_user if col == user_field else profile.attacker_ip
                mask = values == target if target else None
            else:
                mask = values.isin(profile.attacker_identities)
            if mask is None:
                continue
            scope_series = mask if scope_series is None else (scope_series | mask)
        if scope_series is not None:
            profile.scope_positions = [int(p) for p in df.index[scope_series]]
            if profile.scope_positions:
                profile.last_incident_position = max(profile.scope_positions)

    # --- escalation / root activity / tooling / sensitive reads -------------
    # Content detection runs over every attacker-scope row: exploit staging
    # (tool download, payload compile) executes as the ATTACKER user before
    # any privilege is gained, so gating it on uid=0 would miss it.
    scope = profile.scope_positions or list(df.index)

    # Case-insensitive column lookup for source-specific fields
    # (TargetImage, TargetFilename, ...) whose original casing varies by
    # exporter.
    lower_columns = {str(c).lower(): c for c in df.columns}
    target_image_col = columns_for(lower_columns.get("targetimage"))
    target_file_col = columns_for(lower_columns.get("targetfilename"))
    process_name_col = columns_for("process_name")

    for pos in scope:
        eid = str(event_id_field.iloc[pos]).strip() if event_id_field is not None else ""
        target_image = str(target_image_col.iloc[pos]) if target_image_col is not None else ""
        target_file = str(target_file_col.iloc[pos]) if target_file_col is not None else ""
        uid = str(uid_col.iloc[pos]) if uid_col is not None else ""
        euid = str(euid_col.iloc[pos]) if euid_col is not None else ""
        auid = str(auid_col.iloc[pos]) if auid_col is not None else ""
        pid = str(pid_series.iloc[pos]) if pid_series is not None else ""
        line = str(df["line"].iloc[pos]) if "line" in df.columns else ""

        # Sysmon ProcessAccess (EventID 10) against LSASS: credential dumping
        # access regardless of any command line. Also Sysmon FileCreate (11)
        # staging a dump/hive.
        if eid == "10" and target_image and re.search(r"lsass(?:\.exe)?$", target_image, re.I):
            process_name = str(process_name_col.iloc[pos]) if process_name_col is not None else ""
            profile.credential_access.append({
                "kind": "LSASS process access",
                "source": process_name or "unknown process",
                "target": target_image,
                "pid": pid, "line": line,
                "position": pos,
            })
        if eid == "11" and target_file and _SENSITIVE_WINDOWS_RE.search(target_file):
            profile.credential_access.append({
                "kind": "sensitive file created",
                "source": target_file,
                "target": target_file,
                "pid": pid, "line": line,
                "position": pos,
            })

        command = str(command_col.iloc[pos]) if command_col is not None else ""
        if not command:
            continue
        first = _first_token(command)
        is_root = uid == "0" or euid == "0"

        # Windows suspicious executions (execution-shaped signatures; benign
        # admin activity that merely mentions these words is not a match)
        for signature in _SUSPICIOUS_WINDOWS:
            if not signature["re"].search(command):
                continue
            profile.suspicious_executions.append({
                "label": signature["label"], "command": command[:220],
                "pid": pid, "uid": uid, "line": line, "position": pos,
            })

        # escalation utilities (flag scanner-style checks, keep them ranked
        # below real attempts)
        if first in _ESCALATION_BINARIES:
            profile.escalation.append({
                "binary": first, "command": command[:220], "pid": pid,
                "uid": uid, "auid": auid, "line": line, "position": pos,
                "check": bool(_BENIGN_CHECK_RE.search(command)),
                "as_root": is_root,
            })

        # root commands in the attacker session (Unix; on Windows the uid
        # column carries SIDs, and SYSTEM activity is captured through the
        # suspicious-execution signatures instead)
        if is_root and uid == "0" and auid not in _UNSET_UIDS:
            profile.root_positions.append(pos)
            profile.root_commands.append({
                "command": command[:220], "pid": pid, "uid": uid, "auid": auid,
                "line": line, "position": pos,
            })

        # CVE signature mapping (execution-based; benign privilege checks
        # emitted by enumeration scanners are excluded)
        for signature in _CVE_SIGNATURES:
            if first not in signature["bins"]:
                continue
            if _BENIGN_CHECK_RE.search(command):
                continue
            extra = signature["extra"]
            if extra is not None and not extra.search(command):
                continue
            profile.cve_matches.append({
                "cve": signature["cve"], "description": signature["description"],
                "command": command[:220], "pid": pid, "line": line, "position": pos,
            })
        if _LIBNSS_RE.search(command):
            profile.cve_matches.append({
                "cve": "CVE-2021-3156", "description": "sudo/sudoedit payload library injection",
                "command": command[:220], "pid": pid, "line": line, "position": pos,
            })

        # downloaded tools (enumeration) and payload archives — Unix and
        # Windows downloader shapes
        for url_match in re.finditer(r"(wget|curl)[^\n]*?(https?://\S+)", command, re.I):
            url = url_match.group(2).rstrip("'\"&)")
            basename = url.rsplit("/", 1)[-1].split("?")[0]
            if _ARCHIVE_SUFFIX_RE.search(basename):
                profile.payload_downloads.append({
                    "url": url, "command": command[:220], "pid": pid,
                    "line": line, "position": pos,
                })
                continue
            tool = re.sub(r"\.(sh|py|pl|bin|elf)$", "", basename, flags=re.I)
            if tool:
                profile.downloaded_tools.append({
                    "tool": tool, "url": url, "command": command[:220],
                    "pid": pid, "line": line, "position": pos,
                })
        for url_match in _WINDOWS_DOWNLOAD_RE.finditer(command):
            url = url_match.group(2).rstrip("'\"&)")
            basename = url.rsplit("/", 1)[-1].split("?")[0]
            if _ARCHIVE_SUFFIX_RE.search(basename):
                profile.payload_downloads.append({
                    "url": url, "command": command[:220], "pid": pid,
                    "line": line, "position": pos,
                })
                continue
            tool = re.sub(r"\.(sh|py|pl|bin|elf|exe|ps1|bat|dll)$", "", basename, flags=re.I)
            if tool:
                profile.downloaded_tools.append({
                    "tool": tool, "url": url, "command": command[:220],
                    "pid": pid, "line": line, "position": pos,
                })

        # sensitive file access — Unix: direct readers only (path must be an
        # argument token, not a mention inside a scanner command); Windows:
        # artifact patterns in the executed command (dump tools, hive copies)
        if first in _DIRECT_READ_TOOLS:
            for path_match in _SENSITIVE_PATH_RE.finditer(command):
                path = path_match.group(1)
                if not re.search(rf"(^|\s){re.escape(path)}(\s|$)", command):
                    continue
                profile.sensitive_reads.append({
                    "path": path, "command": command[:220],
                    "pid": pid, "uid": uid, "auid": auid, "line": line,
                    "position": pos,
                    "as_root": is_root,
                })
        for artifact_match in _SENSITIVE_WINDOWS_RE.finditer(command):
            artifact = artifact_match.group(1)
            profile.sensitive_reads.append({
                "path": artifact, "command": command[:220],
                "pid": pid, "uid": uid, "auid": auid, "line": line,
                "position": pos,
                "as_root": is_root,
            })

    # De-duplicate by key while preserving order.
    def _dedupe(items: list[dict], key_fields: tuple[str, ...]) -> list[dict]:
        seen = set()
        out = []
        for item in items:
            key = tuple(str(item.get(f, ""))[:80] for f in key_fields)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def _dedupe_sensitive(items: list[dict]) -> list[dict]:
        """Collapse per-path duplicates but keep root and non-root reads
        separate (the same path is often probed by a scanner as the attacker
        and later actually read as root — only the latter matters)."""
        seen = set()
        out = []
        for item in items:
            key = (str(item.get("path", "")), str(item.get("command", ""))[:80], bool(item.get("as_root")))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        out.sort(key=lambda r: (not r.get("as_root"), r.get("position", 0)))
        return out

    profile.escalation = _dedupe(profile.escalation, ("binary", "command"))
    # Real escalation attempts first; scanner-style checks afterwards.
    profile.escalation.sort(key=lambda e: (bool(e.get("check")), e.get("position", 0)))
    profile.root_commands = _dedupe(profile.root_commands, ("command", "pid"))
    profile.cve_matches = _dedupe(profile.cve_matches, ("cve", "command"))
    # The exploit invocation itself (e.g. `sudoedit -s AAAA…`) is the
    # representative match; library-injection staging (`gcc libnss_X …`)
    # supports it but should not lead the answer.
    profile.cve_matches.sort(
        key=lambda m: (1 if "payload library injection" in str(m.get("description", "")) else 0,
                       m.get("position", 0))
    )
    profile.downloaded_tools = _dedupe(profile.downloaded_tools, ("tool",))
    profile.payload_downloads = _dedupe(profile.payload_downloads, ("url",))
    profile.sensitive_reads = _dedupe_sensitive(profile.sensitive_reads)
    profile.suspicious_executions = _dedupe(profile.suspicious_executions, ("label", "command"))
    profile.suspicious_executions.sort(key=lambda e: e.get("position", 0))
    profile.credential_access = _dedupe(profile.credential_access, ("kind", "source", "target"))
    profile.credential_access.sort(key=lambda e: e.get("position", 0))

    # The resulting root shell: the first command executed as root inside the
    # attacker session AFTER the strongest escalation attempt (for an
    # exploited sudo/sudoedit this is the payload shell the exploit spawned).
    top = profile.top_escalation
    if top is not None and profile.root_commands:
        top_pos = int(top.get("position", -1))
        after = [c for c in profile.root_commands if int(c.get("position", -1)) > top_pos]
        if after:
            profile.root_shell = after[0]

    if profile.cve_matches:
        profile.notes.append(
            "CVE mapping comes from an execution-based command-shape signature table, "
            "not from a CVE string found in the log."
        )
    return profile
