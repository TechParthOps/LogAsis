from __future__ import annotations

"""Deterministic investigation-action engine for LogAsis v0.5.16.

The engine turns a case decision gap into a bounded, evidence-specific search
over the currently loaded event dataset. It never declares an event malicious
or proves causation.

v0.5.16 adds relationship-chain process attribution and explicit rejection diagnostics on top of the v0.5.15 audit-session-aware correlation: low-level
privilege transitions must also be attributable to the linked privilege activity.
A wide temporal window plus the same process is no longer sufficient; strong
identity correlation is preferred, with a conservative five-second fallback for
privilege anchors that lack identity fields. Repetitive attribution records are
collapsed to representative evidence.
"""

from datetime import datetime, timezone
import re
from typing import Any, Iterable


class InvestigationActionEngine:
    """Run explainable, evidence-bounded searches for decision evidence gaps."""

    WINDOW_SECONDS = 300
    MAX_REPRESENTATIVE_RESULTS = 25

    ACTIONS = {
        "G-001": {
            "name": "Search for successful authentication",
            "category": "AUTHENTICATION",
            "description": "Find successful authentication events near the case's observed authentication activity.",
        },
        "G-002": {
            "name": "Search for session creation",
            "category": "SESSION",
            "description": "Find explicit session-open/session-start evidence near the case's authentication activity.",
        },
        "G-003": {
            "name": "Search for successful privilege elevation",
            "category": "PRIVILEGE",
            "description": "Find explicit successful sudo/privilege-elevation evidence and resulting process identity near the case.",
        },
        "G-004": {
            "name": "Search for source attribution",
            "category": "SOURCE_ATTRIBUTION",
            "description": "Find nearby authentication/network records that can supply a missing source IP.",
        },
        "G-005": {
            "name": "Search for process attribution",
            "category": "PROCESS_ATTRIBUTION",
            "description": "Find nearby identity/session/process records that can supply a missing username or identity.",
        },
    }

    _AUTH_TYPES = {
        "USER_AUTH", "AUTH", "AUTHENTICATION",
        "USER_LOGIN", "LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP",
    }
    _IDENTITY_TYPES = _AUTH_TYPES | {
        "USER_START", "USER_END", "SESSION_OPEN", "SESSION_START",
        "SESSION", "SESSION_CREATED", "PROCESS_CREATE", "EXECVE", "SYSCALL",
    }
    _NETWORK_TYPES = {
        "NETWORK", "CONNECTION", "CONNECT", "NETFLOW", "SOCKET",
    }
    _PRIVILEGE_TYPES = {
        "PRIVILEGE", "PRIVILEGE_ESCALATION", "SUDO", "USER_CMD",
    }
    _PRIVILEGE_PROCESSES = {"sudo", "su", "pkexec", "doas"}
    _PRIVILEGE_ACTIONS = {
        "sudo_success", "privilege_escalation_success",
        "privilege_success", "elevation_success",
    }

    @staticmethod
    def _text(event: dict[str, Any]) -> str:
        return " ".join(
            str(event.get(key, "") or "")
            for key in (
                "event_type", "action", "message", "raw_log",
                "command", "result", "status", "rule_name",
                "process_name", "exe", "comm",
            )
        ).lower()

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @classmethod
    def _parse_time(cls, value: Any) -> datetime | None:
        if value is None or str(value).strip() == "":
            return None
        text = str(value).strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            try:
                year = datetime.now(timezone.utc).year
                dt = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
            except (TypeError, ValueError):
                return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def _distance(cls, left: Any, right: Any) -> float | None:
        a = cls._parse_time(left)
        b = cls._parse_time(right)
        if not a or not b:
            return None
        return abs((a - b).total_seconds())

    @classmethod
    def _event_type(cls, event: dict[str, Any]) -> str:
        return cls._norm(event.get("event_type")).upper()

    @classmethod
    def _process(cls, event: dict[str, Any]) -> str:
        process = cls._norm(event.get("process_name"))
        if process:
            return process.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return cls._norm(event.get("comm") or event.get("exe")).rsplit("/", 1)[-1]

    @classmethod
    def _audit_session(cls, event: dict[str, Any]) -> str:
        """Return the normalized audit/session identifier when one is available.

        Linux auditd commonly emits this as ``ses=``. JSON/SIEM exports may
        normalize it as ``audit_session`` or ``session_id``. Treating the
        identifier as an explicit relationship lets attribution cross an
        EXECVE/SYSCALL record and a USER_START/authentication record without
        relying on broad time proximity.
        """
        for key in ("audit_session", "session_id", "ses"):
            value = cls._norm(event.get(key))
            if value:
                return value
        return ""

    @classmethod
    def _audit_identity(cls, event: dict[str, Any]) -> dict[str, str]:
        """Return audit identity fields, recovering them from raw audit text when needed.

        Older loaded datasets can contain the identity information only inside
        ``message``/``raw_log`` even though newer parsers normalize it. Keeping
        recovery here makes investigation correlation version-tolerant without
        weakening attribution rules.
        """
        values = {
            "pid": cls._norm(event.get("pid")),
            "ppid": cls._norm(event.get("ppid")),
            "uid": cls._norm(event.get("uid")),
            "auid": cls._norm(event.get("auid")),
            "audit_serial": cls._norm(event.get("audit_serial")),
            "audit_session": cls._audit_session(event),
        }
        text = " ".join(str(event.get(k, "") or "") for k in ("message", "raw_log"))
        if text:
            patterns = {
                "pid": r"\bpid=(?:\"([^\"]+)\"|(\S+))",
                "ppid": r"\bppid=(?:\"([^\"]+)\"|(\S+))",
                "uid": r"(?<![A-Za-z0-9_])uid=(?:\"([^\"]+)\"|(\S+))",
                "auid": r"\bauid=(?:\"([^\"]+)\"|(\S+))",
                "audit_session": r"\bses=(?:\"([^\"]+)\"|(\S+))",
                "audit_serial": r"\bmsg=audit\([^:()]+:(\d+)\)",
            }
            for key, pattern in patterns.items():
                if values[key]:
                    continue
                m = re.search(pattern, text, re.I)
                if m:
                    values[key] = cls._norm(next((g for g in m.groups() if g), ""))
        return values

    @classmethod
    def _relationship_fields(cls, event: dict[str, Any]) -> dict[str, str]:
        identity = cls._audit_identity(event)
        return {
            **identity,
            "source_ip": cls._norm(event.get("source_ip")),
            "process": cls._process(event),
        }

    @classmethod
    def _strong_relationship(cls, left: dict[str, Any], right: dict[str, Any]) -> tuple[bool, list[str]]:
        """Return whether two records share an explicit process/audit identity key.

        Username and timestamp are deliberately excluded: they are useful context
        but are not sufficient to establish process attribution.
        """
        a = cls._relationship_fields(left)
        b = cls._relationship_fields(right)
        reasons = []
        if a["audit_serial"] and a["audit_serial"] == b["audit_serial"]:
            reasons.append("same audit serial")
        if a["audit_session"] and a["audit_session"] == b["audit_session"]:
            reasons.append("same audit session")
        if a["pid"] and a["pid"] == b["pid"]:
            reasons.append("same PID")
        if a["ppid"] and a["ppid"] == b["ppid"]:
            reasons.append("same parent PID")
        if a["auid"] and a["auid"] == b["auid"]:
            reasons.append("same audit user ID")
        if a["uid"] and a["uid"] == b["uid"]:
            reasons.append("same UID")
        if a["source_ip"] and a["source_ip"] == b["source_ip"]:
            reasons.append("same source IP")
        if a["process"] and a["process"] == b["process"]:
            reasons.append("same process")
        return bool(reasons), reasons

    @classmethod
    def _strong_identity_relationship(cls, left: dict[str, Any], right: dict[str, Any]) -> tuple[bool, list[str]]:
        """Return only hard audit/process identity links suitable for a bridge.

        Process names and source IPs are intentionally excluded here: they are
        useful direct-context signals but are too broad to support a two-hop
        attribution chain on their own.
        """
        a = cls._audit_identity(left)
        b = cls._audit_identity(right)
        reasons = []
        for key, label in (
            ("audit_serial", "same audit serial"),
            ("audit_session", "same audit session"),
            ("pid", "same PID"),
            ("ppid", "same parent PID"),
            ("auid", "same audit user ID"),
            ("uid", "same UID"),
        ):
            if a[key] and a[key] == b[key]:
                reasons.append(label)
        return bool(reasons), reasons

    _STRONG_IDENTITY_KEYS = (
        ("audit_serial", "same audit serial"),
        ("audit_session", "same audit session"),
        ("pid", "same PID"),
        ("ppid", "same parent PID"),
        ("auid", "same audit user ID"),
        ("uid", "same UID"),
    )

    @classmethod
    def _strong_identity_index_keys(cls, event: dict[str, Any]) -> list[tuple[str, str]]:
        identity = cls._audit_identity(event)
        return [
            (key, identity[key])
            for key, _label in cls._STRONG_IDENTITY_KEYS
            if identity[key]
        ]

    @classmethod
    def _build_relationship_bridge_index(
        cls,
        anchors: list[dict[str, Any]],
        candidate_events: list[dict[str, Any]],
        window_seconds: int,
    ) -> dict[tuple[str, str], tuple[dict[str, Any], list[str]]]:
        """Build a bounded two-hop bridge index once per investigation.

        v0.5.16 built the full bridge list inside the per-candidate loop and then
        scanned that list again for every username-bearing candidate. With a real
        log containing tens of thousands of events this became O(N²) and made the
        GUI appear to hang specifically on G-005.

        The index keeps one representative bridge per strong identity key. A
        bridge is useful only inside the same investigation window as its anchor,
        and a single bridge for a key is sufficient because the relationship is
        established by the shared explicit identity field, not by the bridge's
        event count.
        """
        index: dict[tuple[str, str], tuple[dict[str, Any], list[str]]] = {}
        for anchor in anchors:
            for bridge, bridge_reasons in cls._process_bridges(
                anchor, candidate_events, window_seconds=window_seconds
            ):
                for key in cls._strong_identity_index_keys(bridge):
                    current = index.get(key)
                    if current is None:
                        index[key] = (bridge, bridge_reasons)
                        continue
                    # Prefer the bridge with more explicit relationship fields;
                    # use temporal proximity as the deterministic tie-breaker.
                    current_bridge, current_reasons = current
                    current_rank = (
                        -len(current_reasons),
                        cls._distance(anchor.get("timestamp"), current_bridge.get("timestamp"))
                        if cls._distance(anchor.get("timestamp"), current_bridge.get("timestamp")) is not None
                        else 10**12,
                        str(current_bridge.get("timestamp", "")),
                    )
                    candidate_rank = (
                        -len(bridge_reasons),
                        cls._distance(anchor.get("timestamp"), bridge.get("timestamp"))
                        if cls._distance(anchor.get("timestamp"), bridge.get("timestamp")) is not None
                        else 10**12,
                        str(bridge.get("timestamp", "")),
                    )
                    if candidate_rank < current_rank:
                        index[key] = (bridge, bridge_reasons)
        return index

    @classmethod
    def _process_bridges(
        cls,
        anchor: dict[str, Any],
        candidate_events: list[dict[str, Any]],
        window_seconds: int | None = None,
    ) -> list[tuple[dict[str, Any], list[str]]]:
        """Find strong intermediate records that can bridge an incomplete anchor.

        Example: EXECVE lacks ``ses=42`` but a same-serial SYSCALL record has it;
        a USER_START with ``ses=42`` can then be attributed through that bridge.
        Only explicit identity keys are allowed to create the bridge.
        """
        bridges = []
        for event in candidate_events:
            if event is anchor:
                continue
            if window_seconds is not None:
                distance = cls._distance(event.get("timestamp"), anchor.get("timestamp"))
                if distance is not None and distance > window_seconds:
                    continue
            # A bridge may be a low-level audit record without a username; its
            # purpose is to carry PID/serial/session/UID context between the
            # execution anchor and a username-bearing identity record.
            et = cls._event_type(event)
            if not (cls._execution(event) or et in cls._IDENTITY_TYPES or cls._process(event)):
                continue
            matched, reasons = cls._strong_identity_relationship(anchor, event)
            if matched:
                bridges.append((event, reasons))
        return bridges

    @classmethod
    def _success_auth(cls, event: dict[str, Any]) -> bool:
        et = cls._event_type(event)
        if et not in {"USER_AUTH", "AUTH", "AUTHENTICATION"}:
            return False
        text = cls._text(event)
        if any(word in text for word in ("failed", "failure", "denied", "invalid", "rejected")):
            return False
        action = cls._norm(event.get("action"))
        return (
            action in {"successful_login", "auth_success", "login_success", "accepted"}
            or any(word in text for word in ("successful", "accepted", "granted", "login succeeded", "logged in"))
        )

    @classmethod
    def _session(cls, event: dict[str, Any]) -> bool:
        """Return True only for explicit session-creation/session-open evidence."""
        et = cls._event_type(event)
        action = cls._norm(event.get("action"))
        result = cls._norm(event.get("result"))
        status = cls._norm(event.get("status"))
        text = cls._text(event)

        explicit_event_types = {"SESSION_OPEN", "SESSION_START", "SESSION"}
        # auditd USER_START is an explicit user/session lifecycle event. It is
        # accepted here only when the record carries a session identifier or
        # explicitly describes session creation, avoiding generic login events.
        if et == "USER_START":
            return bool(
                cls._audit_session(event)
                or any(term in text for term in (
                    "session opened", "session start", "session created",
                    "session established", "new session",
                ))
            )
        explicit_actions = {
            "session_open", "session_start", "session_created",
            "session_create", "session_established", "login_session_open",
        }

        if et in explicit_event_types:
            return not any(word in text for word in (
                "failed", "failure", "denied", "rejected", "invalid",
            ))

        if action in explicit_actions:
            return True

        if et in {"USER_LOGIN", "LOGIN"}:
            explicit_session_values = {
                "session_open", "session_start", "session_created",
                "session_established", "opened", "created",
            }
            if action in explicit_session_values or result in explicit_session_values or status in explicit_session_values:
                return True

        return any(term in text for term in (
            "session opened", "session start", "session created",
            "session established", "new session",
        ))

    @classmethod
    def _has_explicit_privilege_context(cls, event: dict[str, Any]) -> bool:
        et = cls._event_type(event)
        action = cls._norm(event.get("action"))
        process = cls._process(event)
        text = cls._text(event)

        if et in cls._PRIVILEGE_TYPES or action in cls._PRIVILEGE_ACTIONS:
            return True
        if process in cls._PRIVILEGE_PROCESSES:
            return True
        return any(term in text for term in (
            "privilege escalation", "privilege elevation",
            "sudo succeeded", "sudo successful", "elevated privileges",
        ))

    @classmethod
    def _success_privilege(cls, event: dict[str, Any]) -> bool:
        """Require evidence that records a *successful elevation*, not merely a sudo/syscall record.

        Generic SYSCALL/EXECVE rows for sudo are intentionally rejected unless the
        event carries an explicit success signal *and* a non-root -> root identity
        transition. This prevents routine auditd noise from becoming privilege
        escalation evidence.
        """
        if not cls._has_explicit_privilege_context(event):
            return False

        text = cls._text(event)
        if any(word in text for word in (
            "failed", "failure", "denied", "invalid", "rejected",
        )):
            return False

        et = cls._event_type(event)
        action = cls._norm(event.get("action"))
        result = cls._norm(event.get("result"))
        status = cls._norm(event.get("status"))
        process = cls._process(event)

        # Strong, purpose-built event/action signals are sufficient.
        if action in cls._PRIVILEGE_ACTIONS:
            return True
        if any(term in text for term in (
            "privilege escalation successful",
            "privilege elevation successful",
            "sudo succeeded",
            "sudo successful",
            "elevation succeeded",
            "elevated privileges successfully",
        )):
            return True

        explicit_success = {"success", "successful", "yes", "granted", "accepted"}

        # USER_AUTH/USER_ACCT/PRIVILEGE records can explicitly state that sudo
        # authentication/elevation succeeded. They do not need a UID transition
        # because the event itself is the authoritative semantic record.
        if et in {"USER_AUTH", "USER_ACCT", "AUTH", "AUTHENTICATION", "PRIVILEGE", "SUDO", "USER_CMD"}:
            if action in {"successful_login", "auth_success", "login_success", "accepted"}:
                return True
            if result in explicit_success or status in explicit_success:
                return True

        # For low-level audit records, success alone is not enough. Extract the
        # fields from raw audit text when the normalized parser fields are absent.
        euid = cls._norm(event.get("euid"))
        uid = cls._norm(event.get("uid"))
        auid = cls._norm(event.get("auid"))
        if not euid:
            m = re.search(r"\beuid=(?:\"([^\"]+)\"|(\S+))", text, re.I)
            euid = cls._norm((m.group(1) or m.group(2)) if m else "")
        if not uid:
            m = re.search(r"(?<!e)\buid=(?:\"([^\"]+)\"|(\S+))", text, re.I)
            uid = cls._norm((m.group(1) or m.group(2)) if m else "")
        if not auid:
            m = re.search(r"\bauid=(?:\"([^\"]+)\"|(\S+))", text, re.I)
            auid = cls._norm((m.group(1) or m.group(2)) if m else "")

        raw_success = bool(re.search(r"\bsuccess=(?:\"?yes\"?|\"?success(?:ful)?\"?)\b", text, re.I))
        structured_success = result in explicit_success or status in explicit_success

        if et in {"SYSCALL", "EXECVE", "PROCESS_CREATE"} and process in cls._PRIVILEGE_PROCESSES:
            if not (raw_success or structured_success):
                return False
            # Strongest auditd signal: effective UID becomes root while the
            # invoking UID/AUID remains non-root. If both are root, no elevation
            # has been demonstrated.
            # AUID identifies the audit/login identity, not the effective
            # identity that performed this syscall.  A non-root AUID with
            # uid=0/euid=0 is common for ordinary root-owned work performed
            # inside a user session and does not demonstrate elevation.
            # Require an explicit UID -> root EUID transition.
            if euid == "0" and uid not in {"", "0", "root"}:
                return True
            return False

        return False

    @classmethod
    def _execution(cls, event: dict[str, Any]) -> bool:
        return cls._event_type(event) in {"EXECVE", "PROCESS_CREATE", "SYSCALL"}

    @classmethod
    def _source_attribution_candidate(cls, event: dict[str, Any]) -> bool:
        """Only authentication/network records are eligible to fill a source gap."""
        if not cls._norm(event.get("source_ip")):
            return False
        et = cls._event_type(event)
        action = cls._norm(event.get("action"))
        process = cls._process(event)
        return (
            et in cls._AUTH_TYPES
            or et in cls._NETWORK_TYPES
            or action in {"failed_login", "successful_login", "auth_success", "login_success"}
            or process in {"sshd", "ssh", "login", "sshd-session"}
        )

    @classmethod
    def _process_attribution_candidate(cls, event: dict[str, Any]) -> bool:
        """Only identity-bearing records are eligible to fill a process identity gap."""
        if not cls._norm(event.get("username")):
            return False
        et = cls._event_type(event)
        action = cls._norm(event.get("action"))
        process = cls._process(event)
        return (
            et in cls._IDENTITY_TYPES
            or action in {
                "failed_login", "successful_login", "auth_success", "login_success",
                "session_open", "session_start", "session_created",
            }
            or process in {"sshd", "ssh", "login", "sudo", "su", "pkexec", "doas"}
        )

    @classmethod
    def _anchor_events(cls, case_events: list[dict[str, Any]], action_id: str) -> list[dict[str, Any]]:
        if not case_events:
            return []

        if action_id in {"G-001", "G-002"}:
            auth = [
                e for e in case_events
                if cls._event_type(e) in {"USER_AUTH", "AUTH", "AUTHENTICATION"}
            ]
            return auth or case_events

        if action_id == "G-003":
            privilege = [
                e for e in case_events
                if cls._has_explicit_privilege_context(e)
            ]
            return privilege or case_events

        if action_id == "G-004":
            # The gap exists because the linked authentication evidence lacks
            # a source IP. Do not use arbitrary case events as source anchors
            # when an explicit missing-source authentication anchor exists.
            auth = [
                e for e in case_events
                if cls._event_type(e) in {"USER_AUTH", "AUTH", "AUTHENTICATION"}
                and not cls._norm(e.get("source_ip"))
            ]
            return auth or [
                e for e in case_events
                if not cls._norm(e.get("source_ip"))
            ] or case_events

        if action_id == "G-005":
            executions = [
                e for e in case_events
                if cls._execution(e) and not cls._norm(e.get("username"))
            ]
            return executions or [
                e for e in case_events
                if not cls._norm(e.get("username"))
            ] or case_events

        return case_events

    @classmethod
    def _matches(
        cls,
        event: dict[str, Any],
        action_id: str,
        anchors: list[dict[str, Any]],
        window_seconds: int,
        relationship_context: dict[tuple[str, str], tuple[dict[str, Any], list[str]]] | None = None,
    ) -> tuple[bool, list[str], int, float | None]:
        """Return (matched, reasons, score, nearest_distance_seconds)."""
        if action_id == "G-001":
            if not cls._success_auth(event):
                return False, [], 0, None
        elif action_id == "G-002":
            if not cls._session(event):
                return False, [], 0, None
        elif action_id == "G-003":
            if not cls._success_privilege(event):
                return False, [], 0, None
        elif action_id == "G-004":
            if not cls._source_attribution_candidate(event):
                return False, [], 0, None
        elif action_id == "G-005":
            if not cls._process_attribution_candidate(event):
                return False, [], 0, None
        else:
            return False, [], 0, None

        distances = [
            d for anchor in anchors
            if (d := cls._distance(event.get("timestamp"), anchor.get("timestamp"))) is not None
        ]
        nearest = min(distances) if distances else None

        if anchors and nearest is not None and nearest > window_seconds:
            return False, [], 0, nearest

        event_user = cls._norm(event.get("username"))
        event_ip = cls._norm(event.get("source_ip"))
        event_process = cls._process(event)

        anchor_users = {cls._norm(a.get("username")) for a in anchors if cls._norm(a.get("username"))}
        anchor_ips = {cls._norm(a.get("source_ip")) for a in anchors if cls._norm(a.get("source_ip"))}
        anchor_processes = {cls._process(a) for a in anchors if cls._process(a)}
        anchor_identities = [cls._audit_identity(a) for a in anchors]
        anchor_pids = {x["pid"] for x in anchor_identities if x["pid"]}
        anchor_ppids = {x["ppid"] for x in anchor_identities if x["ppid"]}
        anchor_uids = {x["uid"] for x in anchor_identities if x["uid"]}
        anchor_auids = {x["auid"] for x in anchor_identities if x["auid"]}
        anchor_serials = {x["audit_serial"] for x in anchor_identities if x["audit_serial"]}
        anchor_sessions = {x["audit_session"] for x in anchor_identities if x["audit_session"]}

        reasons: list[str] = []
        score = 1

        event_identity = cls._audit_identity(event)
        event_pid = event_identity["pid"]
        event_ppid = event_identity["ppid"]
        event_uid = event_identity["uid"]
        event_auid = event_identity["auid"]
        event_serial = event_identity["audit_serial"]
        event_session = event_identity["audit_session"]

        same_user = bool(event_user and event_user in anchor_users)
        same_ip = bool(event_ip and event_ip in anchor_ips)
        same_process = bool(event_process and event_process in anchor_processes)
        same_pid = bool(event_pid and event_pid in anchor_pids)
        same_ppid = bool(event_ppid and event_ppid in anchor_ppids)
        same_uid = bool(event_uid and event_uid in anchor_uids)
        same_auid = bool(event_auid and event_auid in anchor_auids)
        same_serial = bool(event_serial and event_serial in anchor_serials)
        same_session = bool(event_session and event_session in anchor_sessions)

        if same_user:
            reasons.append("same username")
            score += 3
        if same_ip:
            reasons.append("same source IP")
            score += 4
        if same_process:
            reasons.append("same process")
            score += 2
        if same_pid:
            reasons.append("same PID")
            score += 5
        if same_ppid:
            reasons.append("same parent PID")
            score += 4
        if same_auid:
            reasons.append("same audit user ID")
            score += 4
        if same_uid:
            reasons.append("same UID")
            score += 3
        if same_serial:
            reasons.append("same audit serial")
            score += 5
        if same_session:
            reasons.append("same audit session")
            score += 6
        if nearest is not None:
            reasons.append(f"within {int(nearest)}s of linked evidence")
            score += 2

        if action_id == "G-003":
            # Low-level audit rows can prove a UID -> root-EUID transition, but
            # the transition must also be attributable to the privilege activity
            # represented by the linked evidence. Same-process + a wide time
            # window is too weak: it routinely turns unrelated sudo/auditd rows
            # into candidates.
            et = cls._event_type(event)
            if et in {"SYSCALL", "EXECVE", "PROCESS_CREATE"}:
                identity_link = (
                    same_pid or same_ppid or same_auid or same_uid
                    or same_serial or same_session or same_user or same_ip
                )
                if not identity_link:
                    # Preserve the useful case where a privilege anchor has no
                    # audit identity fields, but require tight temporal coupling
                    # instead of the full +/-5 minute investigation window.
                    # Five seconds is intentionally conservative and is covered
                    # by the v0.5.13 transition regression.
                    if not same_process or nearest is None or nearest > 5:
                        return False, [], 0, nearest
                    reasons.append("tight privilege-process correlation")
                    score += 4
                else:
                    reasons.append("identity-correlated privilege transition")
                    score += 5
                reasons.append("non-root UID to root EUID transition")
                score += 4

        if action_id == "G-004":
            # A source attribution result must actually connect to the missing
            # source anchor. Otherwise any IP-bearing log in the time window
            # becomes a false attribution candidate.
            # Source attribution is identity-sensitive: prefer the same
            # authenticated username. A shared daemon such as ``sshd`` is too
            # broad because many users can legitimately use the same process.
            if anchor_users and not same_user:
                return False, [], 0, nearest
            if not anchor_users and not same_process:
                return False, [], 0, nearest
            reasons.append("provides source IP")
            score += 2

        if action_id == "G-005":
            # Direct identity links are preferred. If the anchor is incomplete,
            # allow a two-hop relationship through a strong audit/process record.
            # The bridge must share an explicit identity key with the anchor and
            # the candidate must share an explicit identity key with that bridge.
            direct = (
                same_process or same_ip or same_pid or same_ppid
                or same_auid or same_uid or same_serial or same_session
            )
            bridge_reason = []
            if not direct and relationship_context:
                # Query only bridges sharing an explicit identity field with the
                # candidate instead of scanning every bridge for every candidate.
                checked_bridges = set()
                for identity_key in cls._strong_identity_index_keys(event):
                    bridge_entry = relationship_context.get(identity_key)
                    if bridge_entry is None:
                        continue
                    bridge, anchor_link_reasons = bridge_entry
                    bridge_key = (
                        cls._norm(bridge.get("evidence_id")),
                        cls._norm(bridge.get("line")),
                        cls._norm(bridge.get("timestamp")),
                    )
                    if bridge_key in checked_bridges:
                        continue
                    checked_bridges.add(bridge_key)
                    bridge_match, candidate_link_reasons = cls._strong_identity_relationship(event, bridge)
                    if bridge_match:
                        bridge_reason = list(dict.fromkeys(
                            ["relationship-chain attribution"]
                            + [f"bridge: {r}" for r in anchor_link_reasons]
                            + [f"bridge candidate: {r}" for r in candidate_link_reasons]
                        ))
                        direct = True
                        score += 7
                        break
            if not direct:
                return False, [], 0, nearest
            if bridge_reason:
                reasons.extend(bridge_reason)
            reasons.append("provides username")
            score += 2

        return True, reasons, score, nearest

    @classmethod
    def _dedupe_key(cls, event: dict[str, Any], action_id: str) -> tuple[str, ...]:
        if action_id == "G-004":
            return (
                cls._norm(event.get("source_ip")),
                cls._norm(event.get("username")),
                cls._process(event),
                cls._norm(event.get("action")),
                cls._event_type(event),
            )
        if action_id == "G-005":
            return (
                cls._norm(event.get("username")),
                cls._process(event),
                cls._norm(event.get("source_ip")),
                cls._norm(event.get("action")),
                cls._event_type(event),
            )
        return (
            cls._norm(event.get("evidence_id")),
            cls._norm(event.get("source_file")),
            cls._norm(event.get("line")),
            cls._norm(event.get("timestamp")),
        )

    @classmethod
    def run(
        cls,
        action_id: str,
        case: dict[str, Any],
        linked_events: Iterable[dict[str, Any]],
        candidate_events: Iterable[dict[str, Any]],
        window_seconds: int | None = None,
    ) -> dict[str, Any]:
        if action_id not in cls.ACTIONS:
            raise ValueError(f"Unknown investigation action: {action_id}")

        window = int(window_seconds or cls.WINDOW_SECONDS)
        linked = [dict(e) for e in linked_events]
        candidates = [dict(e) for e in candidate_events]

        linked_ids = {
            cls._norm(e.get("evidence_id"))
            for e in linked
            if cls._norm(e.get("evidence_id"))
        }
        linked_keys = {
            (
                cls._norm(e.get("source_file")),
                cls._norm(e.get("line")),
                cls._norm(e.get("timestamp")),
            )
            for e in linked
        }

        anchors = cls._anchor_events(linked, action_id)
        results: list[dict[str, Any]] = []
        seen = set()
        qualifying_count = 0
        rejected_process_candidates = 0
        relationship_bridge_count = 0

        # Build the G-005 relationship index once. v0.5.16 rebuilt and rescanned
        # the bridge graph for every candidate, which is quadratic on realistic
        # log volumes and can freeze the Qt GUI.
        relationship_context: dict[tuple[str, str], tuple[dict[str, Any], list[str]]] = {}
        if action_id == "G-005":
            relationship_context = cls._build_relationship_bridge_index(
                anchors, candidates, window_seconds=window
            )

        for raw in candidates:
            event = dict(raw)
            eid = cls._norm(event.get("evidence_id"))

            if eid and eid in linked_ids:
                continue

            raw_key = (
                cls._norm(event.get("source_file")),
                cls._norm(event.get("line")),
                cls._norm(event.get("timestamp")),
            )
            if raw_key[0] and raw_key in linked_keys:
                continue

            matched, reasons, score, nearest = cls._matches(
                event, action_id, anchors, window, relationship_context
            )
            if not matched:
                if action_id == "G-005" and cls._process_attribution_candidate(event):
                    rejected_process_candidates += 1
                continue
            if action_id == "G-005" and any(r == "relationship-chain attribution" for r in reasons):
                relationship_bridge_count += 1
            if anchors and nearest is None:
                continue

            qualifying_count += 1
            event["_match_score"] = score
            event["_match_reasons"] = reasons
            event["_distance_seconds"] = nearest
            event["_action_id"] = action_id
            results.append(event)

        # Attribution gaps often contain hundreds of repeated auth records.
        # Keep the strongest/closest representative for each semantic event
        # signature, while retaining enough unique candidates for analyst review.
        if action_id in {"G-004", "G-005"}:
            grouped: dict[tuple[str, ...], dict[str, Any]] = {}
            for event in results:
                key = cls._dedupe_key(event, action_id)
                current = grouped.get(key)
                if current is None:
                    grouped[key] = event
                    continue
                current_rank = (
                    -int(current.get("_match_score", 0)),
                    float(current.get("_distance_seconds") or 10**12),
                    str(current.get("timestamp", "")),
                    str(current.get("line", "")),
                )
                candidate_rank = (
                    -int(event.get("_match_score", 0)),
                    float(event.get("_distance_seconds") or 10**12),
                    str(event.get("timestamp", "")),
                    str(event.get("line", "")),
                )
                if candidate_rank < current_rank:
                    grouped[key] = event
            results = list(grouped.values())

        results.sort(
            key=lambda item: (
                -int(item.get("_match_score", 0)),
                float(item.get("_distance_seconds") or 10**12),
                str(item.get("timestamp", "")),
                str(item.get("line", "")),
            )
        )

        truncated = len(results) > cls.MAX_REPRESENTATIVE_RESULTS
        if truncated:
            results = results[:cls.MAX_REPRESENTATIVE_RESULTS]

        limitations = [
            "Results are deterministic matches against the currently loaded event dataset.",
            "A match does not establish causation, malicious intent, or compromise.",
            "Only evidence within the configured investigation window is considered when timestamps are available.",
        ]
        if action_id in {"G-004", "G-005"}:
            limitations.append(
                "Repeated attribution records are collapsed to representative candidates; "
                "the representative row is the strongest/closest record for its event signature."
            )
        diagnostics: dict[str, Any] = {}
        if action_id == "G-005":
            anchor_coverage = {
                "process": sum(bool(cls._process(a)) for a in anchors),
                "pid": sum(bool(cls._audit_identity(a)["pid"]) for a in anchors),
                "ppid": sum(bool(cls._audit_identity(a)["ppid"]) for a in anchors),
                "uid": sum(bool(cls._audit_identity(a)["uid"]) for a in anchors),
                "auid": sum(bool(cls._audit_identity(a)["auid"]) for a in anchors),
                "audit_serial": sum(bool(cls._audit_identity(a)["audit_serial"]) for a in anchors),
                "audit_session": sum(bool(cls._audit_identity(a)["audit_session"]) for a in anchors),
                "source_ip": sum(bool(cls._norm(a.get("source_ip"))) for a in anchors),
            }
            diagnostics = {
                "username_candidates_rejected": rejected_process_candidates,
                "relationship_chain_matches": relationship_bridge_count,
                "anchor_identity_coverage": anchor_coverage,
                "accepted_relationships": [
                    "same audit serial", "same audit session", "same PID",
                    "same parent PID", "same audit user ID", "same UID",
                    "same source IP", "same process",
                    "or a two-hop relationship through a strongly linked audit/process record",
                ],
            }

        if not results:
            if action_id == "G-002":
                limitations.append(
                    "No explicit session-open/session-start evidence was found; authentication "
                    "success or failure alone does not establish session creation."
                )
            elif action_id == "G-003":
                limitations.append(
                    "No explicit successful privilege-elevation signal was found; generic "
                    "SYSCALL/EXECVE activity and ordinary commands are excluded."
                )
            elif action_id == "G-004":
                limitations.append(
                    "No source candidate was accepted because a source-bearing event must also "
                    "share the linked username or process context."
                )
            elif action_id == "G-005":
                limitations.append(
                    "No process-identity candidate was accepted. Direct attribution requires an "
                    "explicit process/audit relationship (process, source IP, PID/PPID, UID/AUID, "
                    "audit serial, or audit session); a two-hop relationship is accepted only "
                    "through a strongly linked intermediate audit/process record."
                )
                coverage = diagnostics.get("anchor_identity_coverage", {})
                if coverage:
                    limitations.append(
                        "Anchor identity coverage: "
                        + ", ".join(f"{k}={v}" for k, v in coverage.items())
                        + "."
                    )
                if rejected_process_candidates:
                    limitations.append(
                        f"{rejected_process_candidates} username-bearing candidate(s) were rejected "
                        "because no qualifying identity relationship could be established."
                    )

        return {
            "action_id": action_id,
            "action": dict(cls.ACTIONS[action_id]),
            "case_id": str(case.get("case_id", "")),
            "window_seconds": window,
            "anchor_evidence_ids": [
                str(e.get("evidence_id", "")).strip()
                for e in anchors
                if str(e.get("evidence_id", "")).strip()
            ],
            "match_count": len(results),
            "qualifying_match_count": qualifying_count,
            "representative_match_count": len(results),
            "truncated": truncated,
            "results": results,
            "limitations": limitations,
            "diagnostics": diagnostics,
        }
