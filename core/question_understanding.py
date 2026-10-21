"""Deterministic question understanding for LogAsis.

Turns an arbitrary natural-language question about the loaded log into a
structured analysis: intent, concrete entities resolved against the *actual*
schema (dynamic discovery, no hard-coded field list), time constraints, and
proof/causality detection. No security conclusions are produced here and no
ground-truth knowledge is embedded: every mapping below is standard
security-log vocabulary or well-known service ports, and every candidate
filter is validated against the loaded dataset's real distinct values before
it is used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Standard security-log vocabulary. These tables normalize common phrasing to
# the canonical values used by structured logs. They are applied only when the
# resulting value actually exists in the loaded dataset.
# ---------------------------------------------------------------------------

_ACTION_PHRASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bfailed\s+(?:ssh\s+|rdp\s+|remote\s+)?(?:login|logon|logons|authentication|auth|sign-?in|attempt)s?", re.I), "failed_login"),
    (re.compile(r"\bfailed\s+log(?:ins?|ons?)\b|\bfailed\s+authentications?\b|\blogin\s+failures?\b", re.I), "failed_login"),
    (re.compile(r"\bsuccessful\s+(?:ssh\s+|rdp\s+|remote\s+)?(?:login|logon|logons|authentication|auth|sign-?in)s?", re.I), "successful_login"),
    (re.compile(r"\bsuccessful\s+logins?\b|\bsuccessful\s+authentications?\b", re.I), "successful_login"),
    (re.compile(r"\bcommand\s+executions?\b|\bcommands?\s+(?:were\s+|was\s+)?executed\b", re.I), "command_executed"),
    (re.compile(r"\bcommand\s+denials?\b|\bcommands?\s+(?:were\s+|was\s+)?denied\b", re.I), "command_denied"),
    (re.compile(r"\bblocked\b", re.I), "blocked"),
    (re.compile(r"\ballowed\b|\bpermitted\b", re.I), "allowed"),
    (re.compile(r"\bdenied\b|\bdenied\s+access\b", re.I), "denied"),
]

_EVENT_TYPE_PHRASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bprocess-?start\b|\bprocess\s+creation\b|\bprocess\s+create\b", re.I), "process_start"),
    (re.compile(r"\bdns\s+(?:queries?|query|lookups?|requests?)\b|\bdns\b", re.I), "dns_query"),
    (re.compile(r"\bweb\s+(?:requests?|access)\b|\bhttp\s+requests?\b", re.I), "web_access"),
    (re.compile(r"\bfirewall\b", re.I), "firewall"),
    (re.compile(r"\boutbound\s+(?:connections?|traffic|flows?)\b|\bconnections?\s+to\b", re.I), "firewall"),
    (re.compile(r"\baudit\b", re.I), "audit"),
    (re.compile(r"\bauthentication\s+(?:events?|attempts?|activity)\b|\bauth\s+events?\b", re.I), "authentication"),
    (re.compile(r"\b(?:failed|successful)\s+(?:ssh\s+|rdp\s+)?log(?:ins?|ons?)\b", re.I), "authentication"),
    (re.compile(r"\blogin\s+events?\b|\blogon\s+events?\b", re.I), "authentication"),
]

# Well-known service ports (standard IANA assignments; used only when a
# destination_port / port field exists in the dataset).
_SERVICE_PORTS = {
    "ssh": "22", "rdp": "3389", "https": "443", "http": "80", "dns": "53",
    "smb": "445", "ftp": "21", "smtp": "25", "telnet": "23",
}

PROOF_RE = re.compile(
    r"\b(?:do(?:es)?\s+the\s+(?:logs?|log|evidence|data)|can\s+we\s+conclude|"
    r"\bdo\s+the\s+logs\b|\bdid\s+the\b|"
    r"prove[sd]?|proves?\b|confirm[sed]?\b|establish(?:es|ed)?\b)",
    re.I,
)
CAUSAL_RE = re.compile(
    r"\b(?:caus(?:e|ed|es|ing|ation)|led\s+to|resulted\s+in|triggered|because\s+of|due\s+to)\b",
    re.I,
)
CONCLUSION_TERMS_RE = re.compile(
    r"\b(?:compromis(?:e|ed)|breach(?:ed)?|exfiltrat(?:e|ed|ion)|malware|"
    r"infect(?:ed|ion)|exploit(?:ed|ation)?|attack(?:ed)?|intrusion|"
    r"privilege\s+escalation|data\s+theft|backdoor|s(?:q)?l\s+injection|injection)\b",
    re.I,
)
SEQUENCE_REFERENCE_RE = re.compile(
    r"\b(?:explicitly\s+(?:represented|constructed|recorded)\b[^.?]*\b(?:in\s+the\s+)?"
    r"(?:labelled|labeled|tagged)[^.?]*\bsequence\b|"
    r"\b(?:labelled|labeled|tagged)\s+[a-z\- ]*sequence\b|"
    r"\bin\s+the\s+sequence\b)",
    re.I,
)
COUNT_INTENT_RE = re.compile(r"\bhow\s+many\b|\bcount\b|\bnumber\s+of\b", re.I)
LIST_INTENT_RE = re.compile(r"\bwhich\s+|\blist\b|\bshow\b|\bwhat\s+(?:events|records|users|hosts|ips|files)\b", re.I)
TIMELINE_RE = re.compile(r"\btimeline\b|\bchronolog(?:y|ical)\b|\border\s+of\s+events\b|\bsequence\s+of\s+events\b", re.I)
CORRELATION_RE = re.compile(r"\bcorrelat(?:e|ion|ed)\b|\brelated\s+events\b|\bassociation\b", re.I)
FIRST_LAST_RE = re.compile(r"\bfirst\b|\blast\b|\blatest\b|\bmost\s+recent\b|\boldest\b|\bnewest\b", re.I)
WHAT_WHICH_RE = re.compile(r"^\s*(?:what|which|who(?:'s|se)?|name\s+of)\b|\bwhat\s+(?:is|was|are|were)\b|\bwhich\b", re.I)

# "What binary...?", "Which PID...?", "What CVE...?" — the question asks the
# analyst to IDENTIFY a concrete value in the data, not to count events.
_EXTRACT_KIND_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("cve", re.compile(r"\bcve\b|vulnerabilit", re.I)),
    ("pid", re.compile(r"\bpids?\b|process\s+ids?\b", re.I)),
    ("process", re.compile(r"\bbinar(?:y|ies)\b|executables?\b|\bprocess(?:es)?\b|\bimages?\b|\btools?\b|utilit|\bprograms?\b|payload", re.I)),
    ("file", re.compile(r"\bfiles?\b|\bpaths?\b|filenames?\b|documents?\b", re.I)),
    ("user", re.compile(r"accounts?\b|users?\b|usernames?\b|credentials?\b", re.I)),
    ("ip", re.compile(r"\bips?\b|\baddress(?:es)?\b", re.I)),
    ("domain", re.compile(r"domains?\b|hostnames?\b", re.I)),
    ("hash", re.compile(r"hash(?:es)?\b", re.I)),
    ("url", re.compile(r"\burls?\b|uris?\b", re.I)),
]

# Kinds that are security CONCLUSIONS rather than observable field values:
# the deterministic layer answers them with a qualified direct refusal plus
# what the log actually shows, never with an invented label.
_CONCLUSION_KINDS = {
    "attack type": re.compile(r"attack\s+types?\b|attack\s+vector\b|techniques?\b|method\s+(?:of|used)", re.I),
    "compromise": re.compile(r"compromis", re.I),
    "attacker attribution": re.compile(r"attackers?\b|threat\s+actors?\b", re.I),
    "exfiltration": re.compile(r"exfiltrat|data\s+(?:theft|leak|stolen)|stole\s+(?:data|files)", re.I),
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r"\bport\s*(?:number\s*)?[=: ]\s*(\d{1,5})\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)
_URL_RE = re.compile(r"https?://[^\s,;\"']+", re.I)
_QUOTED_RE = re.compile(r"[\"']([^\"']{2,80})[\"']")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)
_EXE_RE = re.compile(r"\b[\w.\-]+\.(?:exe|dll|ps1|bat|cmd|sh|bin|py|js|vbs)\b", re.I)
_PATH_RE = re.compile(r"(?<![\w])(?:[A-Za-z]:\\[^\s,;\"']+|/[\w.@:+~-]+(?:/[^\s,;\"']+)*)")
_HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)

# Phrases that explicitly name the field a value belongs to.
_FIELD_HINTS = [
    ("parent_process", re.compile(r"(?:as\s+the\s+)?parent\s+(?:process|image)\b", re.I)),
    ("process", re.compile(r"(?:as\s+the\s+)?process(?:\s+name)?\b|\bprocess\s+(?:named|called)\b", re.I)),
    ("user", re.compile(r"\b(?:for\s+|by\s+|from\s+)?user\s+(?:named\s+)?|\baccount\s+named\b", re.I)),
    ("host", re.compile(r"\b(?:on|from|to)\s+host\b|\bhost\s+(?:named|called)\b", re.I)),
    ("destination_port", re.compile(r"\b(?:on\s+)?port\b|\bdestination\s+port\b", re.I)),
    ("status_code", re.compile(r"\bhttp\s+(?:status\s+)?(?:code\s+)?|\bstatus\s+code\b", re.I)),
]

_TIME_ABS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?))?\b")
_TIME_REL_RE = re.compile(
    r"\bin\s+the\s+(?:last|past)\s+(\d+)\s*(second|minute|hour|day|week)s?\b", re.I
)
_TIME_AFTER_RE = re.compile(r"\bafter\s+(?:the\s+)?([a-z0-9_\-\.\s]{3,40}?)(?=[,?.]|$|\bon\b|\bfrom\b)", re.I)


@dataclass
class ResolvedEntity:
    """A concrete value resolved to an actual dataset field."""
    field: str
    value: str
    source: str  # "literal" | "phrase" | "port" | "hint"
    precision: str  # "exact" | "mapped"

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "value": self.value, "source": self.source, "precision": self.precision}


@dataclass
class TimeConstraint:
    kind: str  # "absolute_range" | "after" | "before" | "relative_back" | "after_event"
    start: str = ""
    end: str = ""
    anchor_event: str = ""  # description of the anchor event set for "after X"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "start": self.start, "end": self.end, "anchor_event": self.anchor_event}


@dataclass
class QuestionAnalysis:
    question: str
    intent: str = "explanation"  # count|list|timeline|correlation|comparison|explanation|proof|causality|extract
    wants_count: bool = False
    wants_list: bool = False
    wants_timeline: bool = False
    proof_requested: bool = False
    causality_requested: bool = False
    conclusion_terms: list[str] = field(default_factory=list)
    # Concrete value kinds the question asks to IDENTIFY ("what binary",
    # "which PID", "what CVE"). Filled only for extraction-style questions.
    extract_kinds: list[str] = field(default_factory=list)
    conclusion_kinds: list[str] = field(default_factory=list)
    entities: list[ResolvedEntity] = field(default_factory=list)
    event_type_candidates: list[str] = field(default_factory=list)
    action_candidates: list[str] = field(default_factory=list)
    time_constraints: list[TimeConstraint] = field(default_factory=list)
    sequence_reference: bool = False
    exhaustive: bool = False
    unresolved_references: list[str] = field(default_factory=list)
    interpretation_notes: list[str] = field(default_factory=list)
    # Entities carried from earlier session turns. For proof/abstention
    # questions these are used as SEPARATE observation lenses (never ANDed
    # into the main filters) so the refusal can report what each referenced
    # activity looks like without over-constraining.
    context_entities: list[ResolvedEntity] = field(default_factory=list)
    status_code: str = ""
    relative_anchor: str = ""  # e.g. "failures" for "after the failures"

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "intent": self.intent,
            "wants_count": self.wants_count,
            "proof_requested": self.proof_requested,
            "causality_requested": self.causality_requested,
            "conclusion_terms": self.conclusion_terms,
            "extract_kinds": self.extract_kinds,
            "conclusion_kinds": self.conclusion_kinds,
            "entities": [e.to_dict() for e in self.entities],
            "event_type_candidates": self.event_type_candidates,
            "action_candidates": self.action_candidates,
            "time_constraints": [t.to_dict() for t in self.time_constraints],
            "sequence_reference": self.sequence_reference,
            "exhaustive": self.exhaustive,
            "unresolved_references": self.unresolved_references,
        }


class QuestionSchema:
    """Dynamic view of the loaded dataset used to resolve question values.

    Built once per question batch; wraps the EventIndex so every candidate
    filter value is verified against real distinct values (never invented).
    """

    _PREFERRED_CATEGORICAL = (
        "event_type", "action", "severity", "event_id", "outcome",
        "auth_method", "logon_type", "http_method", "protocol", "rule_name",
    )

    def __init__(self, index: Any):
        self.index = index
        self.fields: list[str] = [f for f in index.search_fields if f not in {"timestamp_dt", "hour", "date", "raw_log"}]
        self._distinct: dict[str, list[str]] = {}
        self._value_fields: dict[str, list[str]] = {}

    def distinct(self, field_name: str) -> list[str]:
        if field_name not in self._distinct:
            vals = self.index.distinct_values(field_name) if field_name in self.fields else []
            self._distinct[field_name] = vals
        return self._distinct[field_name]

    def has_value(self, field_name: str, value: str) -> bool:
        target = str(value or "").strip().lower()
        if not target:
            return False
        for candidate in self.distinct(field_name):
            if str(candidate).strip().lower() == target:
                return True
        return False

    def fields_containing(self, value: str) -> list[str]:
        """All fields whose distinct values contain this exact value.

        Ordered: preferred categorical fields first, then by ascending
        cardinality (more specific fields first).
        """
        key = str(value or "").strip().lower()
        if not key:
            return []
        if key in self._value_fields:
            return self._value_fields[key]
        matches: list[tuple[int, str]] = []
        for fname in self.fields:
            if fname in {"line", "timestamp"}:
                continue
            if self.has_value(fname, value):
                cardinality = len(self.distinct(fname))
                priority = 0 if fname in self._PREFERRED_CATEGORICAL else 1
                matches.append((priority, f"{cardinality:08d}", fname))
        matches.sort()
        result = [fname for _, _, fname in matches]
        self._value_fields[key] = result
        return result

    def canonical_field(self, logical: str) -> str | None:
        """Map a logical field name to the actual dataset field."""
        aliases = {
            "user": ("user", "username", "account", "acct"),
            "username": ("username", "user", "account", "acct"),
            "process": ("process", "process_name", "image", "exe"),
            "parent_process": ("parent_process", "parent_image", "parentprocessname"),
            "host": ("host", "hostname", "computer", "computer_name"),
            "source_ip": ("source_ip", "src_ip", "client_ip", "sourceaddress"),
            "destination_ip": ("destination_ip", "dst_ip", "dest_ip", "destinationaddress"),
            "destination_port": ("destination_port", "dst_port", "dest_port"),
            "source_port": ("source_port", "src_port"),
            "domain": ("domain", "queryname", "dns_query", "query"),
            "url": ("url", "uri", "request_url"),
            "status_code": ("status_code", "status", "http_status"),
            "port": ("destination_port", "port", "dst_port"),
        }
        for candidate in aliases.get(logical, (logical,)):
            if candidate in self.fields:
                return candidate
        return None


def analyze_question(question: str, schema: QuestionSchema) -> QuestionAnalysis:
    """Produce a deterministic structural analysis of the question."""
    q = str(question or "").strip()
    analysis = QuestionAnalysis(question=q)

    lower = q.lower()

    # --- intent -----------------------------------------------------------
    analysis.proof_requested = bool(PROOF_RE.search(q)) and bool(CONCLUSION_TERMS_RE.search(q) or CAUSAL_RE.search(q))
    analysis.causality_requested = bool(CAUSAL_RE.search(q))
    analysis.conclusion_terms = sorted({m.group(0).lower() for m in CONCLUSION_TERMS_RE.finditer(q)})
    analysis.wants_count = bool(COUNT_INTENT_RE.search(q))
    analysis.wants_list = bool(LIST_INTENT_RE.search(q))
    analysis.wants_timeline = bool(TIMELINE_RE.search(q))
    analysis.sequence_reference = bool(SEQUENCE_REFERENCE_RE.search(q))
    # Extraction questions ("What binary and PID were used...", "Which CVE...")
    # ask to IDENTIFY concrete values. They never coexist with a count intent.
    if not analysis.wants_count and WHAT_WHICH_RE.search(q):
        for kind, pattern in _EXTRACT_KIND_PATTERNS:
            if pattern.search(q) and kind not in analysis.extract_kinds:
                analysis.extract_kinds.append(kind)
        for label, pattern in _CONCLUSION_KINDS.items():
            if pattern.search(q) and label not in analysis.conclusion_kinds:
                analysis.conclusion_kinds.append(label)
        # "What files did the attacker access?" asks for the FILES; the bare
        # 'attacker' mention is context, not the question's subject. The
        # attacker-attribution conclusion only applies when the question
        # itself asks for the attacker's identity (IP/account questions).
        if "attacker attribution" in analysis.conclusion_kinds and analysis.extract_kinds:
            if not any(k in analysis.extract_kinds for k in ("ip", "user")):
                analysis.conclusion_kinds.remove("attacker attribution")
    if analysis.proof_requested:
        analysis.intent = "causality" if analysis.causality_requested else "proof"
    elif analysis.causality_requested:
        analysis.intent = "causality"
    elif analysis.wants_timeline or FIRST_LAST_RE.search(q):
        analysis.intent = "timeline"
    elif CORRELATION_RE.search(q):
        analysis.intent = "correlation"
    elif analysis.wants_count:
        analysis.intent = "count"
    elif analysis.extract_kinds or analysis.conclusion_kinds:
        analysis.intent = "extract"
    elif analysis.wants_list:
        analysis.intent = "list"
    analysis.exhaustive = analysis.intent in {"count", "list", "timeline"}

    # --- literal entities ---------------------------------------------------
    resolved: list[ResolvedEntity] = []
    _service_tokens: set[str] = set()

    def add(field: str, value: str, source: str, precision: str) -> None:
        canonical = schema.canonical_field(field) or field
        for existing in resolved:
            if existing.field == canonical and existing.value.lower() == str(value).lower():
                return
        resolved.append(ResolvedEntity(canonical, str(value), source, precision))

    # IP addresses, with source/destination resolution via prepositions.
    # The preposition immediately preceding the IP wins ("from X" -> source,
    # "to X" -> destination), because a window like "from A to B" contains
    # both words for the second address.
    for match in _IP_RE.finditer(q):
        ip = match.group(0)
        prefix = lower[max(0, match.start() - 30):match.start()]
        owning = schema.fields_containing(ip)
        chosen = ""
        from_idx = prefix.rfind(" from ")
        to_idx = prefix.rfind(" to ")
        if from_idx > to_idx and "source_ip" in owning:
            chosen = "source_ip"
        elif to_idx > from_idx and "destination_ip" in owning:
            chosen = "destination_ip"
        elif from_idx > to_idx and owning:
            chosen = owning[0] if "source_ip" not in owning else "source_ip"
        elif to_idx > from_idx and owning:
            chosen = owning[0] if "destination_ip" not in owning else "destination_ip"
        elif owning:
            chosen = owning[0]
        if chosen:
            add(chosen, ip, "literal", "exact")

    # Port numbers.
    for match in _PORT_RE.finditer(q):
        port = match.group(1)
        fname = schema.canonical_field("destination_port") or schema.canonical_field("port")
        if fname and schema.has_value(fname, port):
            add(fname, port, "literal", "exact")

    # Service names -> well-known ports. Skipped when the service word
    # directly qualifies a status code ("HTTP 200 requests") -- there it
    # names the request protocol, not a port.
    for service, port in _SERVICE_PORTS.items():
        service_match = re.search(rf"\b{service}\b", q, re.I)
        if not service_match:
            continue
        tail = q[service_match.end():service_match.end() + 8]
        if re.match(r"\s*[1-5]\d{2}\b", tail):
            continue
        fname = schema.canonical_field("destination_port")
        if fname and schema.has_value(fname, port):
            add(fname, port, "port", "mapped")
            _service_tokens.add(service.lower())

    # CVEs / URLs / hashes: exact literals.
    for match in _CVE_RE.finditer(q):
        owning = schema.fields_containing(match.group(0).upper()) or schema.fields_containing(match.group(0))
        if owning:
            add(owning[0], match.group(0), "literal", "exact")
    for match in _URL_RE.finditer(q):
        owning = schema.fields_containing(match.group(0))
        if owning:
            add(owning[0], match.group(0), "literal", "exact")
    for match in _HASH_RE.finditer(q):
        owning = schema.fields_containing(match.group(0))
        if owning:
            add(owning[0], match.group(0), "literal", "exact")

    # Executables -> process/parent_process by hint, else field discovery.
    for match in _EXE_RE.finditer(q):
        exe = match.group(0)
        prefix = lower[max(0, match.start() - 40):match.start()]
        owning = schema.fields_containing(exe)
        if not owning:
            continue
        chosen = ""
        if re.search(r"parent\s+(?:process|image)?\s*$|as\s+the\s+parent\s+process\s*$", prefix) and any(
            f in owning for f in ("parent_process", "parent_image")
        ):
            chosen = next(f for f in ("parent_process", "parent_image") if f in owning)
        elif re.search(r"as\s+the\s+process\s*$|\bprocess\b", prefix) and any(
            f in owning for f in ("process", "process_name")
        ):
            chosen = next(f for f in ("process", "process_name") if f in owning)
        else:
            chosen = owning[0]
        add(chosen, exe, "literal", "exact")

    # File paths.
    for match in _PATH_RE.finditer(q):
        path = match.group(0).rstrip(".,;:)")
        owning = schema.fields_containing(path)
        if owning:
            add(owning[0], path, "literal", "exact")

    # Domains (skip values already resolved, and non-domain patterns).
    already = {e.value.lower() for e in resolved}
    for match in _DOMAIN_RE.finditer(q):
        domain = match.group(0)
        if domain.lower() in already or _IP_RE.fullmatch(domain):
            continue
        owning = schema.fields_containing(domain)
        if owning:
            add(owning[0], domain, "literal", "exact")

    # Quoted values.
    for match in _QUOTED_RE.finditer(q):
        value = match.group(1)
        owning = schema.fields_containing(value)
        if owning:
            add(owning[0], value, "literal", "exact")

    # --- event type and action phrases (schema-validated) --------------------
    for pattern, value in _EVENT_TYPE_PHRASES:
        if pattern.search(q):
            fname = schema.canonical_field("event_type") or "event_type"
            if fname in schema.fields and schema.has_value(fname, value):
                analysis.event_type_candidates.append(value)
    for pattern, value in _ACTION_PHRASES:
        if pattern.search(q):
            fname = schema.canonical_field("action") or "action"
            if fname in schema.fields and schema.has_value(fname, value):
                analysis.action_candidates.append(value)

    # Bare words that exactly match categorical values ("deploy" as user,
    # "sudo" as process, "unknown" as user, hostnames mentioned with "on").
    for token_match in re.finditer(r"[A-Za-z0-9_.:@\-]{2,}", q):
        token = token_match.group(0)
        if token.lower() in already or len(token) < 2:
            continue
        if _IP_RE.fullmatch(token) or _EXE_RE.fullmatch(token):
            continue
        # Service words are already expressed through their port mapping;
        # also using them as field filters (e.g. auth_method=RDP) would
        # over-constrain queries in ways the question did not ask for.
        if token.lower() in _service_tokens:
            continue
        prefix = lower[max(0, token_match.start() - 24):token_match.start()]
        owning = schema.fields_containing(token)
        if not owning:
            # Common analyst shorthand: process names quoted without their
            # extension ("PowerShell" for powershell.exe). Only tried for
            # process-family fields, and only when an actual distinct value
            # starts with "<token>." — never a fuzzy match.
            for process_field in ("process", "process_name", "parent_process", "parent_image"):
                if process_field not in schema.fields:
                    continue
                for value in schema.distinct(process_field):
                    candidate = str(value or "").strip()
                    if candidate.lower().startswith(f"{token.lower()}.") and schema.has_value(process_field, candidate):
                        owning = [process_field]
                        break
                if owning:
                    break
        if not owning:
            continue
        # Skip generic English words that happen to match a broad field like
        # message (message is not a filter field for deterministic answers).
        owning = [f for f in owning if f not in {"message", "raw_log", "command", "text", "line", "event_uid"}]
        if not owning:
            continue
        stopword_like = token.lower() in {
            "how", "many", "what", "which", "when", "where", "were", "was", "are",
            "the", "and", "for", "from", "with", "that", "this", "those", "these",
            "logs", "log", "events", "event", "records", "record", "after", "before",
            "between", "during", "show", "list", "did", "do", "does", "can", "we",
            "any", "all", "have", "has", "had", "there", "their", "them", "then",
        }
        if stopword_like:
            continue
        # Privilege-goal phrasing ("used to gain root", "root access",
        # "escalate to root"): the token names the privilege the question is
        # ABOUT, not an account to filter on. Treating it as username=root
        # silently over-constrains the query to root's own records.
        suffix = q[token_match.end():token_match.end() + 24].lower()
        if re.search(r"(?:\b(?:gain|get|obtain|become|achieve|escalat\w+)\s+)+$", prefix) or re.match(
            r"\s+(?:access|privileges?|level)\b", suffix
        ) or re.match(r"\s+was\s+(?:gained|obtained|achieved)\b", suffix):
            continue
        chosen = ""
        # Explicit field-name mention: "<field_name> <value>" binds the value
        # to that dataset field. This supports arbitrary custom/vendor fields
        # without hard-coding a field list.
        prefix_stripped = prefix.strip()
        for candidate_field in schema.fields:
            if candidate_field in {"message", "raw_log", "command", "text", "line", "event_uid", "timestamp"}:
                continue
            if prefix_stripped.endswith(candidate_field.lower()) and schema.has_value(candidate_field, token):
                chosen = candidate_field
                break
        if not chosen and re.search(r"\b(?:for|by)\s+$|\buser\s+$|\busers?\b", prefix) and any(f in owning for f in ("user", "username")):
            chosen = next(f for f in ("user", "username") if f in owning)
        elif re.search(r"\bon\s+$|\bhost\s+$", prefix) and any(f in owning for f in ("host", "hostname")):
            chosen = next(f for f in ("host", "hostname") if f in owning)
        elif re.search(r"\bprocess\b", prefix) and any(f in owning for f in ("process", "process_name")):
            chosen = next(f for f in ("process", "process_name") if f in owning)
        elif len(owning) == 1 and owning[0] in {"user", "username", "host", "hostname", "process", "process_name", "auth_method", "domain", "http_method", "user_agent", "outcome", "logon_type", "severity"}:
            chosen = owning[0]
        if chosen:
            add(chosen, token, "literal", "exact")

    # Status codes ("HTTP 200", "200 responses", "status 200").
    status_match = re.search(r"\b(?:http\s*)?([1-5]\d{2})\b(?:\s*(?:responses?|replies?|status))?", q, re.I)
    if status_match:
        fname = schema.canonical_field("status_code")
        if fname and schema.has_value(fname, status_match.group(1)):
            analysis.status_code = status_match.group(1)

    # --- time constraints ----------------------------------------------------
    for match in _TIME_ABS_RE.finditer(q):
        date, time_part = match.group(1), match.group(2) or ""
        analysis.time_constraints.append(TimeConstraint(
            kind="absolute_range",
            start=f"{date}T{time_part}" if time_part else f"{date}T00:00:00",
            end=f"{date}T23:59:59" if not time_part else "",
        ))
    rel = _TIME_REL_RE.search(q)
    if rel:
        analysis.time_constraints.append(TimeConstraint(kind="relative_back", start=f"{rel.group(1)} {rel.group(2)}"))
    after = _TIME_AFTER_RE.search(q)
    if after and not analysis.proof_requested:
        anchor = after.group(1).strip()
        analysis.relative_anchor = anchor
        analysis.time_constraints.append(TimeConstraint(kind="after_event", anchor_event=anchor))

    analysis.entities = resolved
    # Deduplicate candidates while preserving order.
    analysis.event_type_candidates = list(dict.fromkeys(analysis.event_type_candidates))
    analysis.action_candidates = list(dict.fromkeys(analysis.action_candidates))
    return analysis
