from __future__ import annotations

"""Provider-neutral claim normalization and evidence grounding.

This module deliberately separates three things that older LogAsis releases
mixed together:

* deterministic facts (VERIFIED_FACT)
* evidence-backed analytical inference (GROUNDED_INTERPRETATION)
* unsupported security assertions (UNSUPPORTED_CLAIM)

The provider is never trusted to decide the final class.  The provider may
propose a class, but LogAsis verifies evidence references and concrete event
attributes before accepting it.
"""

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from ai.evidence_grounding import (
    _event_lookup,
    _high_signal_terms,
    _INFERENCE_RE,
    extract_evidence_ids,
)


VERIFIED_FACT = "VERIFIED_FACT"
GROUNDED_INTERPRETATION = "GROUNDED_INTERPRETATION"
RECOMMENDATION = "RECOMMENDATION"
INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
UNSUPPORTED_CLAIM = "UNSUPPORTED_CLAIM"
CONTRADICTED_CLAIM = "CONTRADICTED_CLAIM"

ACCEPTED = "ACCEPTED"
ACCEPTED_AS_INTERPRETATION = "ACCEPTED_AS_INTERPRETATION"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
REJECTED = "REJECTED"
REJECTED_CONTRADICTED = "REJECTED_CONTRADICTED"

HIGH = "HIGH"
MODERATE = "MODERATE"
LOW = "LOW"


def _truncate(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "..."


@dataclass
class GroundedClaim:
    claim_id: str = ""
    text: str = ""
    type: str = UNSUPPORTED_CLAIM
    evidence_references: list[str] = field(default_factory=list)
    confidence: str = MODERATE
    grounding_status: str = "GROUNDED"
    validation_status: str = ACCEPTED
    section: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_confidence(value: Any, default: str = MODERATE) -> str:
    value = str(value or "").strip().upper()
    return value if value in {HIGH, MODERATE, LOW} else default


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first usable JSON object, including fenced JSON output."""
    raw = str(text or "").strip()
    candidates = [raw]
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw, flags=re.I | re.S)
    candidates.extend(fenced)
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if isinstance(value, dict):
            return value
    # Models sometimes put prose around a JSON object. Find balanced braces
    # rather than using a greedy regex that can consume unrelated text.
    start = raw.find("{")
    while start >= 0:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(raw)):
            char = raw[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        value = json.loads(raw[start:index + 1])
                    except (json.JSONDecodeError, TypeError, ValueError):
                        break
                    if isinstance(value, dict):
                        return value
                    break
        start = raw.find("{", start + 1)
    return None


def _section_name(line: str) -> str | None:
    cleaned = str(line or "").strip().replace("**", "")
    match = re.match(r"^[#\-*_\s]*([A-Za-z][A-Za-z0-9 _/&-]{2,})\s*:?[#\-*_\s]*$", cleaned)
    if not match:
        return None
    name = re.sub(r"\s+", " ", match.group(1)).strip().upper()
    known = {
        "DIRECT ANSWER", "OVERALL ASSESSMENT", "OBSERVED EVIDENCE", "EVIDENCE",
        "KEY FINDINGS", "AI INTERPRETATION", "RISK ASSESSMENT",
        "RECOMMENDED INVESTIGATION", "RECOMMENDED NEXT STEPS", "CONFIDENCE",
        "LIMITATIONS", "WHAT THE EVIDENCE DOES NOT ESTABLISH", "EVIDENCE REFERENCES",
    }
    return name if name in known else None


def _split_claim_lines(text: str) -> list[tuple[str, str]]:
    """Fallback parser for normal Markdown/prose provider output."""
    claims: list[tuple[str, str]] = []
    section = ""
    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        value = " ".join(x.strip() for x in buffer).strip()
        if value:
            claims.append((section, value))
        buffer.clear()

    for raw in str(text or "").splitlines():
        current = _section_name(raw)
        if current:
            flush()
            section = current
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("─"):
            flush()
            continue
        if re.match(r"^(?:[-*•]|\d+[.)])\s+", stripped):
            flush()
            buffer.append(re.sub(r"^(?:[-*•]|\d+[.)])\s+", "", stripped))
        elif section in {"DIRECT ANSWER", "OVERALL ASSESSMENT", "AI INTERPRETATION", "RISK ASSESSMENT", "LIMITATIONS", "WHAT THE EVIDENCE DOES NOT ESTABLISH"}:
            # Keep short paragraphs as individual claims. Long provider prose
            # is still safely represented as one analytical claim.
            buffer.append(stripped)
    flush()
    if claims:
        return claims

    # Some local models ignore the requested headings/JSON and return a normal
    # prose report. Do not let that transport style bypass grounding. Recover
    # paragraph/bullet claims as UNSECTIONED provider claims so the common
    # claim validator can still accept grounded interpretations and reject
    # unsupported conclusions.
    fallback: list[tuple[str, str]] = []
    paragraph: list[str] = []
    for raw in str(text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("─"):
            if paragraph:
                value = " ".join(paragraph).strip()
                if value:
                    fallback.append(("UNSECTIONED", value))
                paragraph.clear()
            continue
        cleaned = re.sub(r"^\*{1,3}([^*]+)\*{1,3}$", r"\1", stripped).strip()
        # Standalone Markdown/title lines are section labels, not analyst claims.
        # They must never receive recovered evidence citations.
        if (
            (stripped.startswith("*") and stripped.endswith("*"))
            or (len(cleaned.split()) <= 6 and re.fullmatch(r"[A-Z][A-Za-z0-9 /&_-]{2,70}", cleaned))
        ) and not re.search(r"[.!?]$", cleaned):
            if paragraph:
                value = " ".join(paragraph).strip()
                if value:
                    fallback.append(("UNSECTIONED", value))
                paragraph.clear()
            continue
        if re.match(r"^(?:[-*•]|\d+[.)])\s+", cleaned):
            if paragraph:
                value = " ".join(paragraph).strip()
                if value:
                    fallback.append(("UNSECTIONED", value))
                paragraph.clear()
            cleaned = re.sub(r"^(?:[-*•]|\d+[.)])\s+", "", cleaned)
            if cleaned:
                fallback.append(("UNSECTIONED", cleaned))
        elif cleaned:
            paragraph.append(cleaned)
    if paragraph:
        value = " ".join(paragraph).strip()
        if value:
            fallback.append(("UNSECTIONED", value))
    return fallback


def _candidate_payloads(answer: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    obj = _extract_json_object(answer)
    if obj and isinstance(obj.get("claims"), list):
        claims = [item for item in obj["claims"] if isinstance(item, dict)]
        return obj, claims
    return None, [
        {"text": text, "section": section}
        for section, text in _split_claim_lines(answer)
    ]


def _unsupported_security_conclusion(claim: str, evidence_texts: list[str]) -> str | None:
    """Reject conclusions that require explicit corroboration not present in evidence.

    These are semantic safety boundaries, not phrase whitelists: the validator
    checks whether the evidence contains the *required kind of corroboration*.
    """
    text = str(claim or "").lower()
    evidence = " ".join(str(x or "") for x in evidence_texts).lower()

    checks = [
        (re.compile(r"\b(?:weak|weakness\s+in|insecure)\s+(?:password|credential(?:s)?|authentication)\b|\bpassword\s+(?:is|appears?)\s+weak\b|\bweak\s+credentials?\b"),
         re.compile(r"\b(?:weak\s+password|password\s+strength|credential\s+policy|password\s+policy|weak\s+credential)\b"),
         "password or credential weakness is not established by failed authentication events alone"),
        (re.compile(r"\b(?:successfully\s+)?(?:compromis(?:e|ed)|breach(?:ed)?)\b"),
         re.compile(r"\b(?:account compromise|compromise_established|successful compromise|compromised=true)\b"),
         "successful compromise is not established by the cited evidence"),
        (re.compile(r"\b(?:gave|provided|allowed|enabled)\s+(?:the\s+)?attacker\s+(?:access|entry)\b|\b(?:gave|provided|allowed|enabled)\s+(?:initial\s+)?access\s+to\s+(?:the\s+)?attacker\b"),
         re.compile(r"\b(?:successful\s+(?:authentication|login|session)|authenticated|access_granted|session_established|initial_access_confirmed)\b"),
         "the cited evidence does not establish that the artifact itself provided attacker access"),
        (re.compile(r"\bprivilege\s+escalat(?:e|ed|ion)\b|\bescalat(?:e|ed|ion)\s+privileg(?:e|es)\b|\bescalat(?:ed|ion)\s+to\s+root\b"),
         re.compile(r"\b(?:uid|euid)=0\b|\bprivilege\s+boundary\s+(?:crossed|bypassed)\b|\bgained\s+(?:root|elevated)\s+(?:access|privileges)\b"),
         "privilege escalation is not established by the cited evidence"),
        (re.compile(r"\b(?:exfiltrat(?:e|ed|ion)|data\s+(?:leak|theft|stolen)|stole\s+(?:data|files))\b"),
         re.compile(r"\b(?:upload|uploaded|outbound|transfer|transferred|scp|sftp|rsync|curl|wget|put|stor)\b"),
         "data exfiltration is not established by the cited evidence"),
        (re.compile(r"\b(?:the\s+)?attacker\s+(?:was|is|used|originated|came\s+from)\b"),
         re.compile(r"\b(?:attacker|threat\s+actor|malicious\s+source)\b"),
         "attacker identity is not established by the cited evidence"),
        (re.compile(r"\b(?:brute[- ]force\s+attack|potential\s+brute[- ]force|consistent\s+with\s+(?:a\s+)?brute[- ]force)\b"),
         re.compile(r"\b(?:brute[- ]force|password\s+guess(?:ing)?|credential\s+attack|automated\s+authentication)\b"),
         "the supplied evidence does not establish a brute-force attack; the authentication pattern may be described only as observed/repeated activity"),
        (re.compile(r"\bunauthorized\s+access\b"),
         re.compile(r"\b(?:unauthorized|access_denied|permission_denied|authentication\s+failure)\b"),
         "unauthorized access is not established by failed authentication evidence alone"),
    ]
    negation_markers = re.compile(
        r"\b(?:does\s+not|do\s+not|not\s+establish(?:ed)?|cannot\s+establish|"
        r"no\s+(?:evidence|indication)\s+of|without\s+evidence|"
        r"unproven|unconfirmed|not\s+classified\s+as)\b",
        re.I,
    )
    for conclusion, corroboration, reason in checks:
        for match in conclusion.finditer(text):
            prefix = text[max(0, match.start() - 140):match.start()]
            if negation_markers.search(prefix):
                # A bounded negation such as "does not establish compromise" is
                # itself a safe limitation and must not be mistaken for the
                # positive security conclusion being denied.
                continue
            if not corroboration.search(evidence):
                return reason
    return None


def _concrete_mismatches(claim: str, evidence_text: str) -> list[str]:
    """Find concrete event attributes invented by an interpretation.

    Security vocabulary such as "attack", "suspicious", "credential", or
    "risk" is intentionally ignored. Concrete entities are not: IPs, paths,
    process names, explicit field values, command words and executable paths
    must be traceable to the cited record.
    """
    claim_terms = _high_signal_terms(claim)
    event_terms = _high_signal_terms(evidence_text)
    missing = []
    # CVE identifiers are high-signal concrete facts but are not necessarily
    # included in the generic event-term extractor. Always require an exact
    # CVE match in the cited immutable record.
    claim_cves = {x.upper() for x in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", claim, re.I)}
    event_cves = {x.upper() for x in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", evidence_text, re.I)}
    missing.extend(f"CVE:{x}" for x in sorted(claim_cves - event_cves))
    correlation_only_success = bool(
        re.search(r"\bwarrants?\s+correlation\b", claim, re.I)
        and re.search(r"\blater\s+successful\s+(?:authentication|sessions?|logins?)\b", claim, re.I)
    )
    for term in sorted(claim_terms):
        if term.startswith("line:"):
            continue
        # "Later successful sessions" in a correlation recommendation is not a
        # claim that a successful session occurred in the supplied dataset.
        if correlation_only_success and term in {"successful_login"}:
            continue
        if term not in event_terms:
            missing.append(term)
    return missing


def _interpretation_support_gap(claim: str, evidence_texts: list[str]) -> str | None:
    """Check broad semantic compatibility without whitelisting conclusions.

    This is deliberately a support check, not an allow-list of security
    interpretations. It asks whether the evidence contains the kind of
    observable activity the interpretation talks about.
    """
    text = str(claim or "").lower()
    evidence = [str(x or "").lower() for x in evidence_texts]
    joined = " ".join(evidence)

    domain_patterns = [
        (
            re.search(r"\b(?:authentication|authenticat(?:e|ed|ion)|login|logins|ssh|sshd|credential)\b", text),
            re.compile(r"\b(?:user_auth|user_login|authentication|failed_login|successful_login|sshd|pam:authentication|accepted password|failed password)\b", re.I),
            "authentication-related",
        ),
        (
            re.search(r"\b(?:process|execution|executed|command|shell)\b", text),
            re.compile(r"\b(?:execve|command_exec|process|shell|command=)\b", re.I),
            "process/command",
        ),
        (
            re.search(r"\b(?:network|connection|socket|outbound|transfer|traffic)\b", text),
            re.compile(r"\b(?:network|connection|socket|connect(?:ed|ion)?|outbound|transfer|http|https|tcp|udp|scp|sftp|rsync|curl|wget|netcat|nc)\b", re.I),
            "network/transfer",
        ),
        (
            re.search(r"\b(?:root|privilege|privileged|elevat(?:e|ed|ion))\b", text),
            re.compile(r"\b(?:uid|euid)=0\b|\broot\b|\bsudo\b|\bsu\b|\bpkexec\b|\bprivilege\b", re.I),
            "privilege",
        ),
    ]
    for requested, observed_re, label in domain_patterns:
        if requested and not observed_re.search(joined):
            return f"the cited evidence does not contain observable {label} activity"

    repeated = bool(re.search(r"\b(?:multiple|several|sequence)\b", text))
    if repeated:
        matching = 0
        auth_re = re.compile(r"\b(?:user_auth|user_login|authentication|failed_login|successful_login|sshd|pam:authentication|accepted password|failed password)\b", re.I)
        process_re = re.compile(r"\b(?:execve|command_exec|process|shell|command=)\b", re.I)
        network_re = re.compile(r"\b(?:network|connection|socket|connect(?:ed|ion)?|outbound|transfer|http|https|tcp|udp|scp|sftp|rsync|curl|wget|netcat|nc)\b", re.I)
        if re.search(r"\b(?:authentication|authenticat|login|ssh|sshd|credential)\b", text):
            matching = sum(bool(auth_re.search(x)) for x in evidence)
        elif re.search(r"\b(?:process|execution|executed|command|shell)\b", text):
            matching = sum(bool(process_re.search(x)) for x in evidence)
        elif re.search(r"\b(?:network|connection|socket|outbound|transfer|traffic)\b", text):
            matching = sum(bool(network_re.search(x)) for x in evidence)
        if matching < 2:
            # A single immutable record may itself establish repetition when it
            # explicitly reports a count or repeated-attempts observation.
            internally_repeated = any(
                re.search(r"\b(?:multiple|repeated|at\s+least\s+\d+|\d+\s+failed\s+attempts|\d+\s+attempts)\b", item, re.I)
                for item in evidence
            )
            if not internally_repeated:
                return "the interpretation describes repeated activity but fewer than two supporting observations were cited"

    return None


def _outcome_support_gap(claim: str, evidence_texts: list[str]) -> str | None:
    """Verify common event outcomes that cannot be inferred from a nearby event."""
    text = str(claim or "").lower()
    evidence = " ".join(str(x or "") for x in evidence_texts).lower()

    if re.search(r"\b(?:a|the|this|that)?\s*(?:successful|successfully)\s+(?:login|log in|authentication|authenticated)\s+(?:occurred|was observed|was recorded|succeeded)\b", text):
        if not re.search(r"\b(?:successful_login|accepted password|res=success|authentication.*success)\b", evidence):
            return "successful authentication is not established by the cited evidence"

    if re.search(r"\b(?:a|the|this|that)?\s*(?:failed|unsuccessful)\s+(?:login|log in|authentication|authenticated)\s+(?:occurred|was observed|was recorded)\b", text):
        if not re.search(r"\b(?:failed_login|failed password|res=failed|authentication.*failed)\b", evidence):
            return "failed authentication is not established by the cited evidence"

    if re.search(r"\b(?:root|as root|root-level)\s+(?:execution|command|shell|access)\b", text):
        if not re.search(r"\b(?:uid|euid)=0\b|\broot\b", evidence):
            return "root execution is not established by the cited evidence"

    return None


def _recover_uncited_claim_evidence(text: str, context: dict[str, Any], limit: int = 4) -> list[str]:
    """Recover only deterministic evidence IDs for an uncited claim.

    This is citation recovery, not a security allow-list. A record is eligible
    only when the claim contains concrete entities/terms that are present in the
    immutable record, or a narrow observable-domain anchor (authentication,
    process/command, network/transfer, privilege). The normal claim validator
    still performs the final semantic safety checks after recovery.
    """
    claim = str(text or "").strip()
    if not claim:
        return []
    lookup = _event_lookup(context)
    if not lookup:
        return []
    terms = _high_signal_terms(claim)
    anchors = []
    domain_patterns = [
        (r"\b(?:authentication|authenticat(?:e|ed|ion)|login|logins|ssh|sshd|credential)\b",
         r"\b(?:user_auth|user_login|authentication|failed_login|successful_login|sshd|failed password|accepted password)\b"),
        (r"\b(?:process|execution|executed|command|shell)\b",
         r"\b(?:execve|command_exec|process|shell|command=)\b"),
        (r"\b(?:network|connection|socket|outbound|transfer|traffic)\b",
         r"\b(?:network|connection|socket|connect(?:ed|ion)?|outbound|transfer|http|https|tcp|udp|scp|sftp|rsync|curl|wget|netcat|nc)\b"),
        (r"\b(?:root|privilege|privileged|elevat(?:e|ed|ion))\b",
         r"\b(?:uid|euid)=0\b|\broot\b|\bsudo\b|\bsu\b|\bpkexec\b|\bprivilege\b"),
    ]
    for claim_re, event_re in domain_patterns:
        if re.search(claim_re, claim, re.I):
            anchors.append(re.compile(event_re, re.I))

    scored: list[tuple[int, str]] = []
    for evid, event in lookup.items():
        event_terms = _high_signal_terms(event)
        overlap = terms & event_terms
        score = len(overlap) * 10
        if terms and not overlap:
            score = 0
        # A broad domain anchor (e.g. ``process``) is only a secondary signal.
        # It must not be sufficient by itself to attach an unrelated record to
        # an uncited claim.  Concrete overlap remains the primary recovery gate.
        if score > 0 and anchors and any(rx.search(str(event)) for rx in anchors):
            score += 4
        if score > 0:
            scored.append((score, evid))
    scored.sort(key=lambda item: (-item[0], item[1]))
    selected = [evid for _, evid in scored[:max(1, int(limit))]]
    return selected



def _contradiction_reason(claim: str, evidence_texts: list[str]) -> str | None:
    """Detect positive claims that directly conflict with the supplied records.

    This is intentionally narrower than the unsupported-claim detector.  A
    contradiction requires affirmative deterministic evidence of the opposite
    outcome, e.g. a claim of successful authentication when the cited/current
    authentication evidence is explicitly failed.
    """
    text = str(claim or "").lower()
    evidence = " ".join(str(x or "") for x in evidence_texts).lower()

    positive_success = bool(re.search(
        r"\b(?:a\s+|the\s+|an\s+)?(?:successful|successfully)\s+"
        r"(?:login|log\s*in|authentication|authenticated)\b"
        r"\s+(?:occurred|was\s+(?:observed|recorded)|succeeded)\b",
        text,
        re.I,
    ))
    failed_only = bool(re.search(
        r"\b(?:failed_login|failed\s+(?:password|login|authentication)|res=failed)\b",
        evidence,
        re.I,
    ))
    success_evidence = bool(re.search(
        r"\b(?:successful_login|accepted\s+password|res=success|authentication[^.\n;]*success)\b",
        evidence,
        re.I,
    ))
    if positive_success and failed_only and not success_evidence:
        return "the supplied authentication evidence records failed outcomes and does not establish the claimed successful authentication"

    positive_compromise = bool(re.search(
        r"\b(?:the\s+)?(?:attacker|actor)\s+(?:successfully\s+)?compromised\b|"
        r"\baccount\s+(?:was\s+)?compromised\b",
        text,
        re.I,
    ))
    explicit_noncompromise = bool(re.search(
        r"\b(?:compromise|compromised)\b.*\b(?:false|no|not|absent|failed)\b",
        evidence,
        re.I,
    ))
    if positive_compromise and explicit_noncompromise:
        return "the supplied evidence explicitly contradicts the claimed compromise"

    return None


def _context_status_claim(text: str, proposed_type: str, evidence_texts: list[str]) -> bool:
    """Identify claims whose correct disposition is review rather than rejection."""
    value = str(text or "").lower()
    proposed = str(proposed_type or "").upper().strip()
    if proposed == INSUFFICIENT_CONTEXT:
        return True
    if re.search(
        r"\b(?:insufficient\s+(?:context|evidence)|requires?\s+(?:additional\s+)?context|"
        r"cannot\s+determine|meaning\s+cannot\s+be\s+determined|"
        r"security\s+significance\s+cannot\s+be\s+determined|"
        r"warrants?\s+(?:further\s+)?context(?:ual)?\s+(?:investigation|review))\b",
        value,
        re.I,
    ):
        return True
    # PAM grantor '?' is a classic context-limited audit field.  Do not turn it
    # into a vulnerability or misconfiguration without corroborating evidence.
    if re.search(r"\bpam:authentication\s+grantors\s*=\s*\?", value, re.I) and not re.search(
        r"\b(?:misconfigur|bypass|vulnerab|attack|compromise|malicious)\b", value, re.I
    ):
        return True
    return False



def _aggregate_support_gap(claim: str, context: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Validate set-level claims against the complete immutable evidence bundle.

    A provider citation is only a pointer; it is not permission to generalize
    from two cited records to twelve.  Aggregate and universal claims are
    therefore evaluated against every deterministic record in the bundle.
    """
    text = str(claim or "")
    lower = text.lower()
    lookup = _event_lookup(context)
    if not lookup:
        return None, []
    records = list(lookup.items())

    def event_is_population_member(event: str) -> bool:
        e = str(event or "").lower()
        if re.search(r"\b(?:failed\s+login|failed\s+authentication|failed_login|authentication\s+fail)", lower):
            return bool(re.search(r"\b(?:failed_login|failed password|res=failed|authentication.*failed)", e))
        if re.search(r"\b(?:successful\s+login|successful\s+authentication|successful_login|authentication\s+success)", lower):
            return bool(re.search(r"\b(?:successful_login|accepted password|res=success|authentication.*success)", e))
        if re.search(r"\b(?:login|authentication|ssh|sshd)\b", lower):
            return bool(re.search(r"\b(?:user_auth|user_login|authentication|failed_login|successful_login|sshd|pam:authentication)", e))
        if re.search(r"\b(?:process|command|execution|executed|shell)\b", lower):
            return bool(re.search(r"\b(?:execve|command_exec|process|shell|command=)", e))
        return False

    population_all = [(eid, event) for eid, event in records if event_is_population_member(event)]
    if not population_all:
        return None, []

    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    users = re.findall(r"(?:user|username|account)\s*['\"]?([A-Za-z0-9_.@-]+)", text, re.I)
    processes = [x.rstrip(".,;:)") for x in re.findall(r"\b(?:using|process)\s+['\"]?([A-Za-z0-9_.@/-]+)", text, re.I)]

    def constrained_membership(event: str) -> bool:
        e = str(event or "")
        if ips and not any(ip in e for ip in ips):
            return False
        if users and not any(re.search(rf"\b(?:user|username|acct)=?['\"]?{re.escape(u)}\b", e, re.I) for u in users):
            return False
        if processes and not any(re.search(rf"\b(?:process|proc)=?['\"]?{re.escape(proc)}\b", e, re.I) for proc in processes):
            return False
        return True

    population = [(eid, event) for eid, event in population_all if constrained_membership(event)]
    if not population:
        return None, []
    ids = [eid for eid, _ in population]

    count_match = re.search(
        r"\b(?:total\s+of\s+)?(\d+)\s+(?:failed\s+login\s+attempts?|failed\s+authentication\s+events?|failed\s+logins?|successful\s+logins?|successful\s+authentication\s+events?|events?|records?)\b",
        lower,
    )
    if count_match:
        expected = int(count_match.group(1))
        actual = len(population)
        if expected != actual:
            return (
                f"aggregate count is not supported: claim says {expected}, "
                f"deterministic evidence contains {actual} matching record(s)",
                ids,
            )

    if re.search(r"\b(?:all|every|each)\b", lower):
        user_match = re.search(r"(?:user|username|account)\s*['\"]?([A-Za-z0-9_.@-]+)", text, re.I)
        if user_match:
            wanted = user_match.group(1).lower()
            bad = [eid for eid, event in population_all if not re.search(
                rf"\b(?:user|username|acct)=?['\"]?{re.escape(wanted)}\b", str(event), re.I
            )]
            if bad:
                return f"universal claim is not supported: not every matching record targets user {wanted}", [eid for eid, _ in population_all]
        proc_match = re.search(r"(?:using|process)\s+['\"]?([A-Za-z0-9_.@/-]+)", text, re.I)
        if proc_match:
            wanted = proc_match.group(1).rstrip(".,;:)").lower()
            bad = [eid for eid, event in population_all if not re.search(
                rf"\b(?:process|proc)=?['\"]?{re.escape(wanted)}\b", str(event), re.I
            )]
            if bad:
                return f"universal claim is not supported: not every matching record uses process {wanted}", [eid for eid, _ in population_all]

    return None, ids


def _classify_claim(
    text: str,
    proposed_type: str,
    evidence_ids: list[str],
    context: dict[str, Any],
    section: str,
    proposed_confidence: str,
) -> GroundedClaim:
    lookup = _event_lookup(context)
    allowed = set(context.get("retrieval", {}).get("evidence_ids", []) or [])
    allowed.update(lookup.keys())
    evidence_ids = list(dict.fromkeys(x.upper() for x in evidence_ids))
    invalid = [x for x in evidence_ids if x not in allowed or x not in lookup]
    if invalid:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED,
            section=section, reason=f"Unknown evidence reference(s): {', '.join(invalid)}",
        )

    # Recommendations are advisory actions, not verified findings. Keep them
    # separate even when the provider incorrectly labels them as facts.
    recommendation_re = re.compile(
        r"^\s*(?:monitor|review|investigate|correlate|consider|implement|enable|disable|verify|check|preserve|collect|escalate|ensure|configure|harden|restrict|rotate|block|allow)\b",
        re.I,
    )
    proposed = str(proposed_type or "").upper().strip()
    if (
        proposed in {"RECOMMENDATION", "RECOMMENDED_ACTION", "NEXT_STEP"}
        or recommendation_re.search(text)
        or re.match(r"^\s*(?:\*\*)?recommendation(?:\*\*)?\s*:", text, re.I)
    ):
        cited_texts = [lookup[evid] for evid in evidence_ids]
        return GroundedClaim(
            text=text, type=RECOMMENDATION, evidence_references=evidence_ids,
            confidence=_canonical_confidence(proposed_confidence, MODERATE),
            grounding_status="ACCEPTED", validation_status=ACCEPTED, section=section,
            reason="Provider recommendation is advisory and is kept separate from verified findings.",
        )

    # Limit concrete claims to cited records. Interpretations can introduce
    # analytical vocabulary, but not new concrete entities/events.
    if not evidence_ids:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=[],
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason="The claim has no deterministic evidence reference.",
        )

    cited_texts = [lookup[evid] for evid in evidence_ids]

    aggregate_gap, aggregate_ids = _aggregate_support_gap(text, context)
    if aggregate_gap:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason=aggregate_gap,
        )
    # Set-level claims receive complete deterministic lineage, not just the
    # provider's sample citations.
    if aggregate_ids and re.search(r"\b(?:\d+|multiple|several|many|numerous|all|every|each)\b", text, re.I):
        evidence_ids = list(dict.fromkeys(evidence_ids + aggregate_ids))
        cited_texts = [lookup[evid] for evid in evidence_ids]

    contradiction = _contradiction_reason(text, cited_texts)
    if contradiction:
        return GroundedClaim(
            text=text, type=CONTRADICTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status=REJECTED,
            validation_status=REJECTED_CONTRADICTED, section=section,
            reason=contradiction,
        )

    if _context_status_claim(text, proposed_type, cited_texts):
        return GroundedClaim(
            text=text, type=INSUFFICIENT_CONTEXT, evidence_references=evidence_ids,
            confidence=_canonical_confidence(proposed_confidence, LOW),
            grounding_status="REVIEW_REQUIRED",
            validation_status=REVIEW_REQUIRED, section=section,
            reason="The supplied evidence is insufficient to establish the security significance of this observation.",
        )

    security_gap = _unsupported_security_conclusion(
        text, cited_texts
    )
    if security_gap:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason=security_gap,
        )

    support_gap = _interpretation_support_gap(
        text, [lookup[evid] for evid in evidence_ids]
    )
    if support_gap:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason=support_gap,
        )

    outcome_gap = _outcome_support_gap(
        text, [lookup[evid] for evid in evidence_ids]
    )
    if outcome_gap:
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason=outcome_gap,
        )

    mismatches: dict[str, list[str]] = {}
    for evid in evidence_ids:
        missing = _concrete_mismatches(text, lookup[evid])
        if missing:
            mismatches[evid] = missing

    proposed = str(proposed_type or "").upper().strip()
    is_interpretation = (
        proposed in {"INTERPRETATION", GROUNDED_INTERPRETATION, "HYPOTHESIS", "INFERENCE"}
        or bool(_INFERENCE_RE.search(text))
        or section in {"AI INTERPRETATION", "RISK ASSESSMENT", "OVERALL ASSESSMENT"}
    )

    if mismatches:
        detail = "; ".join(f"{e}: {len(v)} concrete attribute(s) missing" for e, v in mismatches.items())
        return GroundedClaim(
            text=text, type=UNSUPPORTED_CLAIM, evidence_references=evidence_ids,
            confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED, section=section,
            reason=f"Concrete claim attributes are not present in the cited immutable record(s): {detail}",
        )

    # An AI cannot promote an inference into a verified fact simply by asking
    # for VERIFIED_FACT. The validator owns the final class.
    if is_interpretation:
        confidence = _canonical_confidence(proposed_confidence, MODERATE)
        if confidence == HIGH:
            confidence = MODERATE
        return GroundedClaim(
            text=text, type=GROUNDED_INTERPRETATION, evidence_references=evidence_ids,
            confidence=confidence, grounding_status="ACCEPTED",
            validation_status=ACCEPTED_AS_INTERPRETATION, section=section,
            reason="Interpretation is anchored to cited deterministic evidence; analytical meaning is kept advisory.",
        )

    # Direct fact: every cited record must contain the concrete attributes used
    # in the statement. A citation without concrete terms is still provenance,
    # but it cannot establish a stronger factual claim.
    return GroundedClaim(
        text=text, type=VERIFIED_FACT, evidence_references=evidence_ids,
        confidence=_canonical_confidence(proposed_confidence, HIGH),
        grounding_status="ACCEPTED", validation_status=ACCEPTED, section=section,
        reason="Concrete claim attributes match the cited immutable evidence.",
    )



def normalize_provider_analysis(answer: str, context: dict[str, Any]) -> dict[str, Any]:
    """Normalize raw provider output into a common, safe analyst representation."""
    obj, payloads = _candidate_payloads(answer)
    claims: list[GroundedClaim] = []
    for item in payloads:
        text = str(item.get("text") or item.get("claim") or "").strip()
        if not text:
            continue
        evidence = item.get("evidence_references", item.get("evidence", item.get("evidence_ids", [])))
        if isinstance(evidence, str):
            evidence = extract_evidence_ids(evidence)
        elif isinstance(evidence, list):
            evidence = extract_evidence_ids(" ".join(str(x) for x in evidence if isinstance(x, (str, int))))
        else:
            evidence = []
        evidence = list(dict.fromkeys(extract_evidence_ids(text) + evidence))
        if not evidence and context.get("auto_cite_uncited_claims"):
            evidence = _recover_uncited_claim_evidence(text, context)
        claims.append(_classify_claim(
            text,
            str(item.get("type", item.get("claim_type", ""))),
            evidence,
            context,
            str(item.get("section", "")).upper(),
            _canonical_confidence(item.get("confidence"), MODERATE),
        ))

    # Assign stable claim IDs after normalization. These IDs are local to the
    # provider response and do not alter immutable EVID identifiers.
    for index, claim in enumerate(claims, 1):
        claim.claim_id = f"CLAIM-{index:03d}"

    # If a structured response contains no usable claims, keep the raw response
    # as a rejected provider artifact rather than manufacturing deterministic AI text.
    if not claims and str(answer or "").strip():
        claims.append(GroundedClaim(
            text="Provider response could not be normalized into auditable claims.",
            type=UNSUPPORTED_CLAIM, confidence=LOW, grounding_status="REJECTED", validation_status=REJECTED,
            reason="No auditable claim structure was found in the provider response.",
        ))

    if claims:
        for index, claim in enumerate(claims, 1):
            claim.claim_id = f"CLAIM-{index:03d}"

    obj = obj or {}

    # ``overall_assessment`` is provider prose, not an automatically trusted
    # field.  Validate it against the same immutable evidence used for claims.
    # When the full paragraph mixes a supported observation with an unsupported
    # outcome (for example ``no compromise``), keep it out of the primary report
    # and let the accepted claim(s) form the safe overall assessment.
    overall = str(obj.get("overall_assessment") or "").strip()
    overall_claim: GroundedClaim | None = None
    if overall:
        overall_refs = extract_evidence_ids(overall)
        if not overall_refs and context.get("auto_cite_uncited_claims"):
            overall_refs = _recover_uncited_claim_evidence(overall, context, limit=8)
            if not overall_refs:
                # Exact concrete-value lineage for compact provider summaries.
                for evid, event in _event_lookup(context).items():
                    if any(token in str(event) for token in re.findall(r"\b\d{2,}\b", overall)):
                        overall_refs.append(evid)
                overall_refs = list(dict.fromkeys(overall_refs))[:8]
        overall_claim = _classify_claim(
            overall, "GROUNDED_INTERPRETATION", overall_refs, context,
            "OVERALL ASSESSMENT", MODERATE,
        )

    limitations = obj.get("limitations", [])
    if isinstance(limitations, str):
        limitations = [limitations]
    limitations = [str(x).strip() for x in limitations if str(x).strip()]
    next_steps = obj.get("next_steps", obj.get("recommended_next_steps", []))
    if isinstance(next_steps, str):
        next_steps = [next_steps]
    next_steps = [str(x).strip() for x in next_steps if str(x).strip()]

    # A compact provider is allowed to return only overall_assessment. If that
    # paragraph is independently grounded, retain it as a normal claim so the
    # answer is not discarded merely because the provider omitted ``claims``.
    if overall_claim and overall_claim.validation_status in {ACCEPTED, ACCEPTED_AS_INTERPRETATION}:
        if not any(
            c.text.strip() == overall_claim.text.strip() and
            c.evidence_references == overall_claim.evidence_references
            for c in claims
        ):
            overall_claim.claim_id = f"CLAIM-{len(claims) + 1:03d}"
            claims.append(overall_claim)

    accepted = [c for c in claims if c.validation_status in {ACCEPTED, ACCEPTED_AS_INTERPRETATION}]
    accepted_facts = [c for c in accepted if c.type == VERIFIED_FACT]
    accepted_interpretations = [c for c in accepted if c.type == GROUNDED_INTERPRETATION]
    recommendations = [c for c in accepted if c.type == RECOMMENDATION]
    review_items = [c for c in claims if c.validation_status == REVIEW_REQUIRED]
    rejected = [c for c in claims if c.validation_status in {REJECTED, REJECTED_CONTRADICTED}]
    contradicted = [c for c in rejected if c.type == CONTRADICTED_CLAIM]
    if not str(answer or "").strip():
        provider_status = "NO_PROVIDER_ASSESSMENT"
    elif accepted and rejected:
        provider_status = "PARTIALLY_GROUNDED"
    elif accepted:
        provider_status = "FULLY_GROUNDED"
    elif rejected:
        provider_status = "NO_GROUNDED_CLAIMS"
    else:
        provider_status = "INVALID_PROVIDER_RESPONSE"
    # Prefer a fully validated provider overall assessment. If it is too broad
    # to validate as one sentence, derive a concise overall assessment from the
    # first accepted interpretation/fact rather than displaying the unsafe or
    # ungrounded provider paragraph verbatim.
    safe_overall = ""
    if overall_claim and overall_claim.grounding_status == "ACCEPTED":
        safe_overall = overall_claim.text
    elif accepted:
        preferred = next((c for c in accepted if c.type == GROUNDED_INTERPRETATION), accepted[0])
        safe_overall = preferred.text
    # Deterministic provenance metrics are calculated from the immutable
    # evidence bundle, never from provider prose.
    records = [dict(x) for x in (context.get("evidence_records") or []) if isinstance(x, dict)]
    timestamps = [str(r.get("timestamp") or "").strip() for r in records if str(r.get("timestamp") or "").strip()]
    if len(timestamps) < len(records):
        for r in records:
            if str(r.get("timestamp") or "").strip():
                continue
            m = re.search(r"\b(?:time|timestamp)=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", str(r.get("text","")), re.I)
            if m:
                timestamps.append(m.group(1))
    parsed_times = []
    from datetime import datetime
    for ts in timestamps:
        try:
            parsed_times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
        except Exception:
            try:
                parsed_times.append(datetime.strptime(ts.split(".")[0], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                pass
    deterministic_metrics = {
        "event_count": len(records),
        "first_event_timestamp": min(timestamps) if timestamps else "",
        "last_event_timestamp": max(timestamps) if timestamps else "",
        "observed_window_seconds": round((max(parsed_times) - min(parsed_times)).total_seconds(), 2) if len(parsed_times) >= 2 else 0.0,
    }

    return {
        "overall_assessment": safe_overall,
        "deterministic_metrics": deterministic_metrics,
        "provider_overall_assessment": overall,
        "overall_claim": overall_claim.to_dict() if overall_claim else None,
        "claims": [c.to_dict() for c in claims],
        "accepted_claims": [c.to_dict() for c in accepted],
        "accepted_facts": [c.to_dict() for c in accepted_facts],
        "accepted_interpretations": [c.to_dict() for c in accepted_interpretations],
        "recommendations": [c.to_dict() for c in recommendations],
        "review_items": [c.to_dict() for c in review_items],
        "insufficient_context_claims": [c.to_dict() for c in review_items],
        "evidence_records": [dict(x) for x in (context.get("evidence_records") or []) if isinstance(x, dict)],
        "rejected_claims": [c.to_dict() for c in rejected],
        "contradicted_claims": [c.to_dict() for c in contradicted],
        "limitations": limitations,
        "next_steps": next_steps,
        "raw_response": str(answer or ""),
        "provider_status": provider_status,
        # Legacy field retained for existing integrations/tests.
        "provider_response_status": "ACCEPTED_WITH_GROUNDED_CLAIMS" if accepted else "NO_GROUNDED_CLAIMS",
    }


def render_analyst_report(analysis: dict[str, Any]) -> str:
    """Render the AI provider's grounded assessment.

    This renderer is deliberately presentation/provenance-only.  It never
    derives a forensic answer, risk rating, timeline conclusion, or fallback
    answer from the log.  If the provider did not produce a grounded claim,
    the UI reports that condition instead of answering the question itself.
    """
    claims = analysis.get("claims", []) or []
    accepted = [
        x for x in claims
        if x.get("validation_status") in {ACCEPTED, ACCEPTED_AS_INTERPRETATION}
        or (x.get("grounding_status") == "ACCEPTED" and x.get("type") in {VERIFIED_FACT, GROUNDED_INTERPRETATION})
    ]
    facts = [x for x in accepted if x.get("type") == VERIFIED_FACT]
    interpretations = [x for x in accepted if x.get("type") == GROUNDED_INTERPRETATION]
    review_items = [
        x for x in claims
        if x.get("validation_status") == REVIEW_REQUIRED
        or x.get("grounding_status") == "REVIEW_REQUIRED"
    ]
    rejected = [
        x for x in claims
        if x.get("validation_status") in {REJECTED, REJECTED_CONTRADICTED}
        or x.get("grounding_status") == "REJECTED"
    ]
    investigation = analysis.get("investigation") or {}
    provider_status = str(analysis.get("provider_status") or "UNKNOWN").upper()
    provider_label = {
        "FULLY_GROUNDED": "FULLY GROUNDED",
        "PARTIALLY_GROUNDED": "PARTIALLY GROUNDED",
        "NO_GROUNDED_CLAIMS": "NO GROUNDED CLAIMS",
        "NO_PROVIDER_ASSESSMENT": "NO PROVIDER ASSESSMENT",
        "INVALID_PROVIDER_RESPONSE": "INVALID PROVIDER RESPONSE",
    }.get(provider_status, provider_status.replace("_", " ") if provider_status else "UNKNOWN")

    lines = ["AI ANALYST ASSESSMENT", "", f"PROVIDER STATUS: {provider_label}"]

    overall = str(analysis.get("overall_assessment") or "").strip()
    if overall and (facts or interpretations):
        lines += ["", "AI ASSESSMENT", overall]
    elif not accepted:
        lines += [
            "",
            "NO AI ASSESSMENT",
            "The selected AI provider did not return a grounded analyst conclusion.",
            "LogAsis will not generate a forensic answer from the evidence on its own.",
        ]

    if facts:
        lines += ["", "AI-REPORTED VERIFIED FACTS"]
        seen = set()
        for item in facts[:12]:
            key = re.sub(r"\s+", " ", str(item.get("text", ""))).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            refs = " ".join(f"[{x}]" for x in item.get("evidence_references", []))
            display_text = re.sub(r"\s*\[(?:EVID-\d+)\]", "", str(item.get("text", ""))).strip()
            lines.append(f"• {display_text}" + (f" {refs}" if refs else ""))

    if interpretations:
        lines += ["", "AI INTERPRETATION (ADVISORY)"]
        seen = set()
        for item in interpretations[:12]:
            key = re.sub(r"\s+", " ", str(item.get("text", ""))).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            refs = " ".join(f"[{x}]" for x in item.get("evidence_references", []))
            display_text = re.sub(r"\s*\[(?:EVID-\d+)\]", "", str(item.get("text", ""))).strip()
            lines.append(f"• {display_text}" + (f" {refs}" if refs else ""))

    limitations = analysis.get("limitations") or []
    if limitations:
        lines += ["", "LIMITATIONS"]
        lines.extend(f"• {str(x)}" for x in limitations[:8] if str(x).strip())

    next_steps = analysis.get("next_steps") or []
    if next_steps:
        lines += ["", "AI-REPORTED NEXT STEPS"]
        lines.extend(f"• {str(x)}" for x in next_steps[:8] if str(x).strip())

    recommendations = analysis.get("recommendations") or []
    if recommendations:
        lines += ["", "RECOMMENDED INVESTIGATION"]
        for item in recommendations[:8]:
            display_text = re.sub(r"\s*\[(?:EVID-\d+)\]", "", str(item.get("text", ""))).strip()
            refs = " ".join(f"[{x}]" for x in item.get("evidence_references", []))
            lines.append(f"• {display_text}" + (f" {refs}" if refs else ""))

    if review_items:
        lines += ["", "REQUIRES ADDITIONAL CONTEXT"]
        for item in review_items[:8]:
            lines.append(f"• {item.get('text', '')}")

    if rejected:
        lines += ["", "REJECTED AI CLAIMS (UNACCEPTED AI CLAIMS)"]
        for item in rejected[:8]:
            # Never display the rejected claim text itself. A fabricated CVE,
            # IP, account, or compromise statement must not remain visible next
            # to its rejection reason where an analyst could mistake it for a
            # validated finding. Preserve only the auditable reason.
            reason = str(item.get("reason") or "not grounded by the supplied evidence").strip()
            lines.append(f"• Rejected provider claim — {reason}")

    relationships = investigation.get("relationships") or []
    if relationships:
        lines += ["", "CORRELATED ACTIVITY"]
        seen_pairs = set()
        for rel in relationships[:20]:
            a = str(rel.get("evidence_a", "")).strip()
            b = str(rel.get("evidence_b", "")).strip()
            pair = tuple(sorted((a, b)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            reasons = ", ".join(str(x) for x in (rel.get("reasons") or []) if str(x).strip())
            lines.append(f"• {a} ↔ {b}" + (f" — {reasons}" if reasons else ""))

    timeline = investigation.get("timeline") or []
    if timeline:
        lines += ["", "INVESTIGATION TIMELINE"]
        for item in timeline[:20]:
            evid = str(item.get("evidence_id", "")).strip()
            timestamp = str(item.get("timestamp", "")).strip()
            text = re.sub(r"\s+", " ", str(item.get("text", ""))).strip()
            if len(text) > 220:
                text = text[:217].rstrip() + "..."
            prefix = f"[{evid}] " if evid else ""
            when = f"{timestamp} — " if timestamp else ""
            lines.append(f"• {when}{prefix}{text}")

    metrics = analysis.get("deterministic_metrics") or {}
    if metrics:
        lines += ["", "DETERMINISTIC EVIDENCE BASELINE"]
        all_evidence_text = " ".join(str(r.get("text","")) for r in (analysis.get("evidence_records") or []))
        high = any(str(r.get("severity","")).lower() in {"high","critical"} for r in (analysis.get("evidence_records") or [])) or bool(re.search(r"\bseverity=(?:high|critical)\b", all_evidence_text, re.I))
        lines.append(f"RISK / SEVERITY: {'High' if high else 'Low'}")
        if metrics.get("first_event_timestamp"):
            lines.append(f"First observed: {metrics['first_event_timestamp']}")
            lines.append(f"Last observed: {metrics['last_event_timestamp']}")
            lines.append(f"Event count: {metrics['event_count']}")
        auth_records = [r for r in (analysis.get("evidence_records") or []) if re.search(r"failed_login|failed password", str(r.get("text","")), re.I)]
        success_records = [r for r in (analysis.get("evidence_records") or []) if re.search(r"successful_login|accepted password|res=success", str(r.get("text","")), re.I)]
        if auth_records:
            lines.append(f"Successful authentication events: {len(success_records)}")
            if not success_records:
                lines.append("No successful authentication is established by the supplied evidence.")
    evidence_source = investigation.get("evidence_records") or analysis.get("evidence_records") or []
    evidence_ids = [str(x.get("evidence_id", "")) for x in evidence_source if x.get("evidence_id")]
    lines += [
        "",
        "EVIDENCE & GROUNDING DETAILS",
        "Evidence provenance is deterministic; the forensic conclusion is AI-generated.",
        "No question-specific forensic answer rule was applied.",
        "Evidence collected: " + (", ".join(evidence_ids) if evidence_ids else "none"),
    ]
    return "\n".join(lines)

