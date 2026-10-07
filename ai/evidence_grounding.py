from __future__ import annotations

import json
import re
from typing import Any, Dict

EVIDENCE_RE = re.compile(r"(?<![\w-])(?:\[(EVID-\d{1,6})\]|(EVID-\d{1,6}))(?![\w-])", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LINE_RE = re.compile(r"\bline\s*[=:]?\s*(\d+)\b", re.IGNORECASE)
CODE_RE = re.compile(r"`([^`]+)`")
def extract_evidence_ids(text: str) -> list[str]:
    """Extract bracketed or bare EVID identifiers and normalize them.

    AI providers are inconsistent about citation formatting. LogAsis accepts
    both ``[EVID-093]`` and ``EVID-093`` as input, then canonicalizes accepted
    citations to the bracketed form before grounding. This prevents a valid
    chunk-level citation from being mistaken for "no citation" merely because
    the model omitted brackets.
    """
    result: list[str] = []
    for match in EVIDENCE_RE.finditer(str(text or "")):
        evid = (match.group(1) or match.group(2) or "").upper()
        if evid:
            prefix, number = evid.split("-", 1)
            try:
                evid = f"{prefix}-{int(number):03d}"
            except ValueError:
                pass
        if evid and evid not in result:
            result.append(evid)
    return result


COMMAND_WORD_RE = re.compile(
    r"\b(?:systemd-detect-virt|apt-config|dpkg|awk|date|mktemp|find|sudo|su|sshd|execve|curl|wget|scp|sftp|rsync|nc|netcat|chmod|chown|run-parts|uname|whoami|id|ps|ip|ss|netstat|env|fusermount|pulseaudio|tracker-miner(?:-f)?|gvfsd|failed_login|successful_login|command_exec)\b",
    re.IGNORECASE,
)


def _evidence_records(context: Dict[str, Any]) -> list[dict[str, Any]]:
    """Return the immutable evidence bundle used for this analysis."""
    records = context.get("evidence_records") or []
    normalized: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        evid = str(item.get("evidence_id", "")).upper().strip()
        text = str(item.get("text", ""))
        if evid and text:
            normalized.append({"evidence_id": evid, "text": text, "line": item.get("line", "")})
    return normalized


def _allowed_ids(context: Dict[str, Any]) -> set[str]:
    records = _evidence_records(context)
    if records:
        return {item["evidence_id"] for item in records}
    retrieval = context.get("retrieval") or {}
    ids = retrieval.get("evidence_ids") or []
    if not ids:
        ids = [
            evid
            for item in context.get("relevant_events", []) or []
            for evid in extract_evidence_ids(str(item))
        ]
    return {str(value).upper() for value in ids}


def _clean_invalid_citations(text: str, allowed: set[str]) -> tuple[str, list[str]]:
    removed: list[str] = []

    def replace(match: re.Match[str]) -> str:
        evid = (match.group(1) or match.group(2) or "").upper()
        if evid:
            prefix, number = evid.split("-", 1)
            try:
                evid = f"{prefix}-{int(number):03d}"
            except ValueError:
                pass
        if evid in allowed:
            return f"[{evid}]"
        removed.append(evid)
        return "[unverified evidence reference removed]"

    return EVIDENCE_RE.sub(replace, text or ""), removed


def _event_lookup(context: Dict[str, Any]) -> dict[str, str]:
    records = _evidence_records(context)
    if records:
        return {item["evidence_id"]: item["text"] for item in records}
    result: dict[str, str] = {}
    for item in context.get("relevant_events", []) or []:
        text = str(item)
        ids = extract_evidence_ids(text)
        if ids:
            result[ids[0]] = text
    return result


def _compact_evidence_line(text: str, limit: int = 280) -> str:
    value = " ".join(str(text).split())
    value = re.sub(r"^\[EVID-\d{3,6}\]\s*", "", value, flags=re.I)
    if len(value) <= limit:
        return value
    return value[: limit - 24].rstrip() + " … [truncated]"


def _fallback_evidence_ids(context: Dict[str, Any], limit: int = 3) -> list[str]:
    lookup = _event_lookup(context)
    return list(lookup.keys())[:limit]


def _high_signal_terms(text: str) -> set[str]:
    """Extract concrete terms whose presence can be deterministically checked.

    This is intentionally conservative. It does not try to prove a security
    interpretation; it only detects obvious citation-to-event mismatches such
    as a claim about `dpkg` citing an event whose command is `env`.
    """
    value = str(text or "")
    terms: set[str] = set()

    for item in IP_RE.findall(value):
        terms.add(item.lower())
    for item in LINE_RE.findall(value):
        terms.add(f"line:{item}")
    for item in CODE_RE.findall(value):
        token = item.strip().lower()
        if token:
            # Keep command-like snippets and explicit values, not prose.
            first = token.split()[0]
            if re.match(r"^[a-z0-9_./:-]+$", first):
                terms.add(first)
    # COMMAND_WORD_RE is intentionally broad for raw command fields, but some
    # entries (notably the ``ip`` utility) are also ordinary words in analyst
    # prose.  Do not turn a bare prose occurrence of ``IP`` into the concrete
    # token ``ip``; the actual IPv4 address captured above is the authoritative
    # entity.  Command tokens are still retained when they occur in explicit
    # command/code context.
    command_context = bool(re.search(r"(?:\bcommand\s*[=:]|`[^`]+`|proctitle\s*[=:])", value, re.I))
    for item in COMMAND_WORD_RE.findall(value):
        token = item.lower()
        if token == "ip" and not command_context:
            continue
        terms.add(token)

    # Preserve concrete numeric values when the surrounding prose names a
    # structured field. This lets compact provider answers such as "the remote
    # port is 8443" recover an evidence citation without guessing what the
    # number means.
    for match in re.finditer(
        r"\b(?:[A-Za-z_]*port|[A-Za-z_]*pid|process\s*id|event\s*id|status|code)\s*(?:is|was|=|:)?\s*(\d{1,6})\b",
        value,
        re.I,
    ):
        terms.add(match.group(1).lower())

    # Also recognize natural-language field phrases such as "remote port is 8443".
    for match in re.finditer(
        r"\b(?:[A-Za-z_]*port|[A-Za-z_]*pid)\b(?:\s+[A-Za-z_-]+){0,4}\s*(?:is|was|=|:)\s*(\d{1,6})\b",
        value,
        re.I,
    ):
        terms.add(match.group(1).lower())

    # Preserve exact paths and URLs from claims as concrete evidence terms.
    # This is critical for statements such as `cat /var/cache/motd-news` or
    # access to `/run/user/1001/gvfs`; basename-only matching is too weak.
    for item in PATH_RE.findall(value) if "PATH_RE" in globals() else []:
        normalized = _normalize_term(item)
        if normalized:
            terms.add(normalized)
    for item in URL_RE.findall(value) if "URL_RE" in globals() else []:
        normalized = _normalize_term(item)
        if normalized:
            terms.add(normalized)

    # Explicit process/user fields mentioned in prose.
    for match in re.finditer(r"\bprocess\s*[=:]\s*([\w.-]+)", value, re.I):
        terms.add(match.group(1).lower())
    for match in re.finditer(r"\b(?:user|username|account)\s*[=:]\s*['\"]?([\w.@-]+)", value, re.I):
        terms.add(match.group(1).lower())

    # Natural-language provider output often names the same concrete entities
    # without using log-style ``field=value`` syntax. Preserve those entities
    # so claims such as ``user 'btlo' via SSH`` can be checked against the
    # immutable record instead of being rejected as if ``IP`` were the literal
    # command name.
    for match in re.finditer(r"\b(?:user|username|account)\s+['\"]([\w.@-]+)['\"]", value, re.I):
        terms.add(match.group(1).lower())
    for match in re.finditer(r"\b(?:user|username|account)\s+([\w.@-]+)\b", value, re.I):
        candidate = match.group(1).lower()
        if candidate not in {"via", "with", "from", "for", "was", "is", "the"}:
            terms.add(candidate)
    # Treat SSH/SSHD as the same observable authentication service family.
    if re.search(r"\bssh\b", value, re.I):
        terms.add("sshd")
    if re.search(r"\bsshd\b", value, re.I):
        terms.add("ssh")
    return terms


PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[A-Za-z0-9_.@:+~-]+/)*[A-Za-z0-9_.@:+~-]+")
URL_RE = re.compile(r"https?://[^\s,;]+", re.IGNORECASE)
FIELD_VALUE_RE = re.compile(r"\b(?:command|process|process_name|username|user|source_ip|destination_ip|parent_command|parent_image)\s*[=:]\s*([^;]+)", re.IGNORECASE)


def _normalize_term(value: str) -> str:
    return str(value or "").strip().strip("`'\"()[]{}.,:;").lower()


def _add_command_terms(value: str, terms: set[str]) -> None:
    raw = _normalize_term(value)
    if not raw:
        return
    terms.add(raw)
    # Keep executable/path identity as both the full path and basename.
    first = raw.split()[0] if raw.split() else raw
    first = _normalize_term(first)
    if first:
        terms.add(first)
        if "/" in first:
            terms.add(first.rsplit("/", 1)[-1])
    # Command arguments can themselves be security-relevant paths, IPs, or URLs.
    for path in PATH_RE.findall(raw):
        path = _normalize_term(path)
        if path:
            terms.add(path)
    for url in URL_RE.findall(raw):
        terms.add(_normalize_term(url))


def _event_terms(event_text: str) -> set[str]:
    """Extract deterministic concrete terms from an immutable evidence record.

    v0.8.2 compared claims against only a small command-word vocabulary. That
    caused false citation mismatches for exact paths such as ``/run/user/1001/gvfs``
    and executables such as ``/usr/bin/python3`` even when the cited immutable
    record contained those exact values. v0.8.3 indexes structured field values,
    full command paths, basenames, paths, IPs, users, and process names.
    """
    value = str(event_text or "")
    terms = _high_signal_terms(value)

    for match in FIELD_VALUE_RE.finditer(value):
        field = match.group(0).split("=", 1)[0].split(":", 1)[0].strip().lower()
        field_value = match.group(1).strip()
        if field in {"command", "parent_command"}:
            _add_command_terms(field_value, terms)
        else:
            normalized = _normalize_term(field_value)
            if normalized:
                terms.add(normalized)

    for path in PATH_RE.findall(value):
        normalized = _normalize_term(path)
        if normalized:
            terms.add(normalized)
    for url in URL_RE.findall(value):
        terms.add(_normalize_term(url))

    # Structured key/value records may contain multiple IPs outside the
    # dedicated source/destination fields. Keep the existing IPv4 behaviour.
    terms.update(ip.lower() for ip in IP_RE.findall(value))
    return terms


def _claim_for_citation(line: str) -> str:
    # A line is a safer claim boundary than an arbitrary sentence because AI
    # Analyst normally puts one evidence-backed observation per bullet.
    return EVIDENCE_RE.sub("", str(line or "")).strip()


def audit_citation_relevance(answer: str, context: Dict[str, Any], *, allow_shared_claim: bool = False) -> dict[str, Any]:
    """Audit whether each cited claim segment matches its exact evidence record."""
    lookup = _event_lookup(context)
    allowed = _allowed_ids(context)
    findings: list[dict[str, Any]] = []
    for raw_line in str(answer or "").splitlines():
        matches = list(EVIDENCE_RE.finditer(raw_line))
        if not matches:
            continue
        global_claim = _claim_for_citation(raw_line)
        global_terms = _high_signal_terms(global_claim)
        # Associate each citation with the text immediately preceding it. This
        # prevents one citation from borrowing concrete terms from a later
        # citation on the same line.
        previous_end = 0
        for idx, match in enumerate(matches):
            evid = extract_evidence_ids(match.group(0))
            if not evid:
                continue
            evid = evid[0]
            local_text = raw_line[previous_end:match.start()]
            # If this is the first citation, include the claim prefix. For
            # subsequent citations, only the text since the previous citation
            # belongs to that citation.
            if idx == 0:
                local_claim = local_text.strip()
            else:
                local_claim = local_text.strip()
            if not local_claim and global_terms:
                # Consecutive citations such as [EVID-054] [EVID-055] belong
                # to the same claim. Validate the complete claim against each
                # record rather than treating the second citation as an empty
                # claim. This preserves exact per-citation checking when text
                # actually changes between citations (e.g. "awk [154] and date [156]").
                local_claim = global_claim
                local_terms = global_terms
            else:
                local_terms = _high_signal_terms(local_claim)
            event = lookup.get(evid, "")
            if evid not in allowed or not event:
                previous_end = match.end()
                continue
            event_terms = _event_terms(event)
            terms_to_check = global_terms if (len(matches) > 1 and allow_shared_claim) else (local_terms if len(matches) > 1 else global_terms)
            missing = sorted(t for t in terms_to_check if not t.startswith("line:") and t not in event_terms)
            semantically_supported = not missing
            if len(matches) > 1 and not allow_shared_claim and not local_terms and global_terms:
                semantically_supported = False
                missing = sorted(global_terms)
            line_terms = [t for t in terms_to_check if t.startswith("line:")]
            if line_terms:
                event_line_match = re.search(r"\bline=(\d+)\b", event, re.I)
                if not event_line_match or not any(t == f"line:{event_line_match.group(1)}" for t in line_terms):
                    semantically_supported = False
                    missing.extend(line_terms)
            findings.append({
                "evidence_id": evid, "claim": local_claim or global_claim,
                "semantically_supported": semantically_supported,
                "missing_terms": sorted(set(missing)),
            })
            previous_end = match.end()
    return {
        "checked": len(findings),
        "supported": [x for x in findings if x["semantically_supported"]],
        "mismatched": [x for x in findings if not x["semantically_supported"]],
    }


# Conservative post-processing for providers that ignore the citation instruction.
# This does not invent evidence IDs: it only recovers IDs from the immutable
# evidence bundle when a concrete observation term matches the underlying event.
_RECOVERY_SECTION_RE = re.compile(
    r"^\s*(?:[*#_-]+\s*)?(?:observed evidence|evidence|findings|observed findings)\s*[:*#_-]*\s*$",
    re.IGNORECASE,
)
_SECTION_RE = re.compile(r"^\s*(?:[*#_-]+\s*)?([A-Z][A-Z _/-]{2,})[:*#_-]*\s*$")
_COUNTING_WORD_RE = re.compile(r"\b(?:multiple|several|frequent|repeated|many|numerous|instances|high-frequency)\b", re.I)
_COUNT_ASSERTION_RE = re.compile(r"\b\d+(?:[,.]\d+)?\s+(?:events?|records?|processes?|connections?|commands?)\b", re.I)


def _recovery_candidate_ids(claim: str, context: Dict[str, Any], limit: int = 3) -> list[str]:
    """Find high-confidence deterministic evidence for an uncited observation.

    Recovery is intentionally stricter than ordinary retrieval. It requires a
    concrete high-signal term (command/process/IP/user/line) from the claim to
    occur in the exact immutable event record. Generic words such as
    ``security`` or ``activity`` are never enough.
    """
    if _COUNT_ASSERTION_RE.search(claim):
        return []
    claim_terms = {t for t in _high_signal_terms(claim) if not t.startswith("line:")}
    if not claim_terms:
        return []
    records = _evidence_records(context)
    scored: list[tuple[int, str]] = []
    for item in records:
        event_terms = _event_terms(item["text"])
        overlap = claim_terms & event_terms
        if not overlap:
            continue
        # Exact command/process matches are strong; each additional concrete
        # term raises confidence without turning interpretation into fact.
        score = len(overlap)
        if _COUNTING_WORD_RE.search(claim) and score >= 1:
            score += 1
        scored.append((score, item["evidence_id"]))
    scored.sort(key=lambda x: (-x[0], int(x[1].split("-")[-1])))
    if not scored:
        return []
    required = 2 if _COUNTING_WORD_RE.search(claim) else 1
    selected = [evid for score, evid in scored[:limit] if score >= 1]
    if len(selected) < required:
        return []
    return selected


def recover_observation_citations(answer: str, context: Dict[str, Any], limit: int = 3) -> tuple[str, list[str]]:
    """Attach citations to uncited, concrete observation bullets when safe.

    LLMs sometimes follow the evidence instructions semantically but omit the
    literal EVID labels. Rather than treating that as a total grounding failure,
    recover only deterministic citations that can be matched to the same
    immutable records. Interpretation/recommendation prose is left untouched.
    """
    lines = str(answer or "").splitlines()
    active_section = ""
    recovered: list[str] = []
    changed = False
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        section_match = _SECTION_RE.match(stripped.replace("**", ""))
        if section_match:
            active_section = section_match.group(1).strip().upper()
        if _RECOVERY_SECTION_RE.match(stripped.replace("**", "")):
            active_section = "OBSERVED EVIDENCE"
        if not stripped or extract_evidence_ids(stripped):
            continue
        # Only recover bullet/numbered observations. This avoids silently
        # converting risk ratings or recommendations into evidence-backed facts.
        is_observation = bool(re.match(r"^(?:[-*•]|\d+[.)])\s+", stripped))
        in_observation_section = active_section in {
            "OBSERVED EVIDENCE", "EVIDENCE", "FINDINGS", "OBSERVED FINDINGS"
        }
        if not (is_observation and (in_observation_section or active_section == "")):
            continue
        ids = _recovery_candidate_ids(stripped, context, limit=limit)
        if not ids:
            continue
        suffix = " " + " ".join(f"[{evid}]" for evid in ids)
        lines[i] = raw.rstrip() + suffix
        changed = True
        for evid in ids:
            if evid not in recovered:
                recovered.append(evid)
    return ("\n".join(lines), recovered) if changed else (answer, [])



_INFERENCE_RE = re.compile(
    r"\b(?:could|may|might|suggest(?:s|ing)?|indicat(?:e|es|ing)|potential|possibly|likely|warrant(?:s|ed|ing)?|risk|malicious|attack|attacker|compromise|exfiltrat|data\s+leak|privilege\s+escalat|unauthori[sz]ed|brute\s*force|c2|command\s*injection|high\s+cpu|resource\s+contention|system\s+instab)",
    re.IGNORECASE,
)
_OBSERVATION_SECTIONS = {
    "OBSERVED EVIDENCE", "EVIDENCE", "FINDINGS", "OBSERVED FINDINGS",
    "DETERMINISTIC INTERPRETATION", "DETERMINISTIC RISK ASSESSMENT",
}
_INTERPRETATION_SECTIONS = {
    "AI INTERPRETATION", "RISK ASSESSMENT", "CONFIDENCE", "LIMITATIONS",
}


def _section_name_for_line(line: str) -> str | None:
    stripped = str(line or "").strip().replace("**", "")
    match = _SECTION_RE.match(stripped)
    return match.group(1).strip().upper() if match else None


def _extract_structured_claims_for_audit(answer: str) -> list[dict[str, Any]]:
    """Extract structured provider claims for claim-level diagnostics.

    JSON providers frequently return the claims correctly while the legacy
    line-oriented auditor sees ``"evidence_references": [...]`` as prose and
    reports empty references.  That is a diagnostics bug, not a grounding
    failure, so structured claims get a first-class audit path.
    """
    raw = str(answer or "").strip()
    candidates = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.I | re.S)
    candidates.extend(fenced)
    if raw.startswith("{"):
        candidates.append(raw)
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if isinstance(obj, dict) and isinstance(obj.get("claims"), list):
            return [x for x in obj["claims"] if isinstance(x, dict)]
    # Prose around JSON: recover the first balanced object.
    start = raw.find("{")
    while start >= 0:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(raw)):
            c = raw[i]
            if in_string:
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    in_string = False
                continue
            if c == '"':
                in_string = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(raw[start:i + 1])
                    except (json.JSONDecodeError, TypeError, ValueError):
                        break
                    if isinstance(obj, dict) and isinstance(obj.get("claims"), list):
                        return [x for x in obj["claims"] if isinstance(x, dict)]
                    break
        start = raw.find("{", start + 1)
    return []


def audit_claim_level_grounding(answer: str, context: Dict[str, Any]) -> dict[str, Any]:
    """Audit individual analyst claims, not just citation IDs.

    v0.8.4 retains exact-term citation matching, but a citation can still
    support only the *event* while the sentence adds an unsupported security
    interpretation (for example, a gvfs process being described as data
    exfiltration). v0.8.4 makes that distinction explicit.
    """
    structured_claims = _extract_structured_claims_for_audit(answer)
    if structured_claims:
        lookup = _event_lookup(context)
        allowed = _allowed_ids(context)
        claims: list[dict[str, Any]] = []
        for item in structured_claims[:40]:
            claim = str(item.get("text") or item.get("claim") or "").strip()
            if not claim:
                continue
            refs = item.get("evidence_references", item.get("evidence_ids", item.get("evidence", [])))
            if isinstance(refs, str):
                refs = extract_evidence_ids(refs)
            elif isinstance(refs, list):
                refs = extract_evidence_ids(" ".join(str(x) for x in refs))
            else:
                refs = []
            refs = list(dict.fromkeys(refs + extract_evidence_ids(claim)))
            valid = [e for e in refs if e in allowed and e in lookup]
            invalid = [e for e in refs if e not in allowed or e not in lookup]
            if invalid:
                status = "UNSUPPORTED_CITATION"
            elif not valid:
                status = "UNCITED_OBSERVATION" if str(item.get("type", "")).upper() == "VERIFIED_FACT" else "INTERPRETATION_ONLY"
            else:
                local = audit_citation_relevance(claim + " " + " ".join(f"[{e}]" for e in valid), context)
                mismatched = [x for x in local.get("mismatched", []) if x.get("evidence_id") in valid]
                proposed = str(item.get("type") or "").upper()
                if mismatched:
                    status = "CITATION_MISMATCH"
                elif proposed in {"GROUNDED_INTERPRETATION", "INTERPRETATION", "HYPOTHESIS", "INFERENCE"} or bool(_INFERENCE_RE.search(claim)):
                    status = "EVENT_SUPPORTED_INTERPRETATION_UNPROVEN"
                else:
                    status = "SUPPORTED_OBSERVATION"
            claims.append({
                "claim": claim,
                "section": "STRUCTURED CLAIM",
                "evidence_ids": valid or refs,
                "basis_evidence_ids": [],
                "status": status,
                "inference": status == "EVENT_SUPPORTED_INTERPRETATION_UNPROVEN",
            })
        unique = []
        seen = set()
        for item in claims:
            key = (item.get("claim", "").strip().lower(), tuple(item.get("evidence_ids", [])))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return {
            "claims": unique,
            "duplicate_claims_removed": len(claims) - len(unique),
            "supported_observations": [x for x in unique if x["status"] == "SUPPORTED_OBSERVATION"],
            "citation_mismatches": [x for x in unique if x["status"] == "CITATION_MISMATCH"],
            "unsupported_citations": [x for x in unique if x["status"] == "UNSUPPORTED_CITATION"],
            "interpretation_claims": [x for x in unique if x["status"] in {"EVENT_SUPPORTED_INTERPRETATION_UNPROVEN", "INTERPRETATION_ONLY"}],
            "uncited_observations": [x for x in unique if x["status"] == "UNCITED_OBSERVATION"],
            "deterministic_assessments": [],
            "insufficient_specificity": [],
        }

    lookup = _event_lookup(context)
    allowed = _allowed_ids(context)
    citation_audit = audit_citation_relevance(answer, context)
    by_key = {(x["evidence_id"], x["claim"]): x for x in citation_audit["supported"] + citation_audit["mismatched"]}
    claims: list[dict[str, Any]] = []
    section = ""
    for raw in str(answer or "").splitlines():
        current = _section_name_for_line(raw)
        if current:
            section = current
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("─"):
            continue
        ids = extract_evidence_ids(stripped)
        claim = _claim_for_citation(stripped)
        if not claim or not re.search(r"\b(?:[A-Za-z]{3,}|[0-9])", claim):
            continue
        is_bullet = bool(re.match(r"^(?:[-*•]|\d+[.)])\s+", stripped))
        if not is_bullet and not ids:
            continue
        deterministic_section = section in {"DETERMINISTIC INTERPRETATION", "DETERMINISTIC RISK ASSESSMENT", "DIRECT ANSWER"}
        inference = (bool(_INFERENCE_RE.search(claim)) or section in _INTERPRETATION_SECTIONS) and not deterministic_section
        concrete_terms = _high_signal_terms(claim)
        semantic_anchor = bool(re.search(
            r"\b(?:root|privileged|authentication|authenticat(?:ion|ed)?|login|failed\s+login|successful\s+login|\"?sshd\"?|process|command|execution|network|connection|transfer|user|source\s+ip|destination\s+ip)\b",
            claim, re.I,
        ))
        if ids and not concrete_terms and not semantic_anchor and not re.search(r"\b(?:privileged/root|root\s+context|root\s+execution|privileged\s+context)\b", claim, re.I) and not (bool(_INFERENCE_RE.search(claim)) or section in _INTERPRETATION_SECTIONS):
            status = "INSUFFICIENT_SPECIFICITY"
            claims.append({
                "claim": claim, "section": section or "UNSECTIONED", "evidence_ids": ids,
                "basis_evidence_ids": [], "status": status, "inference": False,
            })
            continue
        if ids:
            valid_ids = [e for e in ids if e in allowed and e in lookup]
            mismatches = []
            unsupported = []
            for evid in valid_ids:
                item = by_key.get((evid, claim))
                if item and not item["semantically_supported"]:
                    mismatches.append(evid)
                elif not item:
                    # Re-audit exact line in case a normalized citation changed the key.
                    local = audit_citation_relevance(stripped, context)
                    if any(x["evidence_id"] == evid and not x["semantically_supported"] for x in local["mismatched"]):
                        mismatches.append(evid)
            unsupported.extend([e for e in ids if e not in allowed])
            if unsupported:
                status = "UNSUPPORTED_CITATION"
            elif mismatches:
                status = "CITATION_MISMATCH"
            elif inference:
                status = "EVENT_SUPPORTED_INTERPRETATION_UNPROVEN"
            else:
                status = "SUPPORTED_OBSERVATION"
        else:
            if section in _OBSERVATION_SECTIONS or (is_bullet and not section):
                status = "UNCITED_OBSERVATION"
            elif inference:
                status = "INTERPRETATION_ONLY"
            else:
                continue
        basis_ids = [] if ids else _recovery_candidate_ids(claim, context, limit=1)
        if not ids and not basis_ids:
            claim_terms = {t for t in _high_signal_terms(claim) if not t.startswith("line:")}
            for record in _evidence_records(context):
                if claim_terms & _event_terms(record["text"]):
                    basis_ids = [record["evidence_id"]]
                    break
        claims.append({
            "claim": claim,
            "section": section or "UNSECTIONED",
            "evidence_ids": ids,
            "basis_evidence_ids": basis_ids,
            "status": status,
            "inference": inference,
        })
    # Deduplicate identical claims while preserving first occurrence.
    unique = []
    seen = set()
    for item in claims:
        key = (item.get("section"), re.sub(r"\s+", " ", item.get("claim", "")).strip().lower(), tuple(item.get("evidence_ids", [])))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    duplicate_claims_removed = max(0, len([x for x in claims]) - len(unique))
    claims = unique
    insufficient_specificity = [x for x in claims if x.get("status") == "INSUFFICIENT_SPECIFICITY"]
    return {
        "claims": claims,
        "duplicate_claims_removed": duplicate_claims_removed,
        "supported_observations": [x for x in claims if x["status"] == "SUPPORTED_OBSERVATION"],
        "citation_mismatches": [x for x in claims if x["status"] == "CITATION_MISMATCH"],
        "unsupported_citations": [x for x in claims if x["status"] == "UNSUPPORTED_CITATION"],
        "interpretation_claims": [x for x in claims if x["status"] in {"EVENT_SUPPORTED_INTERPRETATION_UNPROVEN", "INTERPRETATION_ONLY"}],
        "uncited_observations": [x for x in claims if x["status"] == "UNCITED_OBSERVATION"],
        "deterministic_assessments": [x for x in claims if x.get("section") in {"DETERMINISTIC INTERPRETATION", "DETERMINISTIC RISK ASSESSMENT"}],
        "insufficient_specificity": insufficient_specificity,
    }


def _downgrade_unscoped_confidence(text: str, claim_audit: dict[str, Any]) -> str:
    """Prevent high confidence from being asserted for unproven security interpretations."""
    if not claim_audit.get("interpretation_claims") and not claim_audit.get("citation_mismatches"):
        return text
    if not re.search(r"\bconfidence\s*[:=]\s*high\b", text, re.I):
        return text
    return re.sub(
        r"(\bconfidence\s*[:=]\s*)high\b",
        r"\1moderate",
        text,
        flags=re.I,
    )

def _risk_calibration_note(claim_audit: dict[str, Any]) -> str | None:
    risky = [x for x in claim_audit.get("interpretation_claims", []) if _INFERENCE_RE.search(x["claim"])]
    bad = claim_audit.get("citation_mismatches", []) + claim_audit.get("unsupported_citations", [])
    if not risky and not bad:
        return None
    if bad:
        return (
            "Risk calibration: one or more AI claims contain citation mismatches or unsupported citation IDs. "
            "Those claims are not treated as verified findings. Deterministic event evidence remains authoritative."
        )
    return (
        "Risk calibration: security interpretations such as privilege escalation, data leakage/exfiltration, "
        "malicious activity, unauthorized access, SSH connection activity, or performance impact are treated as "
        "hypotheses unless the supplied deterministic evidence directly establishes them. A cited event proves "
        "the event, not intent, causality, or risk."
    )

def ground_response(
    answer: str,
    context: Dict[str, Any],
    *,
    question: str = "",
    fallback_limit: int = 3,
) -> str:
    """Validate AI evidence citations and detect citation-to-event mismatches."""
    text = str(answer or "").strip()
    original_cited = [evid for evid in extract_evidence_ids(text) if evid in _allowed_ids(context)]
    text, recovered = recover_observation_citations(text, context)
    text, removed = _clean_invalid_citations(text, _allowed_ids(context))
    if not text:
        text = "The selected AI provider returned an empty assessment."

    allowed = _allowed_ids(context)
    cited = [evid for evid in extract_evidence_ids(text) if evid in allowed]

    audit = audit_citation_relevance(text, context, allow_shared_claim=bool(recovered))
    claim_audit = audit_claim_level_grounding(text, context)
    calibrated_text = _downgrade_unscoped_confidence(text, claim_audit)
    if calibrated_text != text:
        text = calibrated_text
        audit = audit_citation_relevance(text, context)
        claim_audit = audit_claim_level_grounding(text, context)
    supported_ids = list(dict.fromkeys(x["evidence_id"] for x in audit["supported"]))
    mismatched = audit["mismatched"]

    lookup = _event_lookup(context)
    structured_claims = _extract_structured_claims_for_audit(answer)
    display_text = text
    if structured_claims:
        display_text = (
            "Provider returned a structured evidence-grounded assessment. "
            "The normalized claim results are shown below; raw provider JSON is omitted from the analyst display."
        )
    lines = [
        display_text,
        "",
        "────────────────────────────────────────",
        "EVIDENCE GROUNDING",
        "────────────────────────────────────────",
        f"Question: {str(question or context.get('question') or '').strip()}",
        f"Evidence bundle: {len(lookup)} immutable record(s) shared by retrieval, AI context, and validator.",
    ]

    if recovered:
        lines.append(
            "Citation recovery: LogAsis added deterministic evidence references to "
            f"{len(recovered)} uncited observation(s) whose concrete terms matched the immutable evidence bundle."
        )

    if cited:
        if mismatched:
            lines.append(
                f"Grounding status: {len(cited)} citation ID(s) were supplied; "
                f"{len(mismatched)} citation-to-event mismatch(es) were detected by LogAsis."
            )
            lines.append("WARNING: A valid EVID ID does not automatically make the AI claim evidence-supported.")
        elif recovered and not original_cited:
            lines.append(
                f"Grounding status: {len(cited)} deterministic evidence reference(s) were attached by LogAsis "
                "after the AI omitted explicit EVID citations. Citation relevance checked by LogAsis."
            )
        elif supported_ids:
            lines.append(
                f"Grounding status: {len(supported_ids)} deterministic evidence reference(s) cited by AI. "
                "Citation relevance checked by LogAsis."
            )
        else:
            lines.append(
                "Grounding status: Citation IDs are valid, but the cited claims contain no concrete terms "
                "that LogAsis can independently match to the event records."
            )
        if recovered and not original_cited:
            lines.append("Evidence references used for grounding: " + ", ".join(f"[{item}]" for item in cited))
        else:
            lines.append("AI-cited evidence: " + ", ".join(f"[{item}]" for item in cited))
        if supported_ids:
            lines.append("")
            lines.append("VERIFIED EVIDENCE REFERENCES:")
            for evid in supported_ids:
                lines.append(f"- [{evid}] {_compact_evidence_line(lookup.get(evid, 'Evidence record unavailable.'))}")
        if mismatched:
            lines.append("")
            lines.append("CITATION RELEVANCE WARNINGS:")
            for item in mismatched:
                missing = ", ".join(item["missing_terms"][:8]) or "concrete claim terms"
                lines.append(
                    f"- [{item['evidence_id']}] does not contain claim term(s): {missing}. "
                    "Treat that claim as AI interpretation, not verified evidence."
                )
        lines.append("")
        lines.append(
            "Citation rule: an EVID ID identifies a deterministic retrieval record. "
            "It does not prove the AI's interpretation, intent, causality, or risk rating."
        )
    else:
        fallback = _fallback_evidence_ids(context, fallback_limit)
        if fallback:
            lines.append(
                "Grounding status: AI did not cite a supplied evidence ID. "
                "The following evidence was retrieved by LogAsis for analyst review; "
                "it is not presented as proof of every AI statement."
            )
            lines.append("Retrieved evidence basis:")
            for evid in fallback:
                lines.append(f"- [{evid}] {_compact_evidence_line(lookup[evid])}")
        else:
            lines.append(
                "Grounding status: No deterministic event evidence was retrieved for this question. "
                "The AI assessment must be treated as inconclusive."
            )

    if removed:
        unique_removed = list(dict.fromkeys(removed))
        lines.append(
            "Safety note: LogAsis removed unsupported evidence reference(s) "
            + f"({len(unique_removed)} reference(s))."
        )

    # EVID labels are LogAsis-generated provenance labels, not fields that are
    # expected to exist in the original raw log. Some local models incorrectly
    # describe the absence of raw EVID text as a grounding limitation. Clarify
    # that distinction without changing the model's substantive assessment.
    if (
        re.search(r"(?:log|log data|log file)[^\n]{0,120}(?:does not contain|does not have|no specific|without)[^\n]{0,60}EVID", text, re.I)
        or re.search(r"(?:no|without|does not)[^\n]{0,60}EVID[^\n]{0,80}(?:log|log data|log file)", text, re.I)
    ):
        lines.append(
            "Grounding clarification: EVID-xxx labels are generated by LogAsis "
            "for deterministic evidence provenance; they are not expected to "
            "appear in the original raw log."
        )

    lines += [
        "",
        "CLAIM-LEVEL GROUNDING",
        "────────────────────────────────────────",
    ]
    claim_lines = claim_audit.get("claims", [])
    if claim_lines:
        for item in claim_lines[:20]:
            evid_text = ", ".join(f"[{e}]" for e in item.get("evidence_ids", [])) or "none"
            basis = item.get("basis_evidence_ids", []) or []
            basis_text = ", ".join(f"[{e}]" for e in basis)
            short_claim = " ".join(item["claim"].split())
            if len(short_claim) > 220:
                short_claim = short_claim[:196].rstrip() + " …"
            lineage = f" | basis={basis_text}" if basis_text else ""
            lines.append(f"- {item['status']}: {short_claim} | evidence={evid_text}{lineage}")
        if len(claim_lines) > 20:
            lines.append(f"- … {len(claim_lines)-20} additional claim(s) omitted from the display.")
    else:
        lines.append("- No individually auditable analyst claims were identified.")
    note = _risk_calibration_note(claim_audit)
    if note:
        lines += ["", note]
    lines += [
        "",
        f"Unique verified event claims: {len(claim_audit.get('supported_observations', []))}",
        f"Duplicate claims removed: {claim_audit.get('duplicate_claims_removed', 0)}",
        "Grounding rule: deterministic LogAsis evidence remains authoritative. "
        "AI interpretation does not create new events, entities, timestamps, or security facts.",
    ]
    return "\n".join(lines).strip()


def validate_evidence_citations(answer: str, context: Dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic citation audit useful to tests and future UI."""
    allowed = _allowed_ids(context)
    cited = extract_evidence_ids(answer or "")
    valid = [item for item in cited if item in allowed]
    invalid = [item for item in cited if item not in allowed]
    semantic = audit_citation_relevance(answer, context)
    return {
        "allowed_count": len(allowed),
        "cited_count": len(cited),
        "valid_ids": list(dict.fromkeys(valid)),
        "invalid_ids": list(dict.fromkeys(invalid)),
        "semantically_supported_ids": list(dict.fromkeys(x["evidence_id"] for x in semantic["supported"])),
        "citation_mismatches": semantic["mismatched"],
        "grounded": bool(valid) and not semantic["mismatched"],
    }
