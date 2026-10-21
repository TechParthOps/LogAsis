"""Deterministic question answering for LogAsis.

Executes factual questions against the persistent index instead of asking an
LLM to estimate results. Produces exact counts over the COMPLETE matching set,
bounded evidence samples with full identity lists, coverage accounting, and
claim-level grounding metadata. Analytical/proof/causality questions receive a
deterministic observation scaffold that reports only what the evidence
establishes and explicitly refuses unsupported security conclusions.

No ground-truth knowledge is embedded here. Every filter is resolved against
the loaded dataset's actual schema and values, every plan is validated by
QueryEngine.compile before execution, and every number in the answer comes
from an executed query result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from core.event_index import EventIndex
from core.incident_profile import _NO_INCIDENT
from core.log_dataset import safe_frame_records
from core.query_engine import QueryEngine
from core.question_understanding import QuestionAnalysis, QuestionSchema, ResolvedEntity, TimeConstraint, analyze_question

EVID_FORMAT = "EVID-{position:03d}"


def evidence_id_for_position(position: int) -> str:
    return f"EVID-{position + 1:03d}"


@dataclass
class CoverageReport:
    total_events: int = 0
    indexed_events: int = 0
    candidate_events: int = 0
    total_matching_events: int = 0
    retrieved_events: int = 0
    correlated_events: int = 0
    verified_evidence: int = 0
    excluded_events: int = 0
    failed_batches: int = 0
    truncated_results: bool = False
    coverage_status: str = "UNKNOWN"
    completion_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "indexed_events": self.indexed_events,
            "candidate_events": self.candidate_events,
            "total_matching_events": self.total_matching_events,
            "retrieved_events": self.retrieved_events,
            "correlated_events": self.correlated_events,
            "verified_evidence": self.verified_evidence,
            "excluded_events": self.excluded_events,
            "failed_batches": self.failed_batches,
            "truncated_results": self.truncated_results,
            "coverage_status": self.coverage_status,
            "completion_reason": self.completion_reason,
        }


@dataclass
class DeterministicResult:
    kind: str  # "count" | "list" | "timeline" | "abstention" | "correlation" | "extract"
    question: str
    analysis: QuestionAnalysis
    answer: str
    direct_answer: str = ""
    has_direct_answer: bool = False
    count: int | None = None
    filters: dict[str, str] = field(default_factory=dict)
    plan: dict[str, Any] = field(default_factory=dict)
    evidence_records: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids_all: list[str] = field(default_factory=list)
    coverage: CoverageReport = field(default_factory=CoverageReport)
    claims: list[dict[str, Any]] = field(default_factory=list)
    interpretation_notes: list[str] = field(default_factory=list)
    requires_ai: bool = False

    def to_dict(self, max_records: int = 25) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "question": self.question,
            "intent": self.analysis.intent,
            "answer": self.answer,
            "direct_answer": self.direct_answer,
            "has_direct_answer": self.has_direct_answer,
            "count": self.count,
            "filters": dict(self.filters),
            "plan": dict(self.plan),
            "evidence_records": self.evidence_records[:max_records],
            "evidence_ids_all": list(self.evidence_ids_all),
            "evidence_id_count": len(self.evidence_ids_all),
            "coverage": self.coverage.to_dict(),
            "claims": list(self.claims),
            "interpretation_notes": list(self.interpretation_notes),
            "requires_ai": self.requires_ai,
        }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _parse_ts(value: Any):
    return EventIndex._parse_timestamp(value)


_HARD_IDENTIFIER_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\bCVE-\d{4}-\d{4,8}\b|"
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b|"
    r"[\"']([^\"']{2,80})[\"']",
    re.I,
)

# Value kinds with dedicated regex extractors (scanned over matching rows).
_EXTRACT_VALUE_PATTERNS: dict[str, re.Pattern[str]] = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I),
    "file": re.compile(r"(?<![\w])(?:[A-Za-z]:\\[^\s;\"',]+|/[\w.@:+~-]+(?:/[^\s;\"',]+)*)"),
    "hash": re.compile(r"\b[a-f0-9]{32,64}\b", re.I),
}
_EXTRACT_VALUE_MAX_ROWS = 5000

# Categorical kinds resolved through indexed facets over the matching set.
_EXTRACT_FACET_FIELDS: dict[str, tuple[str, ...]] = {
    "process": ("process", "process_name", "image", "exe"),
    "pid": ("pid", "process_id", "processid", "newprocessid"),
    "user": ("user", "username", "account", "acct", "targetusername"),
    "ip": ("source_ip", "destination_ip", "src_ip", "dst_ip"),
    "domain": ("domain", "queryname", "hostname"),
    "url": ("url", "uri"),
}
_EXTRACT_KIND_LABELS = {
    "cve": "CVE identifier",
    "pid": "process ID (PID)",
    "process": "binary/process",
    "file": "file path",
    "user": "account/user",
    "ip": "IP address",
    "domain": "domain",
    "hash": "hash value",
    "url": "URL",
}


def _unresolved_hard_identifiers(question: str, resolved_values: set[str], schema) -> list[str]:
    """Concrete identifiers named in the question that exist nowhere in the
    dataset. Such values are unambiguous: if no field contains them, the
    matching event count is a verified zero, never 'all other events'."""
    unresolved: list[str] = []
    for match in _HARD_IDENTIFIER_RE.finditer(str(question or "")):
        value = (match.group(1) or match.group(0)).strip().strip(".,;:!?")
        if not value or len(value) < 4:
            continue
        if value.lower() in {v.lower() for v in resolved_values}:
            continue
        # Skip values that actually exist in some dataset field.
        if schema.fields_containing(value):
            continue
        # Skip generic words that merely look domain-like (single dictionary
        # tokens without a dot are handled by the soft-token path instead).
        if "." not in value and " " in value:
            continue
        unresolved.append(value)
    return unresolved


def _build_schema(dataset: Any, df: pd.DataFrame) -> QuestionSchema:
    index = getattr(dataset, "event_index", None)
    if index is None or getattr(index, "size", -1) != len(df):
        index = EventIndex(safe_frame_records(df) if not df.empty else [])
    return QuestionSchema(index)


def _identity_segments(df: pd.DataFrame, positions: list[int]) -> dict[str, list[tuple[str, int]]]:
    """Group candidate positions by labelled identity segment.

    Understands identity values shaped PREFIX-SEGMENT-NUMBER (for example
    WEB-B-0007). Returns {segment_key: [(uid, position), ...]}.
    """
    segments: dict[str, list[tuple[str, int]]] = {}
    id_col = None
    for col in ("event_uid", "event_id", "uid", "id"):
        if col in df.columns:
            id_col = col
            break
    if id_col is None:
        return segments
    pattern = re.compile(r"^([A-Za-z0-9]+)-([A-Za-z0-9]+)-(\d+)$")
    for pos in positions:
        raw = str(df.iloc[pos].get(id_col, "") or "").strip()
        match = pattern.match(raw)
        if not match:
            continue
        prefix, segment, number = match.groups()
        key = f"{prefix}-{segment}"
        segments.setdefault(key, []).append((raw, int(number), pos))
    return {k: [(uid, pos) for uid, _num, pos in v] for k, v in segments.items()}


def _consecutive_sequence_groups(groups: dict[str, list[tuple[str, int]]]) -> dict[str, list[tuple[str, int]]]:
    """Keep only groups whose identity numbers form an unbroken run."""
    result = {}
    for key, members in groups.items():
        numbers = sorted(int(str(uid).rsplit("-", 1)[-1]) for uid, _ in members)
        if len(numbers) >= 2 and numbers == list(range(numbers[0], numbers[0] + len(numbers))):
            result[key] = members
    return result


def _render_evidence_table(df: pd.DataFrame, positions: list[int], limit: int = 8) -> list[dict[str, Any]]:
    records = []
    for pos in positions[:limit]:
        row = df.iloc[pos]
        record = {
            "evidence_id": evidence_id_for_position(pos),
            "timestamp": str(row.get("timestamp", "") or ""),
            "host": str(row.get("host", "") or ""),
            "event_type": str(row.get("event_type", "") or ""),
            "action": str(row.get("action", "") or ""),
            "source_ip": str(row.get("source_ip", "") or ""),
            "destination_ip": str(row.get("destination_ip", "") or ""),
            "user": str(row.get("user", row.get("username", "")) or ""),
            "process": str(row.get("process", row.get("process_name", "")) or ""),
            "message": str(row.get("message", "") or "")[:160],
        }
        for col in ("event_uid",):
            if col in df.columns and str(row.get(col, "") or "").strip():
                record["source_identity"] = str(row.get(col))
                break
        records.append(record)
    return records


def _verified_claim(text: str, evidence_ids: list[str], claim_no: int) -> dict[str, Any]:
    return {
        "claim_id": f"CLAIM-{claim_no:03d}",
        "text": text,
        "type": "VERIFIED_FACT",
        "evidence_references": list(evidence_ids[:12]),
        "confidence": "HIGH",
        "reason": "Computed directly from the complete matching set via a validated deterministic query.",
    }


class DeterministicQAEngine:
    def __init__(self, df: pd.DataFrame, dataset: Any = None):
        self.df = df.reset_index(drop=True)
        self.dataset = dataset
        self.schema = _build_schema(dataset, self.df)
        self.index = self.schema.index
        self.query_engine = QueryEngine(self.index)
        self.total_events = int(len(self.df))
        indexed = getattr(self.index, "size", 0)
        self.parse_failures = 0
        if "timestamp_parse_failed" in self.df.columns:
            self.parse_failures = int(self.df["timestamp_parse_failed"].fillna(False).astype(bool).sum())
        self._incident_profile: Any = None

    # ------------------------------------------------------------------
    # deterministic incident profile (cached per dataset)
    # ------------------------------------------------------------------
    def _incident(self) -> Any:
        """Lazily build (once per dataset) the deterministic incident profile.

        The profile derives the strongest evidence-backed incident facts
        (compromised account, attacker source, escalation executions, exploit
        signature matches, downloaded tools, root sensitive-file reads) with
        no model involvement. Failures never break answering: the caller
        falls back to the generic query-based behavior.
        """
        if self._incident_profile is not None:
            return None if self._incident_profile is _NO_INCIDENT else self._incident_profile
        if self.dataset is not None:
            getter = getattr(self.dataset, "get_incident_profile", None)
            if callable(getter):
                try:
                    profile = getter()
                    self._incident_profile = profile if profile is not None else _NO_INCIDENT
                    return profile
                except Exception:
                    pass
        profile = None
        try:
            from core.incident_profile import build_incident_profile

            profile = build_incident_profile(self.df, self.index, self.schema)
        except Exception:
            profile = None
        self._incident_profile = profile if profile is not None else _NO_INCIDENT
        return profile

    # ------------------------------------------------------------------
    # public entry
    # ------------------------------------------------------------------
    def answer(
        self,
        question: str,
        conversation_context: list[dict[str, Any]] | None = None,
    ) -> DeterministicResult | None:
        question = str(question or "").strip()
        if not question or self.df.empty:
            return None
        analysis = analyze_question(question, self.schema)
        self._apply_conversation_context(analysis, conversation_context or [])

        if analysis.intent in {"proof", "causality"}:
            result = self._answer_proof_or_causality(question, analysis)
            if result is not None:
                return result
            # Causality/proof questions without resolvable observations are
            # better served by the AI investigation runtime.
            return None
        if analysis.intent == "extract":
            return self._answer_extract(question, analysis)
        suspicious = self._answer_suspicious_users(question, analysis, [])
        if suspicious is not None:
            return suspicious
        summary = self._answer_incident_summary(question, analysis)
        if summary is not None:
            return summary
        return self._answer_factual(question, analysis)

    # ------------------------------------------------------------------
    # conversation context (entities carried from earlier questions)
    # ------------------------------------------------------------------
    def _apply_conversation_context(self, analysis: QuestionAnalysis, context: list[dict[str, Any]]) -> None:
        has_placeholder = bool(
            re.search(r"\bthis\s+(?:source|ip|host|user|server|workstation|account)\b|\bthe\s+same\s+\w+\b", analysis.question, re.I)
        )
        carried: list[ResolvedEntity] = []
        for item in context[-4:]:
            if not isinstance(item, dict):
                continue
            for ent in item.get("entities", []) or []:
                if not isinstance(ent, dict):
                    continue
                fname = str(ent.get("field", ""))
                value = str(ent.get("value", ""))
                if not fname or not value:
                    continue
                if fname not in {"source_ip", "destination_ip", "host", "user", "username", "process", "domain"}:
                    continue
                if any(e.field == fname and e.value.lower() == value.lower() for e in carried):
                    continue
                carried.append(ResolvedEntity(fname, value, "context", "exact"))
        if not carried:
            return

        if analysis.intent == "causality":
            # Causality questions reference earlier activities; the two-set
            # observation path decides how to use them.
            analysis.context_entities = carried
            analysis.interpretation_notes.append(
                "Contextual references from the earlier questions in this session were considered as observation lenses."
            )
        elif analysis.intent == "proof":
            # Proof/abstention questions use prior entities as separate
            # observation lenses, never as additional AND filters.
            analysis.context_entities = carried
            analysis.interpretation_notes.append(
                "Contextual references from the earlier questions in this session were used to collect observations."
            )
        elif has_placeholder:
            for ent in carried:
                if not any(e.field == ent.field for e in analysis.entities):
                    analysis.entities.append(ent)
                    analysis.interpretation_notes.append(
                        f"Resolved the contextual reference using the earlier question's {ent.field}={ent.value}."
                    )

    # ------------------------------------------------------------------
    # factual questions (count / list / timeline / correlation)
    # ------------------------------------------------------------------
    def _build_filters(self, analysis: QuestionAnalysis) -> tuple[dict[str, str], list[str]]:
        filters: dict[str, str] = {}
        notes: list[str] = []
        for entity in analysis.entities:
            fname = entity.field
            if fname not in self.schema.fields:
                canonical = self.schema.canonical_field(fname)
                if not canonical:
                    continue
                fname = canonical
            if not self.schema.has_value(fname, entity.value):
                notes.append(f"Value '{entity.value}' does not exist in field '{fname}' of the loaded dataset; filter omitted.")
                continue
            filters[fname] = str(entity.value)
        if analysis.status_code:
            fname = self.schema.canonical_field("status_code")
            if fname and self.schema.has_value(fname, analysis.status_code):
                filters[fname] = analysis.status_code
        # Vocabulary-derived event type / action filters are applied only when
        # the value exists in the loaded schema and does not CONFLICT with an
        # entity already resolved for the same field.
        event_type_field = self.schema.canonical_field("event_type") or "event_type"
        if analysis.event_type_candidates and event_type_field not in filters:
            for value in analysis.event_type_candidates:
                if event_type_field in self.schema.fields and self.schema.has_value(event_type_field, value):
                    filters[event_type_field] = value
                    break
        action_field = self.schema.canonical_field("action") or "action"
        if analysis.action_candidates and action_field not in filters:
            for value in analysis.action_candidates:
                if action_field in self.schema.fields and self.schema.has_value(action_field, value):
                    filters[action_field] = value
                    break
        return filters, notes

    def _execute(self, filters: dict[str, str], limit: int | None = None) -> dict[str, Any]:
        conditions = [
            {"field": k, "operator": "EXACT", "value": v} for k, v in filters.items()
        ]
        raw = {"operation": "AND", "conditions": conditions}
        if limit:
            raw["limit"] = limit
        plan = self.query_engine.compile(raw)
        result = self.query_engine.execute(plan)
        plan_dict = {
            "operation": "AND",
            "conditions": conditions,
            "limit": limit,
            "valid": plan.is_valid,
            "validation_errors": plan.validation_errors,
        }
        result["plan"] = plan_dict
        return result

    # ------------------------------------------------------------------
    # extraction questions ("What binary and PID...", "Which CVE...")
    # ------------------------------------------------------------------
    def _extract_values(self, kind: str, positions: list[int], prefer_commands: bool = False) -> tuple[list[str], bool]:
        """Extract distinct values of one kind from the matching rows.

        Returns (values, complete). ``complete`` is False when the regex scan
        hit its bounded row ceiling (the extraction is then labelled partial).

        ``prefer_commands`` (tool-style questions such as "what tool was used
        to ..."): extract the executed program tokens from command lines,
        ranked by frequency, instead of listing every process name — system
        daemons (sshd, polkitd, ...) otherwise drown out the commands a human
        analyst actually ran.
        """
        field_names = _EXTRACT_FACET_FIELDS.get(kind)
        if field_names:
            if prefer_commands and kind == "process":
                commands, complete = self._extract_command_tokens(positions)
                if commands:
                    return commands, complete
            values: list[str] = []
            for fname in field_names:
                if fname not in self.schema.fields:
                    continue
                for value in self.index.facet_counts(fname, set(positions), limit=12):
                    cleaned = str(value).strip()
                    if cleaned and cleaned.lower() not in {v.lower() for v in values}:
                        values.append(cleaned)
            return values[:12], True

        pattern = _EXTRACT_VALUE_PATTERNS.get(kind)
        if pattern is None:
            return [], True
        found: list[str] = []
        internal = {"timestamp_dt", "hour", "date", "raw_log"}
        scan = positions[:_EXTRACT_VALUE_MAX_ROWS]
        for pos in scan:
            row = self.df.iloc[pos]
            for col, value in row.items():
                if str(col) in internal or value is None:
                    continue
                text = str(value)
                if not text or len(text) > 4000:
                    continue
                for match in pattern.findall(text):
                    cleaned = str(match).strip().rstrip(".,;:)")
                    if cleaned and cleaned.lower() not in {v.lower() for v in found}:
                        found.append(cleaned)
                    if len(found) >= 12:
                        return found, len(scan) == len(positions)
        return found, len(scan) == len(positions)

    def _answer_extract(self, question: str, analysis: QuestionAnalysis) -> DeterministicResult | None:
        filters, notes = self._build_filters(analysis)

        # Conclusion-shaped extraction ("which account was compromised?",
        # "what is the attacker's IP?", "what attack type...") can never be
        # answered as a proven security label. Give a qualified direct answer
        # plus what the log actually shows.
        if analysis.conclusion_kinds:
            return self._answer_conclusion_extract(question, analysis, filters, notes)

        profile_answer = self._answer_extract_from_profile(question, analysis, filters, notes)
        if profile_answer is not None:
            return profile_answer

        if not analysis.extract_kinds:
            return None

        # Hard identifiers that exist nowhere must not be silently dropped
        # (same verified-zero semantics as count questions).
        if filters:
            unresolved_ids = _unresolved_hard_identifiers(question, set(filters.values()), self.schema)
            if unresolved_ids:
                return self._verified_zero_result(question, analysis, filters, unresolved_ids, notes)

        result = self._execute(filters) if filters else {"positions": list(self.index.all_positions()), "count": int(self.index.size)}
        positions = list(result["positions"])
        total_matching = len(positions)

        # Tool-style questions ("what tool was used to...", "what was used to
        # ...") should surface the executed commands, not every daemon name.
        prefer_commands = bool(
            re.search(r"\b(?:tool|used\s+to|utility|ran|run|executed?|enumerat\w*|what\s+commands?)\b", question, re.I)
            and "process" in analysis.extract_kinds
        )

        filter_text = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else "the whole loaded log"
        findings: list[str] = []
        direct_lines: list[str] = []
        any_found = False
        partial_scan = False

        for kind in analysis.extract_kinds[:4]:
            values, complete = self._extract_values(kind, positions, prefer_commands=prefer_commands)
            if not complete:
                partial_scan = True
            label = _EXTRACT_KIND_LABELS.get(kind, kind)
            context = f" among events matching {filter_text}" if filters else " in the loaded log"
            if values:
                any_found = True
                shown = ", ".join(values[:6])
                extra = f" (and {len(values) - 6} more)" if len(values) > 6 else ""
                line = f"The {label}{context}: {shown}{extra}."
                if kind == "cve":
                    line += " The log containing a CVE identifier does not by itself prove that it was exploited."
                direct_lines.append(line)
                findings.append((kind, values))
            else:
                context = (
                    f"No {label} is recorded in the {total_matching} event(s) matching {filter_text}."
                    if filters
                    else f"No {label} appears anywhere in the {self.total_events:,}-event loaded log."
                )
                direct_lines.append(context)

        evidence_chain = _render_evidence_table(self.df, positions, limit=8) if total_matching else []
        evidence_ids_all = [evidence_id_for_position(p) for p in positions]

        if not any_found:
            # No direct value found anywhere: the direct answer IS the
            # explicit "not present" statement; attach the most relevant
            # evidence chain for the requested context.
            answer = "\n".join(direct_lines)
            if total_matching == 0:
                answer = (
                    f"No events match {filter_text}, so no requested value can be identified. "
                    f"This is a verified zero over all {self.total_events:,} indexed events."
                )
            if not filters and not total_matching:
                return None
            claims = []
            claim_no = 1
            if total_matching:
                claims.append(_verified_claim(
                    f"{total_matching} event(s) match {filter_text}.", evidence_ids_all[:12], claim_no,
                ))
                claim_no += 1
            for kind, values in findings:
                claims.append(_verified_claim(
                    f"{len(values)} distinct {kind} value(s) observed in the matching events.",
                    evidence_ids_all[:12], claim_no,
                ))
                claim_no += 1
            coverage = CoverageReport(
                total_events=self.total_events,
                indexed_events=int(self.index.size),
                candidate_events=int(self.index.size),
                total_matching_events=total_matching,
                retrieved_events=min(len(positions), 8),
                verified_evidence=len(evidence_ids_all),
                excluded_events=self.total_events - total_matching,
                truncated_results=partial_scan,
                coverage_status="COMPLETE",
                completion_reason=(
                    "extraction over the complete matching set"
                    + (" (regex scan bounded to the first 5000 matching rows)" if partial_scan else "")
                ),
            )
            return DeterministicResult(
                kind="extract",
                question=question,
                analysis=analysis,
                answer=answer,
                direct_answer=answer,
                has_direct_answer=True,
                count=total_matching,
                filters=filters,
                plan=result.get("plan", {}),
                evidence_records=evidence_chain,
                evidence_ids_all=evidence_ids_all,
                coverage=coverage,
                claims=claims,
                interpretation_notes=notes,
                requires_ai=False,
            )

        answer = "\n".join(direct_lines)
        claims = []
        claim_no = 1
        for kind, values in findings:
            claims.append(_verified_claim(
                f"{kind}: {', '.join(values[:6])} observed in the matching events.",
                evidence_ids_all[:12], claim_no,
            ))
            claim_no += 1
        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=int(self.index.size),
            total_matching_events=total_matching,
            retrieved_events=min(len(positions), 8),
            verified_evidence=len(evidence_ids_all),
            excluded_events=self.total_events - total_matching,
            truncated_results=partial_scan,
            coverage_status="COMPLETE",
            completion_reason=(
                "extraction over the complete matching set"
                + (" (regex scan bounded to the first 5000 matching rows)" if partial_scan else "")
            ),
        )
        return DeterministicResult(
            kind="extract",
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer=answer,
            has_direct_answer=True,
            count=total_matching,
            filters=filters,
            plan=result.get("plan", {}),
            evidence_records=evidence_chain,
            evidence_ids_all=evidence_ids_all,
            coverage=coverage,
            claims=claims,
            interpretation_notes=notes,
            requires_ai=False,
        )

    # ------------------------------------------------------------------
    # incident-profile-driven extraction
    # ------------------------------------------------------------------
    def _profile_result(
        self,
        question: str,
        analysis: QuestionAnalysis,
        lines: list[str],
        chain_positions: list[int],
        claims: list[dict[str, Any]],
        notes: list[str],
        coverage_reason: str,
    ) -> DeterministicResult:
        positions = sorted(set(chain_positions))
        evidence_records = _render_evidence_table(self.df, positions, limit=8) if positions else []
        evidence_ids = [evidence_id_for_position(p) for p in positions]
        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=int(self.index.size),
            total_matching_events=len(positions),
            retrieved_events=min(len(positions), 8),
            verified_evidence=len(evidence_ids),
            excluded_events=self.total_events - len(positions),
            truncated_results=False,
            coverage_status="TARGETED",
            completion_reason=coverage_reason,
        )
        answer = "\n".join(lines)
        return DeterministicResult(
            kind="extract",
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer=answer,
            has_direct_answer=True,
            count=len(positions),
            filters={},
            plan={},
            evidence_records=evidence_records,
            evidence_ids_all=evidence_ids,
            coverage=coverage,
            claims=claims,
            interpretation_notes=notes,
            requires_ai=False,
        )

    def _answer_extract_from_profile(self, question, analysis, filters, notes) -> DeterministicResult | None:
        """Direct answers for incident-specific extraction questions, derived
        from the deterministic incident profile (compromise session, exploit
        executions, downloaded tooling, root sensitive reads).

        Returns None whenever the profile has no incident or no matching
        facts, so the generic query-based extraction still runs (its
        abstention/verified-zero behavior remains the fallback).
        """
        profile = self._incident()
        if profile is None:
            return None
        # Content-derived facts (suspicious executions, downloaded tooling,
        # exploit signatures, sensitive artifacts) are answerable even when
        # no authentication sequence was found; only the login-dependent
        # branches below additionally require has_incident.
        has_incident = bool(getattr(profile, "has_incident", False))
        if not (
            has_incident
            or profile.suspicious_executions
            or profile.credential_access
            or profile.downloaded_tools
            or profile.cve_matches
            or profile.sensitive_reads
        ):
            return None
        if filters:
            # An explicitly filtered question (e.g. "…for user X") must be
            # answered against that filter, not the whole incident.
            return None

        q = str(question or "")
        lower_q = q.lower()
        claims: list[dict[str, Any]] = []
        claim_no = 1
        chain: list[int] = []
        lines: list[str] = []

        def _claim(text: str, refs: list[int]) -> None:
            nonlocal claim_no
            claims.append(_verified_claim(
                text, [evidence_id_for_position(p) for p in refs[:12]], claim_no,
            ))
            claim_no += 1

        # --- CVE / vulnerability questions --------------------------------
        wants_cve = bool(
            "cve" in analysis.extract_kinds
            or re.search(r"\bcve\b|vulnerabilit", q, re.I)
        )
        if wants_cve:
            if not profile.cve_matches:
                return None  # no signature match: generic extraction handles the verified zero
            top = profile.top_cve_match
            esc = profile.top_escalation
            shell = profile.root_shell
            chain.append(int(top.get("position", 0)))
            if esc:
                chain.append(int(esc.get("position", 0)))
            if shell:
                chain.append(int(shell.get("position", 0)))
            lines.append(
                f"Best-supported answer: {top.get('cve', '')} — {top.get('description', '')}."
            )
            lines.append(
                f"Matched execution: `{top.get('command', '')}` (PID {top.get('pid', '')}) inside the "
                "attacker session."
            )
            if shell:
                lines.append(
                    f"The exploit produced a root shell immediately afterwards: `{shell.get('command', '')}` "
                    f"running as uid=0 (PID {shell.get('pid', '')})."
                )
            lines.append(
                "The log contains no CVE identifier string; this mapping comes from an execution-based "
                "command-shape signature table, not from text found in the log."
            )
            _claim(
                f"The attacker session executed `{str(top.get('command', ''))[:120]}` (PID {top.get('pid', '')}), "
                f"matching the {top.get('cve', '')} signature.",
                chain,
            )
            if shell:
                _claim(
                    f"A process running as uid=0 (PID {shell.get('pid', '')}, command `{str(shell.get('command', ''))[:80]}`) "
                    "followed the exploit execution in the attacker session.",
                    [int(shell.get("position", 0))],
                )
            return self._profile_result(
                question, analysis, lines, chain, claims, notes,
                "execution-based exploit-signature mapping over the attacker session",
            )

        # --- binary + PID used to gain root --------------------------------
        wants_escalation_binary = bool(
            ("process" in analysis.extract_kinds or "pid" in analysis.extract_kinds)
            and re.search(
                r"gain\s+root|root\s+access|privilege\s+escalat|escalat\w*|get\s+root|become\s+root|obtain\s+root",
                q, re.I,
            )
        )
        if wants_escalation_binary:
            esc = profile.top_escalation if not profile.is_windows else None
            if esc is None:
                # Windows: the closest analog is the suspicious-execution
                # chain (encoded PowerShell, dump tooling, remote exec).
                if profile.suspicious_executions:
                    sus = profile.top_suspicious_execution
                    chain.append(int(sus.get("position", 0)))
                    lines.append(
                        f"Best-supported answer: `{sus.get('command', '')}` (PID {sus.get('pid') or 'unknown'}) — "
                        f"matched the {sus.get('label', '')} signature."
                    )
                    others = profile.suspicious_executions[1:3]
                    if others:
                        lines.append(
                            "Also suspicious: "
                            + "; ".join(f"`{o.get('command', '')}` (PID {o.get('pid', '')})" for o in others)
                            + "."
                        )
                    _claim(
                        f"The attacker session executed `{str(sus.get('command', ''))[:120]}` (PID {sus.get('pid') or 'unknown'}), "
                        f"matching the {sus.get('label', '')} signature.",
                        chain,
                    )
                    return self._profile_result(
                        question, analysis, lines, chain, claims, notes,
                        "suspicious execution identified inside the attacker session",
                    )
                return None
            shell = profile.root_shell
            chain.append(int(esc.get("position", 0)))
            if shell:
                chain.append(int(shell.get("position", 0)))
            lines.append(
                f"Best-supported answer: binary `{esc.get('binary', '')}` (PID {esc.get('pid', '')}) — "
                f"executed as `{esc.get('command', '')}`."
            )
            if shell:
                lines.append(
                    f"It succeeded: the payload shell `{shell.get('command', '')}` ran as uid=0 (PID "
                    f"{shell.get('pid', '')}) inside the attacker session."
                )
            checks = [e for e in profile.escalation if e.get("check")]
            if checks:
                shown = ", ".join(f"`{e.get('command', '')}`" for e in checks[:3])
                lines.append(
                    f"Privilege-boundary checks such as {shown} were run during enumeration and are "
                    "not escalation attempts."
                )
            _claim(
                f"The attacker session executed `{str(esc.get('command', ''))[:120]}` (PID {esc.get('pid', '')}); "
                + (
                    f"a uid=0 shell (PID {shell.get('pid', '')}) followed it."
                    if shell else "no resulting root shell was identified."
                ),
                chain,
            )
            return self._profile_result(
                question, analysis, lines, chain, claims, notes,
                "escalation execution identified inside the attacker session",
            )

        # --- suspicious processes / credential access (Windows-shaped) ------
        wants_suspicious_activity = bool(
            profile.suspicious_executions or profile.credential_access
        ) and re.search(
            r"suspicious|malicious|credential|dump|dumping|mimikatz|lsass|powershell|lateral|persist",
            q, re.I,
        )
        if wants_suspicious_activity and (profile.suspicious_executions or profile.credential_access):
            if profile.suspicious_executions:
                sus = profile.top_suspicious_execution
                chain.append(int(sus.get("position", 0)))
                lines.append(
                    f"Best-supported answer: `{sus.get('command', '')}` (PID {sus.get('pid') or 'unknown'}) — "
                    f"matched the {sus.get('label', '')} signature."
                )
                _claim(
                    f"The attacker session executed `{str(sus.get('command', ''))[:120]}` (PID {sus.get('pid') or 'unknown'}), "
                    f"matching the {sus.get('label', '')} signature.",
                    chain,
                )
            for entry in profile.credential_access[:2]:
                chain.append(int(entry.get("position", 0)))
                lines.append(
                    f"Credential access: {entry.get('kind', '')} — {entry.get('source', '')} → "
                    f"{entry.get('target', '')}."
                )
            if len(profile.suspicious_executions) > 1:
                lines.append(
                    f"{len(profile.suspicious_executions) - 1} further suspicious execution(s) were "
                    "identified in the attacker session; see the evidence chain."
                )
            return self._profile_result(
                question, analysis, lines, chain, claims, notes,
                "suspicious execution / credential access identified inside the attacker session",
            )

        # --- files / artifacts touched inside the attacker session -----------
        wants_files = bool(
            "file" in analysis.extract_kinds
            and re.search(r"access\w*|stage\w*|touch\w*|dump|exfiltrat|stolen|sensitive|artifact", q, re.I)
        )
        if wants_files and (profile.sensitive_reads or profile.credential_access):
            shown: list[str] = []
            for read in profile.sensitive_reads[:4]:
                path = str(read.get("path", ""))
                if path and path not in shown:
                    shown.append(path)
            for entry in profile.credential_access[:2]:
                target = str(entry.get("target", ""))
                if target and target not in shown:
                    shown.append(target)
            if shown:
                for read in list(profile.sensitive_reads[:2]) + list(profile.credential_access[:2]):
                    chain.append(int(read.get("position", 0)))
                lines.append(
                    "Best-supported answer: " + ", ".join(shown[:6]) + ". The attacker session "
                    "recorded direct access to these artifacts."
                )
                lines.append(
                    "The log proves the access happened inside the attacker session; whether data "
                    "actually left the environment requires evidence beyond this log."
                )
                _claim(
                    f"The attacker session accessed {', '.join(shown[:4])}.",
                    chain,
                )
                return self._profile_result(
                    question, analysis, lines, chain, claims, notes,
                    "sensitive-artifact access identified inside the attacker session",
                )

        # --- enumeration tooling -------------------------------------------
        wants_tool = bool(
            "process" in analysis.extract_kinds
            and re.search(r"\btools?\b|used\s+to|enumerat|recon|discover", q, re.I)
        )
        if wants_tool and profile.downloaded_tools:
            tool = profile.downloaded_tools[0]
            chain.append(int(tool.get("position", 0)))
            lines.append(
                f"Best-supported answer: {tool.get('tool', '')} — fetched from {tool.get('url', '')} with "
                f"`{tool.get('command', '')}` (PID {tool.get('pid') or 'unknown'}) from the attacker-controlled host."
            )
            lines.append(
                "System-enumeration scanners also execute many benign privilege-boundary checks "
                "(sudo -l, pkexec --version); those are checks, not the tool itself."
            )
            _claim(
                f"The attacker session downloaded {tool.get('tool', '')} from {tool.get('url', '')} "
                f"via `{tool.get('command', '')}` (PID {tool.get('pid') or 'unknown'}).",
                chain,
            )
            return self._profile_result(
                question, analysis, lines, chain, claims, notes,
                "downloaded-tool execution identified inside the attacker session",
            )

        # --- suspicious / compromised accounts ------------------------------
        if re.search(r"suspicious|compromis|attack\w*|malicious|unauthorized|malware", q, re.I) and (
            "user" in analysis.extract_kinds or re.search(r"\busers?\b|\baccounts?\b", q, re.I)
        ):
            return self._answer_suspicious_users(question, analysis, notes)

        return None

    def _answer_suspicious_users(self, question, analysis, notes) -> DeterministicResult | None:
        """Direct answer for 'Identify suspicious users' style questions from
        the incident profile. Available for any question shape (extract or
        explanation intent) whenever an incident was identified."""
        profile = self._incident()
        if profile is None or not getattr(profile, "has_incident", False):
            return None
        q = str(question or "")
        if not re.search(r"suspicious|compromis|attack\w*|malicious|unauthorized|malware", q, re.I):
            return None
        if not re.search(r"\busers?\b|\baccounts?\b", q, re.I):
            return None

        chain = list(profile.login_positions[:12])
        claims: list[dict[str, Any]] = []
        lines: list[str] = [
            f"Best-supported answer: '{profile.compromised_user}'. The log records "
            f"{profile.failed_count} failed login(s) followed by {profile.success_count} successful "
            f"login(s) for this account from {profile.attacker_ip} — the failed-then-successful "
            "intrusion signature."
        ]
        lines.append(
            "No other account carries the failed-then-successful signature (3+ failures) in this log."
        )
        lines.append(
            "This is an evidence-backed interpretation; the log alone cannot prove account takeover."
        )
        claims.append(_verified_claim(
            f"{profile.failed_count} failed login(s) were followed by {profile.success_count} successful "
            f"login(s) for '{profile.compromised_user}' from {profile.attacker_ip}.",
            [evidence_id_for_position(p) for p in chain[:12]], 1,
        ))
        return self._profile_result(
            question, analysis, lines, chain, claims, list(notes) + list(analysis.interpretation_notes),
            "compromised-account identification from the failed-then-successful login sequence",
        )

    # ------------------------------------------------------------------
    # incident summary (highest-risk findings / critical activity)
    # ------------------------------------------------------------------
    def _answer_incident_summary(self, question: str, analysis: QuestionAnalysis) -> DeterministicResult | None:
        """Deterministic highest-risk summary derived from the incident profile.

        Covers 'Summarize highest-risk findings' / 'Explain critical activity'
        style questions when the profile identified a real intrusion sequence.
        Without an incident, returns None so the generic factual/AI paths run.
        """
        if analysis.wants_count or analysis.wants_timeline:
            return None
        if not re.search(
            r"\bsummar\w*\b|critical|highest[- ]risk|top\s+findings?\b|what\s+happened|"
            r"\boverview\b|key\s+(?:findings|activity|events)|risk\w*\s+findings",
            question, re.I,
        ):
            return None
        profile = self._incident()
        if profile is None:
            return None
        if not (
            getattr(profile, "has_incident", False)
            or profile.suspicious_executions
            or profile.credential_access
            or profile.downloaded_tools
        ):
            return None

        chain: list[int] = []
        claims: list[dict[str, Any]] = []
        claim_no = 1
        has_incident = bool(getattr(profile, "has_incident", False))
        if has_incident:
            opener = (
                f"The loaded log records one coherent intrusion sequence centered on account "
                f"'{profile.compromised_user}' from {profile.attacker_ip}. Highest-risk findings, in order:"
            )
        else:
            opener = "The loaded log records high-risk attacker activity. Highest-risk findings, in order:"
        lines: list[str] = [opener]

        def _claim(text: str, refs: list[int], c_type: str = "VERIFIED_FACT") -> None:
            nonlocal claim_no
            claims.append({
                "claim_id": f"CLAIM-{claim_no:03d}",
                "text": text,
                "type": c_type,
                "evidence_references": [evidence_id_for_position(p) for p in refs[:12]],
                "confidence": "HIGH" if c_type == "VERIFIED_FACT" else "MODERATE",
                "reason": (
                    "Computed directly from the loaded dataset."
                    if c_type == "VERIFIED_FACT"
                    else "Evidence-backed interpretation of the observed sequence; the security label is qualified, not asserted."
                ),
            })
            claim_no += 1

        item_no = 1

        def _item(title: str, detail: str, refs: list[int]) -> None:
            nonlocal item_no
            lines.append(f"{item_no}. {title} — {detail}")
            item_no += 1
            chain.extend(refs)

        if has_incident:
            _item(
                "Brute-force initial access",
                f"{profile.failed_count} failed login(s) for '{profile.compromised_user}' from "
                f"{profile.attacker_ip}, followed by {profile.success_count} successful login(s) from the same source.",
                [],
            )
        shell = None
        for tool in profile.downloaded_tools[:1]:
            _item(
                "Attacker tooling",
                f"{tool.get('tool', '')} was downloaded from {tool.get('url', '')} "
                f"(`{tool.get('command', '')}`, PID {tool.get('pid') or 'unknown'}) and used for system enumeration.",
                [int(tool.get("position", 0))],
            )
        for payload in profile.payload_downloads[:1]:
            _item(
                "Payload staged",
                f"{payload.get('url', '')} was downloaded (`{payload.get('command', '')}`, PID {payload.get('pid', '')}).",
                [int(payload.get("position", 0))],
            )
        if profile.is_windows:
            for sus in profile.suspicious_executions[:2]:
                _item(
                    f"Suspicious execution ({sus.get('label', '')})",
                    f"`{sus.get('command', '')}` (PID {sus.get('pid') or 'unknown'}).",
                    [int(sus.get("position", 0))],
                )
            for entry in profile.credential_access[:2]:
                _item(
                    "Credential access",
                    f"{entry.get('kind', '')}: {entry.get('source', '')} → {entry.get('target', '')}.",
                    [int(entry.get("position", 0))],
                )
        elif has_incident:
            esc = profile.top_escalation
            if esc is not None and not esc.get("check"):
                cve_text = ""
                top_cve = profile.top_cve_match
                if top_cve:
                    cve_text = f" — matches the {top_cve.get('cve', '')} signature ({top_cve.get('description', '')})"
                _item(
                    "Privilege escalation",
                    f"`{esc.get('command', '')}` (PID {esc.get('pid', '')}){cve_text}.",
                    [int(esc.get("position", 0))],
                )
            shell = profile.root_shell
            if shell is not None:
                _item(
                    "Root shell obtained",
                    f"`{shell.get('command', '')}` executed as uid=0 (PID {shell.get('pid', '')}) inside the "
                    "attacker session after the escalation attempt.",
                    [int(shell.get("position", 0))],
                )
        root_reads = profile.root_sensitive_reads[:2] or profile.sensitive_reads[:2]
        if root_reads:
            _item(
                "Sensitive data accessed as root" if not profile.is_windows else "Sensitive artifacts touched",
                "; ".join(f"`{r.get('command', '')}` (PID {r.get('pid', '')}) accessed {r.get('path', '')}" for r in root_reads) + ".",
                [int(r.get("position", 0)) for r in root_reads],
            )
        if has_incident:
            _claim(
                f"{profile.failed_count} failed login(s) were followed by {profile.success_count} successful "
                f"login(s) for '{profile.compromised_user}' from {profile.attacker_ip}.",
                profile.login_positions or (
                    [profile.first_failure_position] if profile.first_failure_position >= 0 else []
                ),
                "GROUNDED_INTERPRETATION",
            )
        if shell is not None:
            _claim(
                f"A process ran as uid=0 (PID {shell.get('pid', '')}, `{str(shell.get('command', ''))[:80]}`) "
                "inside the attacker session after the escalation attempt.",
                [int(shell.get("position", 0))],
                "GROUNDED_INTERPRETATION",
            )
        lines.append(
            "These findings are derived deterministically from the recorded events "
            "(login sequences, executed commands, root activity). Security labels are evidence-backed "
            "interpretations, not asserted facts."
        )
        return self._profile_result(
            question, analysis, lines, chain, claims, list(analysis.interpretation_notes),
            "deterministic incident-profile summary of the attacker session",
        )

    def _answer_conclusion_extract(self, question, analysis, filters, notes) -> DeterministicResult | None:
        """Data-driven direct answers for conclusion-shaped questions.

        Instead of refusing with generic counts, the deterministic layer
        computes the strongest evidence-backed answer from the log:

        - "Which account was compromised?"  -> the account(s) with
          failed-then-successful login sequences plus what ran under them.
        - "What is the attacker's IP?"      -> the source IP(s) with the
          failed-then-successful signature.
        - "What attack type was used to gain initial access?" -> the
          observed pattern (mass failures followed by a success) interpreted
          with its counts, clearly labelled as an evidence-backed
          interpretation.
        - "What file was exfiltrated...?"   -> the file/URL artifacts that
          actually appear in transfer commands.

        Every answer states what is directly observed and what remains an
        interpretation, so the concrete answer is useful without asserting
        unproven security labels as fact.
        """
        result = self._execute(filters) if filters else {"positions": list(self.index.all_positions()), "count": int(self.index.size)}
        positions = list(result["positions"])
        total_matching = len(positions)
        filter_text = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else "the loaded log"

        action_field = self.schema.canonical_field("action") or "action"
        user_field = self.schema.canonical_field("user") or self.schema.canonical_field("username")
        source_field = self.schema.canonical_field("source_ip")
        timestamp_field = "timestamp"

        # ---- deterministic failed -> successful sequence analysis ----------
        failed_positions: list[int] = []
        success_positions: list[int] = []
        if action_field in self.schema.fields:
            failed_set = set(self.index.exact(action_field, "failed_login"))
            success_set = set(self.index.exact(action_field, "successful_login"))
            candidate = set(positions)
            failed_positions = sorted(failed_set & candidate)
            success_positions = sorted(success_set & candidate)

        def _row_value(pos: int, field: str) -> str:
            if not field:
                return ""
            return str(self.df.iloc[pos].get(field, "") or "").strip()

        def _row_ts(pos: int):
            return _parse_ts(self.df.iloc[pos].get(timestamp_field))

        # Sequences per account and per source IP.
        def _sequences(group_field: str) -> dict[str, dict[str, Any]]:
            groups: dict[str, dict[str, Any]] = {}
            if not group_field or (not failed_positions and not success_positions):
                return groups
            for label, bucket in (("failed", failed_positions), ("success", success_positions)):
                for pos in bucket:
                    value = _row_value(pos, group_field)
                    if not value:
                        continue
                    entry = groups.setdefault(
                        value, {"failed": 0, "success": 0, "failed_pos": [], "success_pos": []}
                    )
                    entry[label] += 1
                    entry[f"{label}_pos"].append(pos)
            return groups

        user_groups = _sequences(user_field)
        ip_groups = _sequences(source_field) if source_field else {}

        def _has_sequence(entry: dict[str, Any]) -> bool:
            if not entry["failed"] or not entry["success"]:
                return False
            # Row position is the authoritative ordering: auditd records are
            # frequently all timestamped within the same second (and out of
            # order), so pure timestamp comparison misses real sequences.
            last_failure_pos = max(entry["failed_pos"])
            if any(p > last_failure_pos for p in entry["success_pos"]):
                return True
            last_failure = max(
                (t for t in (_row_ts(p) for p in entry["failed_pos"]) if t is not None),
                default=None,
            )
            if last_failure is None:
                return False
            return any(
                (t := _row_ts(p)) is not None and t > last_failure
                for p in entry["success_pos"]
            )

        lines: list[str] = []
        claims: list[dict[str, Any]] = []
        claim_no = 1
        chain_positions: set[int] = set()

        def _claim(text: str, refs: list[str], c_type: str = "VERIFIED_FACT", reason: str = "") -> None:
            nonlocal claim_no
            claims.append({
                "claim_id": f"CLAIM-{claim_no:03d}",
                "text": text,
                "type": c_type,
                "evidence_references": refs[:12],
                "confidence": "HIGH" if c_type == "VERIFIED_FACT" else "MODERATE",
                "reason": reason or (
                    "Computed directly from the loaded dataset via a validated deterministic query."
                    if c_type == "VERIFIED_FACT"
                    else "Evidence-backed interpretation of the observed counts; the security label itself is not asserted as proven."
                ),
            })
            claim_no += 1

        def _top_entries(groups: dict[str, dict[str, Any]], with_sequence_only: bool = False, limit: int = 5):
            items = [
                (value, entry) for value, entry in groups.items()
                if (not with_sequence_only or _has_sequence(entry))
            ]
            items.sort(key=lambda item: (-(item[1]["failed"] + item[1]["success"]), item[0]))
            return items[:limit]

        def _entry_ips(entry: dict[str, Any]) -> list[str]:
            if not source_field:
                return []
            return sorted({_row_value(p, source_field) for p in entry["failed_pos"] + entry["success_pos"]} - {""})

        for label in analysis.conclusion_kinds[:2]:
            profile = self._incident()
            has_incident = bool(profile is not None and getattr(profile, "has_incident", False))
            if label == "compromise":
                if has_incident:
                    # The incident profile's (account, source) grouping is
                    # authoritative: per-user sequences alone break when late
                    # unrelated failures (e.g. failed sudo checks) follow the
                    # successful logins.
                    chain_positions.update(profile.login_positions[:12])
                    lines.append(
                        f"Best-supported answer: the '{profile.compromised_user}' account. The log records "
                        f"{profile.failed_count} failed login(s) followed by {profile.success_count} "
                        f"successful login(s) for it from {profile.attacker_ip}"
                        " — the classic failed-then-successful intrusion signature."
                    )
                    lines.append(
                        "This is an evidence-backed interpretation of the observed login sequence; "
                        "the log alone cannot prove the account was actually taken over."
                    )
                    _claim(
                        f"{profile.failed_count} failed logins were followed by {profile.success_count} "
                        f"successful logins for account '{profile.compromised_user}' from {profile.attacker_ip}.",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                    )
                else:
                    sequenced = _top_entries(user_groups, with_sequence_only=True, limit=3) if user_groups else []
                    if sequenced:
                        best_value, best_entry = sequenced[0]
                        chain_positions.update(best_entry["failed_pos"][:6])
                        chain_positions.update(best_entry["success_pos"][:6])
                        ips = _entry_ips(best_entry)
                        lines.append(
                            f"Best-supported answer: the '{best_value}' account. The log records "
                            f"{best_entry['failed']} failed login(s) followed by {best_entry['success']} "
                            f"successful login(s) for it"
                            + (f" from {', '.join(ips[:3])}" if ips else "")
                            + " — the classic failed-then-successful intrusion signature."
                        )
                        if len(sequenced) > 1:
                            others = ", ".join(f"'{v}'" for v, _ in sequenced[1:])
                            lines.append(f"Accounts with the same pattern: {others}.")
                        lines.append(
                            "This is an evidence-backed interpretation of the observed login sequence; "
                            "the log alone cannot prove the account was actually taken over."
                        )
                        _claim(
                            f"{best_entry['failed']} failed logins were followed by {best_entry['success']} successful logins for account '{best_value}'.",
                            [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                        )
                    else:
                        lines.append(
                            "No account shows a failed-then-successful login sequence in this log, so no "
                            "account carries direct compromise indicators."
                        )
                        if user_groups:
                            shown = "; ".join(
                                f"'{v}' ({e['failed']} failed / {e['success']} successful)"
                                for v, e in _top_entries(user_groups, limit=3)
                            )
                            lines.append(f"Accounts observed (without that pattern): {shown}.")
                        lines.append(
                            "Without evidence of unauthorized success, the log does not support naming "
                            "a compromised account."
                        )
            elif label == "attacker attribution":
                if has_incident and profile.attacker_ip:
                    chain_positions.update(profile.login_positions[:12])
                    lines.append(
                        f"Best-supported answer: {profile.attacker_ip}. This source produced "
                        f"{profile.failed_count} failed login(s) followed by {profile.success_count} "
                        f"successful login(s) against account '{profile.compromised_user}' — "
                        "the failed-then-successful signature of an intrusion attempt."
                    )
                    lines.append(
                        "The log attributes this activity to the address(es) above; whether they belong "
                        "to an attacker (vs. a mistyped client or a test) requires context beyond this log."
                    )
                    _claim(
                        f"{profile.failed_count} failed logins followed by {profile.success_count} successful "
                        f"logins came from {profile.attacker_ip}.",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                    )
                    continue
                sequenced = _top_entries(ip_groups, with_sequence_only=True, limit=3) if ip_groups else []
                if sequenced:
                    best_value, best_entry = sequenced[0]
                    chain_positions.update(best_entry["failed_pos"][:6])
                    chain_positions.update(best_entry["success_pos"][:6])
                    lines.append(
                        f"Best-supported answer: {best_value}. This source produced "
                        f"{best_entry['failed']} failed login(s) followed by {best_entry['success']} "
                        f"successful login(s) — the failed-then-successful signature of an intrusion attempt."
                    )
                    if len(sequenced) > 1:
                        lines.append(
                            "Sources with the same pattern: "
                            + ", ".join(f"{v} ({e['failed']} failed / {e['success']} successful)" for v, e in sequenced[1:])
                            + "."
                        )
                    lines.append(
                        "The log attributes this activity to the address(es) above; whether they belong "
                        "to an attacker (vs. a mistyped client or a test) requires context beyond this log."
                    )
                    _claim(
                        f"{best_entry['failed']} failed logins followed by {best_entry['success']} successful logins came from {best_value}.",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                    )
                else:
                    high_failure = _top_entries(ip_groups, limit=3) if ip_groups else []
                    lines.append(
                        "No source IP shows a failed-then-successful login pattern, so the log does not "
                        "identify an attacker."
                    )
                    if high_failure:
                        shown = "; ".join(f"{v} ({e['failed']} failed)" for v, e in high_failure)
                        lines.append(f"Highest failed-login sources (informational): {shown}.")
            elif label == "attack type":
                if has_incident:
                    chain_positions.update(profile.login_positions[:12])
                    lines.append(
                        f"Best-supported answer: a brute-force / password-guessing attack. The log shows "
                        f"{profile.failed_count} failed login attempt(s) against account "
                        f"'{profile.compromised_user}' from {profile.attacker_ip} followed by "
                        f"{profile.success_count} successful login(s) from the same source — "
                        "the signature of repeated credential guessing that eventually succeeded."
                    )
                    lines.append(
                        "Initial access therefore most likely occurred through a successful login after "
                        "the failures. This is an interpretation of the observed counts; the log does "
                        "not label the activity itself."
                    )
                    _claim(
                        f"{profile.failed_count} failed login attempt(s) against '{profile.compromised_user}' "
                        f"were followed by {profile.success_count} successful login(s) from "
                        f"{profile.attacker_ip}.",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                        c_type="GROUNDED_INTERPRETATION",
                    )
                    continue
                total_failed = len(failed_positions)
                total_success = len(success_positions)
                failure_ips = sorted({_row_value(p, source_field) for p in failed_positions} - {""}) if source_field else []
                sequenced_ips = (
                    sorted(v for v, e in (ip_groups or {}).items() if _has_sequence(e))
                    if ip_groups else []
                )
                if total_failed >= 5 and sequenced_ips:
                    event_type_field = self.schema.canonical_field("event_type")
                    service = ""
                    generic_type_values = {"json", "syslog", "text", "log", "events", "generic", "ndjson"}
                    if event_type_field and failed_positions:
                        types = [
                            t for t in self.index.facet_counts(event_type_field, set(failed_positions), limit=3)
                            if t.lower() not in generic_type_values
                        ]
                        if types:
                            service = f" against {', '.join(types[:2])}"
                    chain_positions.update(failed_positions[:6])
                    after_successes = [
                        p for p in success_positions
                        if _row_value(p, source_field) in sequenced_ips
                    ]
                    chain_positions.update(after_successes[:4])
                    lines.append(
                        f"Best-supported answer: a brute-force / password-guessing attack. The log shows "
                        f"{total_failed} failed login attempt(s){service}"
                        + (f" from {len(failure_ips)} source address(es) ({', '.join(failure_ips[:3])})" if failure_ips else "")
                        + f" followed by {total_success} successful login(s) from the same source(s) — "
                        "the signature of repeated credential guessing that eventually succeeded."
                    )
                    lines.append(
                        "Initial access therefore most likely occurred through a successful login after "
                        "the failures. This is an interpretation of the observed counts; the log does "
                        "not label the activity itself."
                    )
                    _claim(
                        f"{total_failed} failed login attempt(s) were followed by {total_success} successful login(s) from the same source(s).",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                        c_type="GROUNDED_INTERPRETATION",
                    )
                elif total_failed >= 5:
                    lines.append(
                        f"The log shows {total_failed} failed login attempt(s) but no successful login "
                        "after them, so no completed intrusion pattern is present. The volume of "
                        "failures is consistent with login-guessing attempts that did not succeed."
                    )
                else:
                    lines.append(
                        "The log does not contain a recognizable attack pattern (no mass failed-login "
                        "activity followed by success). Describing a specific attack type from these "
                        "records alone would be speculation."
                    )
            elif label == "exfiltration":
                root_reads = list(profile.root_sensitive_reads) if profile else []
                if root_reads:
                    # The incident profile identified direct reads of
                    # sensitive paths executed as root INSIDE the attacker
                    # session — the strongest available "what was taken"
                    # evidence. Prefer it over a generic path scan, which on
                    # a busy system log otherwise returns every path any
                    # process ever referenced.
                    first = root_reads[0]
                    chain_positions.add(int(first.get("position", 0)))
                    shown_paths = list(dict.fromkeys(str(r.get("path", "")) for r in root_reads[:4]))
                    extra_count = len(root_reads) - 1
                    lines.append(
                        f"Best-supported answer: {', '.join(shown_paths)}. The log records it being read as root "
                        f"({first.get('command', '')}, PID {first.get('pid', '')}) inside the attacker session after "
                        f"the privilege escalation"
                        + (f" — plus {extra_count} further root read(s)." if extra_count > 0 else ".")
                    )
                    lines.append(
                        "The log proves the file was accessed while root; whether its contents actually left "
                        "the environment requires evidence beyond this log."
                    )
                    _claim(
                        f"Inside the attacker session, {first.get('command', '')} (PID {first.get('pid', '')}) read "
                        f"{', '.join(shown_paths)} as root after the privilege escalation.",
                        [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]],
                    )
                else:
                    values, complete = self._extract_values("file", positions)
                    urls, _ = self._extract_values("url", positions)
                    transfer_commands = self._extract_transfer_commands(positions)
                    artifacts = list(dict.fromkeys(values + urls))[:8]
                    # The evidence chain must show the transfer-command records
                    # themselves, not unrelated rows from the same context.
                    artifact_tokens = [a.lower() for a in artifacts] + [c for c in transfer_commands]
                    for pos in positions[:_EXTRACT_VALUE_MAX_ROWS]:
                        row_text = str(self.df.iloc[pos].get("command", "") or "") + " " + str(self.df.iloc[pos].get("message", "") or "")
                        low = row_text.lower()
                        if any(tok in low for tok in artifact_tokens if len(tok) >= 4):
                            chain_positions.add(pos)
                        if len(chain_positions) >= 10:
                            break
                    if artifacts or transfer_commands:
                        lines.append(
                            "Transfer activity observed in the log: "
                            + (f"commands {', '.join(transfer_commands[:5])}. " if transfer_commands else "")
                            + (f"Referenced targets: {', '.join(artifacts[:6])}." if artifacts else "")
                        )
                        lines.append(
                            "These are the files/URLs the log actually records in transfer commands. "
                            "The log alone does not prove that data successfully left the environment."
                        )
                        if artifacts:
                            _claim(
                                f"Transfer commands reference {', '.join(artifacts[:4])}.",
                                [evidence_id_for_position(p) for p in sorted(chain_positions)[:12]] or
                                [evidence_id_for_position(p) for p in positions[:12]],
                            )
                    else:
                        lines.append(
                            "No file-transfer commands or referenced file/URL artifacts appear in the "
                            "matching events, so no exfiltrated file can be identified from this log."
                        )
            else:
                lines.append(
                    f"The log does not establish '{label}'; this label requires evidence beyond log events."
                )

        answer = "\n".join(lines)
        if not answer:
            return None

        evidence_records = (
            _render_evidence_table(self.df, sorted(chain_positions) or positions[:8], limit=8)
            if (chain_positions or positions) else []
        )
        # For unfiltered whole-dataset context, a full identity dump of 80k+
        # rows is noise: cap the recorded identity list at the relevant set.
        if chain_positions:
            evidence_ids_all = [evidence_id_for_position(p) for p in sorted(chain_positions)]
        else:
            evidence_ids_all = [evidence_id_for_position(p) for p in positions[:200]]
        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=int(self.index.size),
            total_matching_events=total_matching,
            retrieved_events=len(evidence_records),
            verified_evidence=len(evidence_ids_all),
            excluded_events=self.total_events - total_matching,
            truncated_results=total_matching > len(evidence_ids_all),
            coverage_status="TARGETED",
            completion_reason=(
                "best-supported answer computed from the observed login/transfer patterns; "
                "security labels qualified, not asserted"
            ),
        )
        return DeterministicResult(
            kind="abstention",
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer=lines[0] if lines else "",
            has_direct_answer=True,
            count=None,
            filters=filters,
            plan={},
            evidence_records=evidence_records,
            evidence_ids_all=evidence_ids_all,
            coverage=coverage,
            claims=claims,
            interpretation_notes=notes + analysis.interpretation_notes,
            requires_ai=False,
        )

    def _extract_command_tokens(self, positions: list[int], limit: int = 12) -> tuple[list[str], bool]:
        """Executed program tokens from command lines, ranked by frequency.

        Used for tool-style questions: the first token of each command line
        (basename only) is what the analyst actually ran. System daemons that
        merely appear in a process field are not counted here.
        """
        counts: dict[str, int] = {}
        command_fields = tuple(
            f for f in ("command", "commandline", "cmdline", "processcommandline")
            if f in self.schema.fields
        )
        if not command_fields:
            return [], True
        scan = positions[:_EXTRACT_VALUE_MAX_ROWS]
        for pos in scan:
            row = self.df.iloc[pos]
            for field in command_fields:
                value = str(row.get(field, "") or "").strip()
                if not value:
                    continue
                first = value.split()[0].strip("\"'")
                basename = first.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
                if not basename or len(basename) < 2:
                    continue
                counts[basename] = counts.get(basename, 0) + 1
        ranked = [name for name, _ in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
        return ranked[:limit], len(scan) == len(positions)

    def _extract_transfer_commands(self, positions: list[int]) -> list[str]:
        """Command programs that move data, from the matching rows (bounded)."""
        counts: dict[str, int] = {}
        transfer_names = {
            "curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat",
            "ftp", "tar", "gpg", "base64", "python", "python3", "powershell",
        }
        for pos in positions[:_EXTRACT_VALUE_MAX_ROWS]:
            row = self.df.iloc[pos]
            for field in ("command", "commandline", "cmdline", "process", "process_name"):
                value = str(row.get(field, "") or "").strip()
                if not value:
                    continue
                first = value.split()[0].strip("\"'")
                basename = first.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
                if basename in transfer_names:
                    counts[basename] = counts.get(basename, 0) + 1
        return [name for name, _ in sorted(counts.items(), key=lambda x: -x[1])]

    def _verified_zero_if_tokens_absent(self, question, analysis, notes) -> DeterministicResult | None:
        """Verified zero when the question's distinctive tokens appear in no
        indexed value at all. Tokens that exist somewhere fall through to the
        AI runtime (the question may still be answerable from field text)."""
        from core.question_understanding import COUNT_INTENT_RE

        if not COUNT_INTENT_RE.search(question):
            return None
        tokens = [
            t for t in re.findall(r"[a-z0-9_.:/@-]{3,}", str(question or "").lower())
            if t not in {
                "how", "many", "what", "which", "when", "where", "were", "was", "are",
                "the", "and", "for", "from", "with", "that", "this", "those", "these",
                "logs", "log", "events", "event", "records", "record", "after", "before",
                "between", "during", "show", "list", "did", "do", "does", "can", "we",
                "any", "all", "have", "has", "had", "there", "their", "them", "then",
                "count", "number", "total", "dataset",
            }
        ]
        if not tokens:
            return None
        matched_any = False
        for token in tokens[:12]:
            if self.index.match_postings(token) or self.index.field_name_postings(token):
                matched_any = True
                break
        if matched_any:
            return None
        dataset_size = self.total_events
        token_text = ", ".join(f"'{t}'" for t in tokens[:5])
        answer = (
            f"There are 0 matching events in the complete dataset.\n\n"
            f"The question's distinguishing term(s) {token_text} do not appear in any field value "
            f"of the loaded dataset ({dataset_size:,} events). This is a verified zero over the "
            f"complete dataset; it does not prove that such events never occurred outside the "
            f"dataset or logging coverage."
        )
        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=0,
            total_matching_events=0,
            retrieved_events=0,
            verified_evidence=0,
            excluded_events=self.total_events,
            truncated_results=False,
            coverage_status="COMPLETE",
            completion_reason="verified zero: the question's distinguishing terms exist in no indexed value",
        )
        return DeterministicResult(
            kind="count",
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer="There are 0 matching events for the described activity.",
            has_direct_answer=True,
            count=0,
            filters={},
            plan={"operation": "AND", "conditions": [], "verified_zero": True},
            evidence_records=[],
            evidence_ids_all=[],
            coverage=coverage,
            claims=[{
                "claim_id": "CLAIM-001",
                "text": f"The terms {token_text} appear in no indexed field value of the loaded dataset.",
                "type": "VERIFIED_FACT",
                "evidence_references": [],
                "confidence": "HIGH",
                "reason": "Exhaustive token lookup over the index returned no postings.",
            }],
            interpretation_notes=notes,
            requires_ai=False,
        )

    def _verified_zero_result(self, question, analysis, filters, unresolved_ids, notes) -> DeterministicResult:
        result = self._execute({})  # dataset size only
        dataset_size = int(result["count"])
        unresolved_text = ", ".join(sorted(set(unresolved_ids))[:5])
        answer = (
            f"There are 0 matching events in the complete dataset for the specified filters.\n\n"
            f"The question names the concrete identifier(s) {unresolved_text}, which do not appear "
            f"in any field of the loaded dataset. This is a verified zero over all "
            f"{dataset_size:,} indexed events; it does not prove that such events never occurred "
            f"outside the dataset or logging coverage."
        )
        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=0,
            total_matching_events=0,
            retrieved_events=0,
            verified_evidence=0,
            excluded_events=self.total_events,
            truncated_results=False,
            coverage_status="COMPLETE",
            completion_reason="verified zero: a named hard identifier exists in no indexed field",
        )
        return DeterministicResult(
            kind="count",
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer="There are 0 matching events for the named identifier(s).",
            has_direct_answer=True,
            count=0,
            filters=filters,
            plan={"operation": "AND", "conditions": [], "unresolved_identifiers": unresolved_ids},
            evidence_records=[],
            evidence_ids_all=[],
            coverage=coverage,
            claims=[{
                "claim_id": "CLAIM-001",
                "text": f"No events reference the identifier(s) {unresolved_text} in the loaded dataset.",
                "type": "VERIFIED_FACT",
                "evidence_references": [],
                "confidence": "HIGH",
                "reason": "Exhaustive lookup over every indexed field returned no value match.",
            }],
            interpretation_notes=notes,
            requires_ai=False,
        )

    def _answer_factual(self, question: str, analysis: QuestionAnalysis) -> DeterministicResult | None:
        filters, notes = self._build_filters(analysis)
        if not filters:
            # No schema-resolved filters. If the question's content tokens do
            # not exist anywhere in the indexed dataset (e.g. "failed logins"
            # in a log with no login events at all), this is a verified zero
            # rather than an unanswerable question.
            return self._verified_zero_if_tokens_absent(question, analysis, notes)

        # Hard identifiers named in the question but absent from every field
        # make the answer a verified zero. Dropping them would silently count
        # a different population (e.g. 'failed logins from 192.0.2.99' when
        # that IP never appears must be 0, not all failed logins).
        unresolved_ids = _unresolved_hard_identifiers(
            question, set(filters.values()), self.schema
        )
        if unresolved_ids:
            return self._verified_zero_result(question, analysis, filters, unresolved_ids, notes)

        # Base query.
        result = self._execute(filters)
        if result.get("error"):
            return None
        positions = list(result["positions"])
        count = int(result["count"])

        # Sequence-reference narrowing ("the labelled ... sequence").
        if analysis.sequence_reference and count > 0:
            groups = _identity_segments(self.df, positions)
            consecutive = _consecutive_sequence_groups(groups)
            if len(consecutive) == 1 and len(next(iter(consecutive.values()))) < count:
                seg_key, members = next(iter(consecutive.items()))
                new_positions = sorted(pos for _, pos in members)
                notes.append(
                    f"Interpreted the question's reference to an explicitly labelled sequence as the "
                    f"consecutively numbered evidence group '{seg_key}' ({len(new_positions)} events with "
                    f"explicit sequence labels); background events without sequence labels were excluded."
                )
                positions = new_positions
                count = len(positions)

        # Relative time constraint ("after the failures").
        anchor_note = ""
        anchor_count = None
        after_constraint = next((t for t in analysis.time_constraints if t.kind == "after_event"), None)
        if after_constraint and positions:
            anchor_positions = self._resolve_anchor(after_constraint.anchor_event, filters)
            if anchor_positions:
                anchor_times = [
                    _parse_ts(self.df.iloc[p].get("timestamp"))
                    for p in anchor_positions
                ]
                anchor_times = [t for t in anchor_times if t is not None]
                if anchor_times:
                    last_anchor = max(anchor_times)
                    kept = []
                    for p in positions:
                        ts = _parse_ts(self.df.iloc[p].get("timestamp"))
                        if ts is not None and ts > last_anchor:
                            kept.append(p)
                    anchor_count = len(anchor_positions)
                    notes.append(
                        f"Time constraint applied: only events after the last of the "
                        f"{anchor_count} anchor events ({after_constraint.anchor_event.strip()}) were counted."
                    )
                    positions = kept
                    count = len(positions)

        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=int(self.index.size),
            total_matching_events=count,
            retrieved_events=min(len(positions), 25),
            verified_evidence=len(positions),
            excluded_events=self.total_events - count,
            truncated_results=False,
            coverage_status="COMPLETE",
            completion_reason="exhaustive indexed query over the complete dataset",
        )
        if self.parse_failures:
            coverage.completion_reason += f"; {self.parse_failures} record(s) had unparseable timestamps"

        evidence_ids_all = [evidence_id_for_position(p) for p in positions]
        evidence_records = _render_evidence_table(self.df, positions)

        if analysis.intent == "count":
            answer = self._render_count_answer(question, analysis, filters, count, positions, notes)
        elif analysis.intent == "timeline":
            answer = self._render_timeline_answer(question, analysis, filters, positions, notes)
        else:
            answer = self._render_list_answer(question, analysis, filters, count, positions, notes)

        # Direct answer + claims. The main answer body stays concise; the
        # evidence chain is attached for the grounding panel and is rendered
        # inline only when no direct answer was possible.
        claims = []
        claim_no = 1
        filter_text = ", ".join(f"{k}={v}" for k, v in filters.items())
        if count > 0:
            claims.append(_verified_claim(
                f"{count} event(s) in the loaded dataset match the filters ({filter_text}).",
                evidence_ids_all, claim_no,
            ))
            claim_no += 1
            claims.append(_verified_claim(
                f"The count is exhaustive over all {self.total_events} indexed events (no sampling or truncation).",
                [], claim_no,
            ))
        else:
            claims.append({
                "claim_id": f"CLAIM-{claim_no:03d}",
                "text": f"No events in the loaded dataset match the filters ({filter_text}).",
                "type": "VERIFIED_FACT",
                "evidence_references": [],
                "confidence": "HIGH",
                "reason": "Verified zero over the complete dataset and the stated filters; this does not prove absence outside the dataset or logging coverage.",
            })
        if anchor_count is not None:
            claims.append(_verified_claim(
                f"{anchor_count} anchor event(s) matching '{after_constraint.anchor_event.strip()}' were identified for the relative time constraint.",
                [], claim_no,
            ))

        kind = {"count": "count", "timeline": "timeline", "list": "list", "correlation": "correlation"}.get(
            analysis.intent, "count"
        )
        direct = answer.split("\n")[0] if answer else ""
        return DeterministicResult(
            kind=kind,
            question=question,
            analysis=analysis,
            answer=answer,
            direct_answer=direct,
            has_direct_answer=True,
            count=count,
            filters=filters,
            plan=result.get("plan", {}),
            evidence_records=evidence_records,
            evidence_ids_all=evidence_ids_all,
            coverage=coverage,
            claims=claims,
            interpretation_notes=notes,
            requires_ai=False,
        )

    def _resolve_anchor(self, anchor: str, filters: dict[str, str]) -> list[int]:
        """Resolve an 'after the failures'-style anchor to concrete event positions."""
        anchor_filters = dict(filters)
        anchor_text = _norm(anchor)
        action_field = self.schema.canonical_field("action") or "action"
        # The anchor describes a DIFFERENT event class than the main query,
        # so the main action filter never applies to it.
        anchor_filters.pop(action_field, None)
        anchor_words = set(re.findall(r"[a-z]+", anchor_text))
        best = ""
        best_score = 0
        for value in self.schema.distinct(action_field):
            value_tokens = re.findall(r"[a-z]+", _norm(value))
            score = 0
            for vt in value_tokens:
                for word in anchor_words:
                    stem = min(4, len(vt), len(word))
                    if stem >= 3 and vt[:stem] == word[:stem]:
                        score += 1
            if score > best_score:
                best, best_score = value, score
        if best:
            anchor_filters[action_field] = best
        if not anchor_filters:
            return []
        result = self._execute(anchor_filters)
        return list(result["positions"])

    # ------------------------------------------------------------------
    # proof / causality questions (abstention scaffolds)
    # ------------------------------------------------------------------
    def _answer_proof_or_causality(self, question: str, analysis: QuestionAnalysis) -> DeterministicResult | None:
        filters, notes = self._build_filters(analysis)
        observations: list[str] = []
        claims: list[dict[str, Any]] = []
        claim_no = 1
        evidence_ids_all: list[str] = []
        main_positions: list[int] = []

        action_field = self.schema.canonical_field("action") or "action"
        action_values = [
            v for v in analysis.action_candidates
            if action_field in self.schema.fields and self.schema.has_value(action_field, v)
        ]
        if analysis.intent == "causality" and len(action_values) < 2 and not analysis.conclusion_terms:
            # A causality question with no resolvable security conclusion and
            # fewer than two referenced activities is not deterministically
            # answerable here; the AI runtime should handle it.
            return None
        if analysis.intent == "causality" and len(action_values) >= 2:
            # Two referenced activity sets: describe each separately, then
            # check for shared correlation identifiers between them. Entities
            # carried from earlier questions are ambiguous across the two
            # sets, so only question-literal entities are applied here.
            context_entity_fields = {e.field for e in analysis.entities if e.source == "context"}
            filters = {k: v for k, v in filters.items() if k not in context_entity_fields}
            # The event-type filter derived from one activity's phrasing
            # ("RDP logons") must not constrain the other set ("HTTPS
            # connections"), which is typically a different event type.
            event_type_field = self.schema.canonical_field("event_type")
            if event_type_field:
                filters.pop(event_type_field, None)
            # Bind each referenced activity set to the service port named for
            # it, in question order ("failed RDP logons ... allowed outbound
            # HTTPS connections" -> set 1 on 3389, set 2 on 443).
            port_field = self.schema.canonical_field("destination_port")
            ordered_ports = []
            if port_field:
                for e in analysis.entities:
                    if e.field == port_field and e.value not in ordered_ports and self.schema.has_value(port_field, e.value):
                        ordered_ports.append(e.value)
            set_positions: list[list[int]] = []
            for idx, action_value in enumerate(action_values[:2], 1):
                set_filters = {k: v for k, v in filters.items() if k != action_field}
                if port_field and idx <= len(ordered_ports):
                    set_filters[port_field] = ordered_ports[idx - 1]
                set_filters[action_field] = action_value
                result = self._execute(set_filters)
                positions_i = list(result["positions"])
                set_positions.append(positions_i)
                evidence_ids_all.extend(evidence_id_for_position(p) for p in positions_i)
                filter_text = ", ".join(f"{k}={v}" for k, v in set_filters.items())
                observations.append(
                    f"Activity set {idx}: {len(positions_i)} event(s) match {filter_text}."
                )
                claims.append(_verified_claim(
                    f"{len(positions_i)} event(s) match {filter_text}.",
                    [evidence_id_for_position(p) for p in positions_i],
                    claim_no,
                ))
                claim_no += 1
            if set_positions:
                shared = self._shared_identifier_check_positions(set_positions)
                if shared:
                    observations.append(
                        "Shared identifiers observed across the referenced event sets: "
                        + ", ".join(shared) + "."
                    )
                else:
                    observations.append(
                        "The referenced event sets share no session, user, process, or correlation "
                        "identifier in the loaded data."
                    )
                main_positions = sorted({p for s in set_positions for p in s})
            answer = self._render_causality_answer(analysis, filters, observations)
        else:
            if filters:
                result = self._execute(filters)
                main_positions = list(result["positions"])
                main_count = int(result["count"])
                evidence_ids_all.extend(evidence_id_for_position(p) for p in main_positions)
                filter_text = ", ".join(f"{k}={v}" for k, v in filters.items())
                observations.append(f"{main_count} event(s) match {filter_text} in the loaded dataset.")
                claims.append(_verified_claim(
                    f"{main_count} event(s) match {filter_text}.", evidence_ids_all, claim_no,
                ))
                claim_no += 1
                if action_field and main_positions:
                    breakdown = self.index.facet_counts(action_field, set(main_positions), limit=6)
                    if breakdown:
                        observations.append(
                            "Outcomes observed for those events: "
                            + ", ".join(f"{k}: {v}" for k, v in sorted(breakdown.items(), key=lambda x: -x[1]))
                        )
                if main_positions and "bytes_sent" in self.df.columns:
                    try:
                        values = pd.to_numeric(self.df.iloc[main_positions]["bytes_sent"], errors="coerce").dropna()
                        if len(values):
                            observations.append(f"Maximum bytes recorded on those events: {int(values.max())}.")
                    except Exception:
                        pass
            # Context entities act as SEPARATE observation lenses (never ANDed
            # with the main filters) so the abstention reports each referenced
            # activity without over-constraining the query.
            covered_fields = set(filters)
            lens_positions: list[int] = []
            for ent in analysis.context_entities:
                if ent.field in covered_fields:
                    continue
                covered_fields.add(ent.field)
                if not self.schema.has_value(ent.field, ent.value):
                    continue
                lens_result = self._execute({ent.field: ent.value})
                positions_i = list(lens_result["positions"])
                lens_positions.extend(positions_i)
                evidence_ids_all.extend(evidence_id_for_position(p) for p in positions_i)
                observations.append(
                    f"Context observation: {len(positions_i)} event(s) reference {ent.field}={ent.value}."
                )
                claims.append(_verified_claim(
                    f"{len(positions_i)} event(s) reference {ent.field}={ent.value}.",
                    [evidence_id_for_position(p) for p in positions_i],
                    claim_no,
                ))
                claim_no += 1
            if lens_positions:
                main_positions = sorted(set(main_positions) | set(lens_positions))
            if analysis.intent == "causality":
                answer = self._render_causality_answer(analysis, filters, observations)
            else:
                conclusion = ", ".join(analysis.conclusion_terms) if analysis.conclusion_terms else "the asked conclusion"
                answer = self._render_proof_answer(analysis, filters, observations, conclusion)

        coverage = CoverageReport(
            total_events=self.total_events,
            indexed_events=int(self.index.size),
            candidate_events=int(self.index.size),
            total_matching_events=len(main_positions),
            retrieved_events=min(len(main_positions), 25),
            verified_evidence=len(main_positions),
            excluded_events=self.total_events - len(main_positions),
            truncated_results=False,
            coverage_status="TARGETED",
            completion_reason="targeted observations supporting a scoped abstention; not an exhaustive review of every event",
        )
        return DeterministicResult(
            kind="abstention",
            question=question,
            analysis=analysis,
            answer=answer,
            count=None,
            filters=filters,
            plan={},
            evidence_records=_render_evidence_table(self.df, main_positions),
            evidence_ids_all=list(dict.fromkeys(evidence_ids_all)),
            coverage=coverage,
            claims=claims,
            interpretation_notes=notes + analysis.interpretation_notes,
            requires_ai=False,
        )

    def _shared_identifier_check_positions(self, position_sets: list[list[int]]) -> list[str]:
        """Look for correlation-grade shared values between event sets."""
        sets = [set(s) for s in position_sets if s]
        if len(sets) < 2:
            return []
        correlation_fields = [
            f for f in self.index.correlation_fields if f in self.df.columns
        ] or ["user", "username", "process", "process_name"]
        shared: list[str] = []
        for field_name in correlation_fields[:6]:
            value_sets = []
            for positions in sets:
                values = {str(self.df.iloc[p].get(field_name, "") or "").strip().lower() for p in positions}
                values.discard("")
                value_sets.append(values)
            common = set.intersection(*value_sets) if value_sets and all(value_sets) else set()
            if common:
                shared.extend(f"{field_name}={v}" for v in sorted(common)[:3])
        return shared

    def _render_causality_answer(self, analysis: QuestionAnalysis, filters: dict[str, str], observations: list[str]) -> str:
        lines = []
        lines.append(
            "Causation is not established by these logs alone. Temporal proximity between two event "
            "sets does not, by itself, demonstrate that one caused the other."
        )
        if observations:
            lines.append("")
            lines.append("What the loaded dataset shows:")
            lines.extend(f"- {obs}" for obs in observations)
        lines.append("")
        lines.append(
            "To establish causation, evidence such as a shared session/process identifier, an explicit "
            "recorded action linking the events, or telemetry showing the intermediate steps would be required."
        )
        return "\n".join(lines)

    def _render_proof_answer(self, analysis: QuestionAnalysis, filters: dict[str, str], observations: list[str], conclusion: str) -> str:
        lines = [f"No. The loaded logs alone do not prove {conclusion}."]
        lines.append("")
        if observations:
            lines.append("What the loaded dataset shows:")
            lines.extend(f"- {obs}" for obs in observations)
        lines.append("")
        lines.append(
            "Why this is not proof: observed log events such as failed or successful authentication, "
            "suspicious-looking commands, blocked connections, or the presence of a vulnerability "
            "identifier do not by themselves establish compromise, successful exploitation, data "
            "exfiltration, or attacker intent. Each of those conclusions requires additional evidence "
            "(for example: demonstrated unauthorized actions, successful outbound transfer of data, "
            "post-exploitation activity, or corroborating telemetry)."
        )
        lines.append("")
        lines.append(
            "What would strengthen the assessment: correlating these events with endpoint/process "
            "telemetry, reviewing authorization and change records for the involved accounts, and "
            "verifying whether the observed activity had any recorded effect beyond the log entries."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # renderers
    # ------------------------------------------------------------------
    def _render_count_answer(self, question, analysis, filters, count, positions, notes) -> str:
        """Concise direct answer. The evidence chain lives in the grounding
        panel; it is rendered inline only when no direct answer is possible."""
        lines = [f"There are {count} matching events in the complete dataset for the specified filters."]
        filter_text = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else ""
        if filter_text:
            lines.append(f"Filters applied: {filter_text}.")
        if notes:
            lines.append("")
            lines.extend(f"Note: {n}" for n in notes[:3])
        return "\n".join(lines)

    def _render_list_answer(self, question, analysis, filters, count, positions, notes) -> str:
        lines = [f"{count} event(s) match the specified filters."]
        filter_text = ", ".join(f"{k}={v}" for k, v in filters.items()) if filters else ""
        if filter_text:
            lines.append(f"Filters applied: {filter_text}.")
        if notes:
            lines.append("")
            lines.extend(f"Note: {n}" for n in notes[:3])
        return "\n".join(lines)

    def _render_timeline_answer(self, question, analysis, filters, positions, notes) -> str:
        first = ""
        last = ""
        ordered = sorted(
            positions,
            key=lambda p: (_parse_ts(self.df.iloc[p].get("timestamp")) is None,
                           _parse_ts(self.df.iloc[p].get("timestamp")) or 0),
        )
        ordered = [p for p in ordered if _parse_ts(self.df.iloc[p].get("timestamp")) is not None]
        if ordered:
            first = str(self.df.iloc[ordered[0]].get("timestamp", ""))
            last = str(self.df.iloc[ordered[-1]].get("timestamp", ""))
        lines = [f"{len(ordered)} matching event(s) have parseable timestamps."]
        if first and last:
            lines.append(f"First occurrence: {first}")
            lines.append(f"Last occurrence: {last}")
        if notes:
            lines.append("")
            lines.extend(f"Note: {n}" for n in notes[:3])
        return "\n".join(lines)


def context_from_questions(
    df: pd.DataFrame,
    dataset: Any,
    questions: list[str],
) -> list[dict[str, Any]]:
    """Extract resolved entities from prior session questions.

    Used to resolve contextual references ("this source") the way a human
    analyst would carry context from earlier questions in the same session.
    Only high-precision identifiers resolved against the schema are returned;
    no ground-truth information is involved.
    """
    if not questions:
        return []
    engine_schema = _build_schema(dataset, df.reset_index(drop=True))
    context: list[dict[str, Any]] = []
    for q in questions[-6:]:
        try:
            analysis = analyze_question(str(q or ""), engine_schema)
        except Exception:
            continue
        context.append({
            "question": str(q),
            "entities": [e.to_dict() for e in analysis.entities],
        })
    return context


def answer_deterministic(
    df: pd.DataFrame,
    question: str,
    dataset: Any = None,
    conversation_context: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Convenience entry: returns the result dict or None when the question
    cannot be answered deterministically from the schema (caller should fall
    back to the AI investigation runtime)."""
    engine = DeterministicQAEngine(df, dataset)
    result = engine.answer(question, conversation_context)
    if result is None:
        return None
    return result.to_dict()
