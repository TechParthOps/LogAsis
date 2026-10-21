from __future__ import annotations

"""Provider-independent, bounded AI security investigation runtime.

The runtime owns the investigation loop. AI providers only supply planning and
analytical language. Evidence collection, correlation, identifiers, limits and
claim verification remain deterministic and auditable.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

import pandas as pd

from ai.context import _row_text
from ai.context import build_evidence_context
from ai.claim_grounding import normalize_provider_analysis


DEFAULT_MAX_STEPS = 3
DEFAULT_MAX_TOOL_CALLS = 6
DEFAULT_MAX_EVIDENCE = 48
DEFAULT_TOOL_RESULT = 12
# Planner responses are tiny JSON actions; a bounded completion budget keeps
# each planning round-trip fast instead of reserving a full 4k output.
PLANNER_MAX_TOKENS = 350

# Coverage statuses (semantics):
#   COMPLETED_SUFFICIENT  - the agent finished and the collected evidence was
#                           sufficient for the objective (or the objective was
#                           answered deterministically).
#   COMPLETED_INSUFFICIENT - the agent finished but evidence was incomplete;
#                           the answer must disclose the gaps.
#   PARTIAL               - stopped at the step/tool budget; findings cover
#                           only part of the objective.
#   FAILED                - provider/parser/query/runtime error prevented the
#                           investigation.
COMPLETED_SUFFICIENT = "COMPLETED_SUFFICIENT"
COMPLETED_INSUFFICIENT = "COMPLETED_INSUFFICIENT"
PARTIAL = "PARTIAL"
FAILED = "FAILED"

logger = logging.getLogger(__name__)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _canonical_evidence_id(value: Any) -> str:
    text = str(value or "").strip().upper()
    match = re.fullmatch(r"EVID-(\d{1,6})", text)
    if not match:
        return text
    return f"EVID-{int(match.group(1)):03d}"


def _truncate(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + f"... [truncated {len(text) - limit} chars]"


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _tokens(text: str) -> list[str]:
    """Generic lexical tokenization for evidence search.

    This deliberately contains no cybersecurity vocabulary or question intents.
    The AI decides what concepts/field names/values to search for.
    """
    return [x.lower() for x in re.findall(r"[A-Za-z0-9_.:/@\-]{2,}", str(text or ""))]


@dataclass
class InvestigationState:
    investigation_id: str
    objective: str
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_evidence: int = DEFAULT_MAX_EVIDENCE
    entities: dict[str, set[str]] = field(default_factory=lambda: {
        "ip": set(), "user": set(), "host": set(), "process": set(),
        "command": set(), "file": set(), "service": set(),
    })
    evidence_ids: list[str] = field(default_factory=list)
    evidence_records: dict[str, dict[str, Any]] = field(default_factory=dict)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: int = 0
    steps: int = 0
    termination_reason: str = ""
    confidence: str = "LOW"
    # Coverage accounting (semantics documented in docs/AI_INVESTIGATION.md).
    coverage: dict[str, Any] = field(default_factory=lambda: {
        "total_events": 0,
        "indexed_events": 0,
        "candidate_events": 0,
        "total_matching_events": 0,
        "retrieved_events": 0,
        "correlated_events": 0,
        "verified_evidence": 0,
        "excluded_events": 0,
        "failed_batches": 0,
        "truncated_results": False,
        "coverage_status": "UNKNOWN",
        "completion_reason": "",
    })
    completion_status: str = PARTIAL
    # Deterministic count observations gathered via the count_events tool.
    # These are authoritative query results, never model estimates, and are
    # reused by claim grounding to verify set-level counts.
    deterministic_counts: list[dict[str, Any]] = field(default_factory=list)
    # Per-question retrieval trace. This is intentionally stored on the
    # investigation state, never in a process/global conversation object.
    retrieval_trace: dict[str, Any] = field(default_factory=dict)

    def add_records(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            evid = str(record.get("evidence_id", "")).upper()
            if not evid:
                continue
            self.evidence_records[evid] = dict(record)
            if evid not in self.evidence_ids:
                self.evidence_ids.append(evid)
        if len(self.evidence_ids) > self.max_evidence:
            self.evidence_ids = self.evidence_ids[-self.max_evidence:]
            keep = set(self.evidence_ids)
            self.evidence_records = {k: v for k, v in self.evidence_records.items() if k in keep}
        self._extract_entities(records)

    def _extract_entities(self, records: list[dict[str, Any]]) -> None:
        for r in records:
            for kind, key in (
                ("ip", "source_ip"), ("ip", "destination_ip"),
                ("user", "username"), ("process", "process_name"),
            ):
                value = str(r.get(key, "") or "").strip()
                if value:
                    self.entities[kind].add(value)
            for key, kind in (("command", "command"),):
                value = str(r.get(key, "") or "").strip()
                if value:
                    self.entities[kind].add(_truncate(value, 160))

    def compact_context(self, limit: int = 12, text_limit: int = 650) -> dict[str, Any]:
        records = [
            self.evidence_records[e]
            for e in self.evidence_ids
            if e in self.evidence_records
        ]
        records = records[-limit:]
        return {
            "objective": self.objective,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "entities": {k: sorted(v)[:20] for k, v in self.entities.items() if v},
            "evidence": [
                {
                    "evidence_id": r["evidence_id"],
                    "text": _truncate(r.get("text", ""), text_limit),
                }
                for r in records
            ],
            "hypotheses": self.hypotheses[-8:],
            "relationships": self.relationships[-12:],
            "timeline": self.timeline[-12:],
            "observations": self.observations[-12:],
            "unresolved_questions": self.unresolved_questions[-8:],
            "actions_taken": self.actions_taken[-10:],
            "deterministic_counts": self.deterministic_counts[-6:],
            "retrieval_trace": dict(self.retrieval_trace),
        }

    def planner_context(self, limit: int = 8) -> dict[str, Any]:
        """Compact context for the planning round-trips.

        Kept small on purpose: planning happens once per step and a large
        serialized state dominates the request latency without improving the
        action choice. The final synthesis still receives the full evidence.
        """
        records = [
            self.evidence_records[e]
            for e in self.evidence_ids
            if e in self.evidence_records
        ]
        records = records[-limit:]
        context: dict[str, Any] = {
            "objective": self.objective,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "entities": {k: sorted(v)[:12] for k, v in self.entities.items() if v},
            "evidence": [
                {"evidence_id": r["evidence_id"], "text": _truncate(r.get("text", ""), 220)}
                for r in records
            ],
            "observations": self.observations[-8:],
            "deterministic_counts": self.deterministic_counts[-4:],
            "unresolved_questions": self.unresolved_questions[-4:],
        }
        if self.hypotheses:
            context["hypotheses"] = self.hypotheses[-4:]
        if self.relationships:
            context["relationships"] = self.relationships[-8:]
        return context

    def to_report_data(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "objective": self.objective,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "termination_reason": self.termination_reason or "completed",
            "completion_status": self.completion_status,
            "confidence": self.confidence,
            "coverage": dict(self.coverage),
            "deterministic_counts": list(self.deterministic_counts),
            "entities": {k: sorted(v) for k, v in self.entities.items() if v},
            "evidence_ids": list(self.evidence_ids),
            "evidence_records": [
                self.evidence_records[e]
                for e in self.evidence_ids
                if e in self.evidence_records
            ],
            "timeline": sorted(self.timeline, key=lambda x: (str(x.get("timestamp", "")), str(x.get("evidence_id", ""))))[:40],
            "relationships": self.relationships[:40],
            "hypotheses": self.hypotheses[:20],
            "actions_taken": self.actions_taken[:20],
            "unresolved_questions": self.unresolved_questions[:12],
            "retrieval_trace": dict(self.retrieval_trace),
        }


def build_tool_catalog(df: pd.DataFrame) -> dict[str, dict[str, Any]]:
    """Build the stable evidence-ID catalog for a parsed log.

    Pure function of the DataFrame: one build per uploaded log can be shared
    across every question (see ``LogDataset.get_tool_catalog``).
    """
    catalog: dict[str, dict[str, Any]] = {}
    internal = {"timestamp_dt", "hour", "date", "raw_log"}
    empty = {"", "nan", "nat", "none"}
    for idx, row in enumerate(df.to_dict("records")):
        evid = f"EVID-{idx + 1:03d}"
        text = _row_text(row)
        source_fields = {}
        for key, raw_value in row.items():
            if str(key) in internal:
                continue
            if raw_value is None:
                continue
            value_text = str(raw_value).strip()
            if value_text and value_text.lower() not in empty:
                source_fields[str(key)] = _truncate(value_text, 700)
        record = {
            "evidence_id": evid,
            "source_position": int(idx),
            "text": text,
            "line": str(row.get("line", "")),
            "source_fields": source_fields,
            "timestamp": str(row.get("timestamp", "")),
            "event_type": str(row.get("event_type", "")),
            "action": str(row.get("action", "")),
            "severity": str(row.get("severity", "")),
            "source_ip": str(row.get("source_ip", "")),
            "destination_ip": str(row.get("destination_ip", "")),
            "username": str(row.get("username", "")),
            "process_name": str(row.get("process_name", "")),
            "command": _truncate(row.get("command", ""), 350),
            "pid": str(row.get("pid", "")),
            "ppid": str(row.get("ppid", "")),
            "uid": str(row.get("uid", "")),
            "euid": str(row.get("euid", "")),
        }
        # Expose source-specific fields directly on the tool record as well
        # as inside source_fields. This keeps the read-only investigation API
        # dynamically compatible with arbitrary parser fields such as
        # destination_port, TargetFilename, Hashes, EventData_* and vendor
        # extensions without per-format configuration. Core keys win on
        # collision to preserve the stable investigation contract.
        for key, value in source_fields.items():
            record.setdefault(str(key), value)
        catalog[evid] = record
    return catalog


class InvestigationToolLayer:
    """Read-only deterministic investigation tools over the current LogAsis dataframe."""

    def __init__(
        self,
        df: pd.DataFrame,
        max_result: int = DEFAULT_TOOL_RESULT,
        event_index: Any = None,
        catalog: dict[str, dict[str, Any]] | None = None,
    ):
        self.df = df.copy().reset_index(drop=True)
        self.max_result = max(1, int(max_result))
        self._index = (
            event_index
            if event_index is not None and getattr(event_index, "size", -1) == len(self.df)
            else None
        )
        self._catalog = catalog if catalog is not None else build_tool_catalog(self.df)

    @property
    def evidence_records(self) -> dict[str, dict[str, Any]]:
        return self._catalog

    def _records(self, ids: list[str]) -> list[dict[str, Any]]:
        return [dict(self._catalog[x]) for x in ids if x in self._catalog]

    def overview(self, **_: Any) -> dict[str, Any]:
        if self.df.empty:
            return {"tool": "overview", "event_count": 0, "message": "No parsed evidence is available."}
        severity = self.df.get("severity", pd.Series("", index=self.df.index)).fillna("").astype(str).str.upper()
        event_types = self.df.get("event_type", pd.Series("", index=self.df.index)).fillna("").astype(str)
        actions = self.df.get("action", pd.Series("", index=self.df.index)).fillna("").astype(str)
        users = sorted({str(x).strip() for x in self.df.get("username", pd.Series("", index=self.df.index)).fillna("").astype(str) if str(x).strip()})
        ips = sorted({str(x).strip() for x in self.df.get("source_ip", pd.Series("", index=self.df.index)).fillna("").astype(str) if str(x).strip()})
        return {
            "tool": "overview",
            "event_count": int(len(self.df)),
            "high_critical": int(severity.isin(["HIGH", "CRITICAL"]).sum()),
            "event_types": event_types.value_counts().head(12).to_dict(),
            "actions": actions.value_counts().head(12).to_dict(),
            "users": users[:20],
            "source_ips": ips[:20],
            "first_observed": str(self.df.iloc[0].get("timestamp", "")) if len(self.df) else "",
            "last_observed": str(self.df.iloc[-1].get("timestamp", "")) if len(self.df) else "",
        }

    def search_events(self, query: str = "", limit: int | None = None, **filters: Any) -> dict[str, Any]:
        """Search arbitrary source fields using generic lexical matching.

        This function is an evidence access primitive, not a forensic answerer.
        It has no knowledge of attack types, PowerShell commands, CVEs, login
        semantics, exfiltration, or predefined user questions.

        When the dataset index is available, candidate rows are resolved from
        the index (cost follows matched postings, not dataset size) and only
        those candidates are scored. Scoring rules are unchanged.
        """
        limit = max(1, min(int(limit or self.max_result), self.max_result))
        query_text = str(query or "").strip().lower()
        qtokens = set(_tokens(query_text))
        rows = []
        candidates: dict[str, Any] | None = None
        if self._index is not None and qtokens:
            positions: set[int] = set()
            for token in qtokens:
                positions.update(self._index.match_postings(token))
                positions.update(self._index.field_name_postings(token))
            candidates = {
                f"EVID-{pos + 1:03d}": self._catalog[f"EVID-{pos + 1:03d}"]
                for pos in sorted(positions)
                if f"EVID-{pos + 1:03d}" in self._catalog
            }
        source = candidates if candidates is not None else self._catalog
        for evid, record in source.items():
            # Search every parsed source field, including vendor/custom fields.
            values = [str(record.get("text", ""))]
            source_fields = record.get("source_fields") or {}
            values.extend(str(v) for v in source_fields.values())
            haystack = " ".join(values).lower()
            doc_tokens = set(_tokens(haystack))
            score = 0.0
            if not query_text:
                score = 1.0
            else:
                score += float(len(qtokens & doc_tokens))
                if query_text in haystack:
                    score += 5.0
                # Exact field/value matches are useful retrieval signals but are
                # not interpreted as security findings.
                for token in qtokens:
                    if token and token in haystack:
                        score += 0.25

            matched = True
            # Filters remain generic structured-field equality constraints.
            for key, wanted_value in filters.items():
                if key in {"limit", "query"} or wanted_value in (None, ""):
                    continue
                key_text = str(key)
                wanted = str(wanted_value).strip().lower()
                actual = record.get(key_text, source_fields.get(key_text, ""))
                if wanted and wanted != str(actual or "").strip().lower():
                    matched = False
                    break
            if matched and score > 0:
                rows.append((score, str(record.get("timestamp", "")), evid, record))

        rows.sort(key=lambda x: (-x[0], x[1], x[2]))
        selected = [x[3] for x in rows[:limit]]
        return {
            "tool": "search_events",
            "query": query_text,
            "result_count": len(selected),
            # Surface truncation so the planner knows when the limit hid
            # additional matches instead of treating results as complete.
            "total_matches": len(rows),
            "records": selected,
        }

    def count_events(self, query: str = "", **filters: Any) -> dict[str, Any]:
        """Deterministic exact count over the complete dataset.

        Unlike search_events, this tool NEVER samples: the reported count is
        computed over every matching row of the loaded dataset, so the model
        never has to estimate totals from a bounded result page. Lexical query
        terms and structured field filters are combined with AND semantics;
        an empty, unconstrained call returns the dataset size.
        """
        limit = self.max_result
        query_text = str(query or "").strip().lower()
        qtokens = set(_tokens(query_text))
        rows = []
        candidates: dict[str, Any] | None = None
        if self._index is not None and qtokens:
            positions: set[int] = set()
            for token in qtokens:
                positions.update(self._index.match_postings(token))
                positions.update(self._index.field_name_postings(token))
            candidates = {
                f"EVID-{pos + 1:03d}": self._catalog[f"EVID-{pos + 1:03d}"]
                for pos in sorted(positions)
                if f"EVID-{pos + 1:03d}" in self._catalog
            }
        source = candidates if candidates is not None else self._catalog
        for evid, record in source.items():
            values = [str(record.get("text", ""))]
            source_fields = record.get("source_fields") or {}
            values.extend(str(v) for v in source_fields.values())
            haystack = " ".join(values).lower()
            doc_tokens = set(_tokens(haystack))
            matched = True
            if query_text:
                if not (qtokens & doc_tokens or query_text in haystack):
                    matched = False
            if matched:
                for key, wanted_value in filters.items():
                    if key in {"limit", "query"} or wanted_value in (None, ""):
                        continue
                    key_text = str(key)
                    wanted = str(wanted_value).strip().lower()
                    actual = record.get(key_text, source_fields.get(key_text, ""))
                    if wanted and wanted != str(actual or "").strip().lower():
                        matched = False
                        break
            if matched:
                rows.append(evid)
        total = len(rows)
        sample_ids = rows[:limit]
        return {
            "tool": "count_events",
            "query": query_text,
            "exact_count": total,
            "exhaustive": True,
            "dataset_size": len(self._catalog),
            "sample_evidence_ids": sample_ids,
            "sample_truncated": total > len(sample_ids),
        }

    def get_timeline(self, evidence_ids: list[str] | None = None, entity_type: str = "", entity_value: str = "", **_: Any) -> dict[str, Any]:
        records = self._records([_canonical_evidence_id(x) for x in (evidence_ids or [])])
        if not records and entity_value:
            value = _norm(entity_value)
            key_map = {"ip": "source_ip", "user": "username", "process": "process_name", "host": "host"}
            key = key_map.get(_norm(entity_type), "")
            if key:
                if self._index is not None:
                    positions = self._index.exact(key, value)
                    records = [
                        self._catalog[evid]
                        for pos in positions
                        if (evid := f"EVID-{pos + 1:03d}") in self._catalog
                    ]
                else:
                    records = [r for r in self._catalog.values() if _norm(r.get(key)) == value]
            else:
                if self._index is not None:
                    positions = set(self._index.match_postings(value))
                    positions.update(self._index.field_name_postings(value))
                    records = [
                        self._catalog[evid]
                        for pos in sorted(positions)
                        if (evid := f"EVID-{pos + 1:03d}") in self._catalog
                    ]
                else:
                    records = [r for r in self._catalog.values() if value in _norm(r.get("text"))]
        if not records:
            records = list(self._catalog.values())
        records = sorted(records, key=lambda r: (str(r.get("timestamp", "")), str(r.get("evidence_id", ""))))[:40]
        return {"tool": "get_timeline", "result_count": len(records), "records": records}

    def correlate(self, evidence_ids: list[str] | None = None, window_seconds: int = 300, **_: Any) -> dict[str, Any]:
        wanted = [_canonical_evidence_id(x) for x in (evidence_ids or []) if _canonical_evidence_id(x) in self._catalog]
        if not wanted:
            return {"tool": "correlate", "relationships": [], "records": []}
        relationships = []
        related_ids: set[str] = set()
        for evid in wanted:
            target = self._catalog[evid]
            tt = _parse_time(target.get("timestamp"))
            for cid, candidate in self._catalog.items():
                if cid == evid:
                    continue
                reasons = []
                for field, label in (
                    ("source_ip", "same source IP"),
                    ("destination_ip", "same destination IP"),
                    ("username", "same user"),
                    ("process_name", "same process"),
                ):
                    a, b = _norm(target.get(field)), _norm(candidate.get(field))
                    if a and b and a == b:
                        reasons.append(label)
                ct = _parse_time(candidate.get("timestamp"))
                if tt and ct:
                    try:
                        if abs((ct - tt).total_seconds()) <= int(window_seconds):
                            reasons.append(f"within {int(window_seconds)}s")
                    except TypeError:
                        pass
                if reasons:
                    related_ids.add(cid)
                    relationships.append({
                        "evidence_a": evid,
                        "evidence_b": cid,
                        "reasons": reasons,
                        "score": len(reasons),
                    })
        relationships.sort(key=lambda x: (-int(x["score"]), x["evidence_a"], x["evidence_b"]))
        records = self._records(sorted(related_ids))
        return {
            "tool": "correlate",
            "relationship_count": len(relationships),
            "relationships": relationships[:50],
            "records": records[:self.max_result],
        }

    def entity_context(
        self,
        entity_type: str = "",
        entity_value: str = "",
        field_name: str = "",
        limit: int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        """Return all records matching a value in a selected field.

        Common entity aliases are supported for convenience, but the AI can
        explicitly provide any parsed source field name.
        """
        value = _norm(entity_value)
        aliases = {
            "ip": "source_ip",
            "source_ip": "source_ip",
            "user": "username",
            "username": "username",
            "process": "process_name",
        }
        key = str(field_name or "").strip() or aliases.get(_norm(entity_type), "")
        if not key or not value:
            return {"tool": "entity_context", "result_count": 0, "records": []}
        records = []
        if self._index is not None:
            positions = self._index.exact(key, value)
            records = [
                self._catalog[evid]
                for pos in positions
                if (evid := f"EVID-{pos + 1:03d}") in self._catalog
            ]
        else:
            for record in self._catalog.values():
                source_fields = record.get("source_fields") or {}
                actual = record.get(key, source_fields.get(key, ""))
                if _norm(actual) == value:
                    records.append(record)
        records = sorted(records, key=lambda r: (str(r.get("timestamp", "")), r["evidence_id"]))
        limit = max(1, min(int(limit or self.max_result), self.max_result))
        return {
            "tool": "entity_context",
            "entity_type": entity_type,
            "entity_value": entity_value,
            "field_name": key,
            "result_count": min(len(records), limit),
            "total_matches": len(records),
            "records": records[:limit],
        }

    def run(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        arguments = arguments or {}
        safe = {
            "overview": self.overview,
            "search_events": self.search_events,
            "count_events": self.count_events,
            "get_timeline": self.get_timeline,
            "correlate": self.correlate,
            "entity_context": self.entity_context,
        }
        func = safe.get(str(tool or "").strip())
        if not func:
            raise ValueError(f"Unsupported investigation tool: {tool}")
        return func(**arguments)


class AgenticInvestigationRuntime:
    def __init__(
        self,
        provider: Any,
        progress_callback: Callable[[int, str], None] | None = None,
        *,
        max_steps: int = DEFAULT_MAX_STEPS,
        max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
        max_evidence: int = DEFAULT_MAX_EVIDENCE,
    ):
        self.provider = provider
        self.progress_callback = progress_callback or (lambda *_: None)
        self.max_steps = max(1, int(max_steps))
        self.max_tool_calls = max(1, int(max_tool_calls))
        self.max_evidence = max(4, int(max_evidence))

    def _progress(self, pct: int, message: str) -> None:
        try:
            self.progress_callback(int(pct), str(message))
        except Exception:
            pass

    def _generate(self, system: str, user: str, *, max_tokens: int | None = None) -> str:
        generator = getattr(self.provider, "generate_with_progress", None)
        if callable(generator):
            try:
                return str(generator(system, user, progress_callback=self._progress, max_tokens=max_tokens) or "")
            except TypeError:
                # Providers whose generate_with_progress predates max_tokens.
                return str(generator(system, user, progress_callback=self._progress) or "")
        try:
            return str(self.provider.generate(system, user, max_tokens=max_tokens) or "")
        except TypeError:
            return str(self.provider.generate(system, user) or "")

    def _generate_final(self, system: str, user: str, source_file: str | None = None) -> str:
        # Providers that support native file analysis (for example Gemini File
        # API through Live AI) receive the original uploaded artifact as well as
        # the deterministic investigation package. Other providers transparently
        # fall back to their normal text generation path.
        if source_file:
            generator = getattr(self.provider, "generate_large", None)
            if callable(generator):
                return str(generator(system, user, source_file) or "")
        return self._generate(system, user)

    @staticmethod
    def _json_object(text: str) -> dict[str, Any] | None:
        raw = str(text or "").strip()
        candidates = [raw]
        fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.I | re.S)
        candidates.extend(fenced)
        for candidate in candidates:
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return obj
            except (json.JSONDecodeError, TypeError):
                continue
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
                            if isinstance(obj, dict):
                                return obj
                        except (json.JSONDecodeError, TypeError):
                            break
            start = raw.find("{", start + 1)
        return None

    def _planner_prompt(self, state: InvestigationState) -> str:
        tools = {
            "search_events": "Search any parsed evidence fields using a natural-language query or exact field filters.",
            "count_events": "Exact deterministic count of events matching a query and/or field filters over the COMPLETE dataset (no sampling). Use this for any 'how many' question.",
            "get_timeline": "Build a chronological view for evidence IDs or a field/value entity.",
            "correlate": "Find generic entity and temporal relationships among selected evidence records.",
            "entity_context": "Return all records containing a selected value in a chosen field.",
            "overview": "Inspect generic dataset counts and available common metadata.",
            "finish": "Stop when the evidence collected is sufficient to answer the user's question. Never finish while your rationale still describes a search, filter, or lookup the tools could perform.",
        }
        return (
            "You are the planning component of LogAsis investigation planner.\n"
            "You are the intelligence component: decide what evidence is needed to answer the user's exact question.\n"
            "Do not assume a predefined question type or attack scenario. The log schema may contain arbitrary vendor fields.\n"
            "Choose ONE safe, read-only action. You may search repeatedly with different queries and correlate results.\n"
            "Before returning finish, run any search or field check your own rationale would recommend; "
            "only finish when further evidence collection would not change the answer.\n"
            "Do not provide hidden chain-of-thought; give only a short action rationale.\n"
            "Return JSON only: {\"action\":\"...\",\"arguments\":{},\"reason\":\"short rationale\",\"hypotheses\":[]}\n"
            f"Available actions: {json.dumps(tools)}\n"
            "Arguments may include query, evidence_ids, entity_type, entity_value, field_name, source_ip, username, "
            "process_name, event_type, action, severity, window_seconds, limit.\n\n"
            f"User objective: {state.objective}\n"
            f"Current investigation state: {json.dumps(state.planner_context(), ensure_ascii=False, default=str)}"
        )


    def _apply_result(self, state: InvestigationState, result: dict[str, Any]) -> None:
        records = result.get("records", []) or []
        state.add_records(records)
        if result.get("tool") == "count_events":
            # Deterministic count results are authoritative query output; keep
            # them verbatim for synthesis and claim verification.
            state.deterministic_counts.append({
                "query": result.get("query", ""),
                "exact_count": result.get("exact_count", 0),
                "dataset_size": result.get("dataset_size", 0),
                "sample_evidence_ids": result.get("sample_evidence_ids", [])[:12],
                "exhaustive": True,
            })
            state.observations.append(
                f"Deterministic count: {result.get('exact_count', 0)} matching event(s) "
                f"out of {result.get('dataset_size', 0)} in the dataset (exhaustive, no sampling)."
            )
        if result.get("relationships"):
            state.relationships.extend(result["relationships"][:50])
        if result.get("tool") == "get_timeline":
            state.timeline = sorted(
                state.timeline + records,
                key=lambda x: (str(x.get("timestamp", "")), str(x.get("evidence_id", ""))),
            )[-40:]
        if result.get("tool") == "overview":
            state.observations.append(
                f"Dataset contains {result.get('event_count', 0)} events; "
                f"{result.get('high_critical', 0)} are high/critical."
            )
        elif records:
            note = f"{result.get('tool', 'tool')} returned {len(records)} relevant evidence record(s)."
            total = result.get("total_matches")
            if total and int(total) > len(records):
                note += (
                    f" {total} records match in total; the tool result was truncated "
                    "at its limit. Refine the query or use field filters to cover the rest."
                )
            state.observations.append(note)

    def run(self, objective: str, df: pd.DataFrame, investigation_id: str = "", source_file: str | None = None, dataset: Any = None) -> tuple[str, dict[str, Any]]:
        if df is None or len(df) == 0:
            raise ValueError("No parsed log evidence is available for investigation.")
        objective = str(objective or "").strip()
        if not objective:
            raise ValueError("Enter an investigation question.")

        # Share the dataset's persistent index with evidence retrieval and the
        # read-only tools so a question never triggers a full DataFrame scan or
        # a second index build. Only use it when it covers the same rows.
        event_index = getattr(dataset, "event_index", None) if dataset is not None else None
        if event_index is not None and getattr(event_index, "size", -1) != len(df):
            event_index = None

        # The evidence-ID catalog is a pure function of the loaded log; reuse
        # the dataset's cached build instead of re-serializing every question.
        catalog = None
        if dataset is not None and event_index is not None:
            getter = getattr(dataset, "get_tool_catalog", None)
            if callable(getter):
                try:
                    shared = getter()
                    if isinstance(shared, dict) and len(shared) == len(df):
                        catalog = shared
                except Exception:
                    catalog = None

        tools = InvestigationToolLayer(df, event_index=event_index, catalog=catalog)
        state = InvestigationState(
            investigation_id=investigation_id or f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}-{uuid4().hex[:8]}",
            objective=objective,
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            max_evidence=self.max_evidence,
        )

        # Seed the investigation with generic RAG retrieval. This is evidence
        # access, not an answer engine: it knows nothing about attack types or
        # question-specific forensic facts. The AI can refine, replace, or
        # correlate this evidence through the read-only tools.
        scoped = build_evidence_context(
            df, objective, max_events=min(20, self.max_evidence), event_index=event_index
        )
        seed_records = list(scoped.get("evidence_records") or [])
        state.add_records(seed_records)
        state.retrieval_trace = {
            "method": "question-scoped-evidence-retrieval",
            "embedding_query": None,
            "keyword_query": objective,
            "top_k": 20,
            "seed_query": objective,
            "seed_evidence_ids": [r.get("evidence_id") for r in seed_records],
            "selected_evidence_ids": list(state.evidence_ids),
            "tool_calls": 0,
        }
        import logging
        logging.getLogger(__name__).info(
            "AI RETRIEVAL TRACE keyword_query=%s top_k=%s selected_evidence_ids=%s",
            objective, 20, list(state.evidence_ids),
        )
        self._progress(10, "RAG retrieved initial evidence; AI is refining the investigation…")

        # Deterministic head start: resolve the question's concrete entities
        # against the schema and record authoritative counts BEFORE any
        # planner round-trip. This frequently removes tool calls entirely and
        # guarantees the synthesis cites real dataset numbers.
        try:
            if tools._index is not None:
                from core.question_understanding import QuestionSchema, analyze_question

                schema = QuestionSchema(tools._index)
                analysis = analyze_question(objective, schema)
                head_filters: dict[str, str] = {}
                for ent in analysis.entities:
                    if ent.field in schema.fields and schema.has_value(ent.field, ent.value):
                        head_filters[ent.field] = ent.value
                    if len(head_filters) >= 4:
                        break
                if head_filters:
                    counted = tools.count_events(**head_filters)
                    state.deterministic_counts.append({
                        "query": ", ".join(f"{k}={v}" for k, v in head_filters.items()),
                        "exact_count": counted.get("exact_count", 0),
                        "dataset_size": counted.get("dataset_size", 0),
                        "sample_evidence_ids": counted.get("sample_evidence_ids", [])[:12],
                        "exhaustive": True,
                    })
                    state.observations.append(
                        f"Deterministic count: {counted.get('exact_count', 0)} matching event(s) for "
                        f"{', '.join(f'{k}={v}' for k, v in head_filters.items())} "
                        f"(exhaustive over {counted.get('dataset_size', 0)} events, no sampling)."
                    )
        except Exception:
            pass

        # Deterministic incident profile: when the log contains a coherent
        # intrusion sequence, seed the investigation with its evidence-backed
        # facts so the planner starts from real forensic context instead of
        # re-deriving (or hallucinating) them. Everything below is derived
        # deterministically from the loaded records; the AI may refine,
        # replace, or correlate it through the read-only tools.
        try:
            profile = None
            if dataset is not None:
                profile_getter = getattr(dataset, "get_incident_profile", None)
                if callable(profile_getter):
                    profile = profile_getter()
            if profile is None and tools._index is not None:
                from core.incident_profile import build_incident_profile
                from core.question_understanding import QuestionSchema as _ProfileSchema

                profile = build_incident_profile(
                    df, tools._index, _ProfileSchema(tools._index)
                )
            if profile is not None and getattr(profile, "has_incident", False):
                facts: list[str] = [
                    f"Compromised account '{profile.compromised_user}': "
                    f"{profile.failed_count} failed then {profile.success_count} successful "
                    f"login(s) from {profile.attacker_ip}.",
                ]
                evidence_positions: list[int] = list(profile.login_positions[:8])
                esc = profile.top_escalation
                if esc is not None and not esc.get("check"):
                    facts.append(
                        f"Privilege escalation execution: `{esc.get('command', '')}` "
                        f"(PID {esc.get('pid', '')})."
                    )
                    evidence_positions.append(int(esc.get("position", 0)))
                top_cve = profile.top_cve_match
                if top_cve:
                    facts.append(
                        f"Execution matches the {top_cve.get('cve', '')} signature "
                        f"({top_cve.get('description', '')}); signature mapping, not a log string."
                    )
                shell = profile.root_shell
                if shell is not None:
                    facts.append(
                        f"Root shell afterwards: `{shell.get('command', '')}` as uid=0 "
                        f"(PID {shell.get('pid', '')})."
                    )
                    evidence_positions.append(int(shell.get("position", 0)))
                for read in profile.root_sensitive_reads[:2]:
                    facts.append(
                        f"Sensitive read as root: `{read.get('command', '')}` "
                        f"(PID {read.get('pid', '')})."
                    )
                    evidence_positions.append(int(read.get("position", 0)))
                for tool_entry in profile.downloaded_tools[:1]:
                    facts.append(
                        f"Enumeration tooling: {tool_entry.get('tool', '')} from "
                        f"{tool_entry.get('url', '')} (`{tool_entry.get('command', '')}`)."
                    )
                    evidence_positions.append(int(tool_entry.get("position", 0)))
                if evidence_positions:
                    evidence_ids = [
                        _canonical_evidence_id(f"EVID-{p + 1:03d}")
                        for p in evidence_positions
                    ]
                    state.add_records(tools._records(evidence_ids))
                for fact in facts:
                    state.observations.append(f"Incident profile: {fact}")
        except Exception:
            pass

        planner_system = (
            "You are the planning component of LogAsis AI investigation planner. Select only safe, read-only evidence operations. "
            "The application provides evidence access; you provide the investigation intelligence. "
            "Never request shell execution, file deletion, network access, credentials, or other side effects."
        )

        for step in range(1, self.max_steps + 1):
            if state.tool_calls >= self.max_tool_calls:
                state.termination_reason = "maximum tool calls reached"
                break
            state.steps = step
            self._progress(15 + int((step - 1) * 45 / self.max_steps), f"Planning investigation step {step}…")
            plan_obj = None
            provider_error = ""
            for attempt, budget in enumerate((PLANNER_MAX_TOKENS, None)):
                try:
                    plan_obj = self._json_object(self._generate(planner_system, self._planner_prompt(state), max_tokens=budget))
                    if plan_obj and isinstance(plan_obj.get("action"), str):
                        break
                except Exception as exc:
                    provider_error = str(exc)
                    plan_obj = None
                if attempt == 0 and not plan_obj:
                    # Reasoning models can exhaust a small planning budget with
                    # hidden reasoning (finish_reason=length). Retry the same
                    # step once with the provider's normal output budget before
                    # treating the step as failed.
                    continue
            if not plan_obj or not isinstance(plan_obj.get("action"), str):
                # Recovery is another AI request, not a deterministic forensic fallback.
                retry_prompt = self._planner_prompt(state) + (
                    "\nYour previous response could not be parsed. Return ONLY one JSON object with an action "
                    "from the available actions. Do not return prose or markdown."
                )
                try:
                    plan_obj = self._json_object(self._generate(planner_system, retry_prompt))
                except Exception as exc:
                    provider_error = provider_error or str(exc)
                    plan_obj = None
            if not plan_obj or not isinstance(plan_obj.get("action"), str):
                state.termination_reason = "AI planner did not return a usable investigation action"
                if provider_error:
                    state.termination_reason += f" ({provider_error[:160]})"
                state.unresolved_questions.append("The AI provider did not produce a usable investigation plan.")
                state.completion_status = FAILED
                break
            plan = plan_obj
            action = str(plan.get("action", "")).strip()
            arguments = plan.get("arguments") if isinstance(plan.get("arguments"), dict) else {}
            reason = str(plan.get("reason", "") or "Investigation action selected.").strip()
            proposed_hypotheses = plan.get("hypotheses", [])
            if isinstance(proposed_hypotheses, list):
                for hypothesis in proposed_hypotheses[:4]:
                    if not isinstance(hypothesis, dict):
                        continue
                    text = str(hypothesis.get("hypothesis") or "").strip()
                    if not text:
                        continue
                    refs = [
                        _canonical_evidence_id(x) for x in (hypothesis.get("evidence_references") or [])
                        if _canonical_evidence_id(x) in state.evidence_records
                    ]
                    state.hypotheses.append({
                        "hypothesis": text,
                        "status": str(hypothesis.get("status") or "UNRESOLVED").upper(),
                        "confidence": str(hypothesis.get("confidence") or "LOW").upper(),
                        "evidence_references": refs,
                    })

            if action == "finish":
                state.termination_reason = "agent determined that sufficient evidence was collected"
                state.actions_taken.append({"step": step, "tool": "finish", "status": "completed", "reason": reason})
                break

            try:
                result = tools.run(action, arguments)
            except Exception as exc:
                state.actions_taken.append({"step": step, "tool": action, "status": "failed", "error": str(exc)})
                state.unresolved_questions.append(f"Tool {action} failed: {exc}")
                state.coverage["failed_batches"] = int(state.coverage.get("failed_batches", 0)) + 1
                continue

            state.tool_calls += 1
            state.retrieval_trace["tool_calls"] = state.tool_calls
            state.retrieval_trace["selected_evidence_ids"] = list(state.evidence_ids)
            self._apply_result(state, result)
            state.retrieval_trace["selected_evidence_ids"] = list(state.evidence_ids)
            state.actions_taken.append({
                "step": step,
                "tool": action,
                "status": "completed",
                "reason": reason,
                "result_count": int(result.get("result_count", len(result.get("records", []) or [])) or 0),
                **(
                    {"total_matches": int(result["total_matches"] or 0)}
                    if result.get("total_matches") is not None
                    else {}
                ),
            })

        if not state.termination_reason:
            state.termination_reason = "maximum investigation steps reached"

        # Timeline is a deterministic presentation of the evidence already
        # collected; it does not require another model/tool round trip.
        state.timeline = sorted(
            [
                state.evidence_records[e]
                for e in state.evidence_ids
                if e in state.evidence_records and state.evidence_records[e].get("timestamp")
            ],
            key=lambda x: (str(x.get("timestamp", "")), str(x.get("evidence_id", ""))),
        )[:40]

        state.confidence = "MODERATE" if len(state.evidence_ids) >= 2 else "LOW"

        # Coverage accounting: distinguishing exhaustive, targeted, partial
        # and failed investigations instead of labelling every budgeted run
        # as complete.
        finished_naturally = state.termination_reason.startswith("agent determined")
        had_unresolved = bool(state.unresolved_questions)
        if state.completion_status != FAILED:
            if finished_naturally and not had_unresolved:
                state.completion_status = COMPLETED_SUFFICIENT
            elif finished_naturally and had_unresolved:
                state.completion_status = COMPLETED_INSUFFICIENT
            else:
                state.completion_status = PARTIAL
        correlated = sum(len(r.get("reasons") or []) for r in state.relationships[:40])
        state.coverage.update({
            "total_events": int(len(tools.df)),
            "indexed_events": int(tools._index.size) if tools._index is not None else int(len(tools.df)),
            "candidate_events": int(len(state.evidence_ids)),
            "total_matching_events": int(state.deterministic_counts[-1]["exact_count"]) if state.deterministic_counts else len(state.evidence_ids),
            "retrieved_events": len(state.evidence_records),
            "correlated_events": correlated,
            "verified_evidence": len(state.evidence_records),
            "excluded_events": max(0, int(len(tools.df)) - len(state.evidence_ids)),
            "truncated_results": any(
                a.get("total_matches") is not None and int(a.get("total_matches", 0)) > a.get("result_count", 0)
                for a in state.actions_taken
            ),
            "coverage_status": (
                "COMPLETE" if state.completion_status == COMPLETED_SUFFICIENT
                else "TARGETED" if state.completion_status == COMPLETED_INSUFFICIENT
                else "PARTIAL"
            ),
            "completion_reason": state.termination_reason,
        })

        # Final model call is synthesis only. It receives compact investigated
        # evidence and deterministic relationship/timeline data, never the full log.
        self._progress(70, "Synthesizing the investigated evidence…")
        deterministic_section = ""
        if state.deterministic_counts:
            deterministic_section = (
                "\n\nDeterministic count results (authoritative query output; use these exact numbers, "
                "never estimates):\n" +
                "\n".join(
                    f"- {c.get('exact_count', 0)} matching event(s) for query '{c.get('query', '')}' "
                    f"(dataset size {c.get('dataset_size', 0)}, exhaustive)"
                    for c in state.deterministic_counts[-8:]
                )
            )
        coverage_section = (
            f"\n\nInvestigation coverage: {state.completion_status} "
            f"({state.coverage.get('coverage_status', 'UNKNOWN')}); termination: {state.termination_reason}. "
            + ("Disclose any incomplete coverage in the answer."
               if state.completion_status in {PARTIAL, COMPLETED_INSUFFICIENT, FAILED}
               else "Coverage was sufficient for the objective.")
        )
        final_system = (
            "You are the final analyst component of LogAsis. Produce an evidence-grounded security assessment.\n"
            "Use only the investigation state and exact evidence records supplied below.\n"
            "Do not invent events, entities, timestamps, commands, IPs, users, processes or relationships.\n"
            "Distinguish VERIFIED_FACT from GROUNDED_INTERPRETATION. Interpretations are advisory and must be "
            "phrased as possible/consistent-with/warrants-investigation when the evidence does not prove intent.\n"
            "Never claim successful compromise, privilege escalation, exfiltration, attacker identity or malicious "
            "intent unless the evidence explicitly establishes it.\n"
            "Every claim must include evidence_references using exact EVID IDs from the supplied evidence.\n"
            "When multiple evidence records repeat the same concrete value (the same CVE ID, IP address, "
            "username, file path, or process name), state that value once and list all supporting EVID IDs "
            "together -- do not repeat the value itself once per record.\n"
            "Return a human-readable analyst report, NOT JSON.\n"
            "Use concise sections such as DIRECT ANSWER, OBSERVED EVIDENCE, AI INTERPRETATION, "
            "LIMITATIONS, CONFIDENCE, and EVIDENCE REFERENCES.\n"
            "Cite material claims with exact evidence IDs such as [EVID-001].\n"
            "Never print JSON objects/arrays or internal field names such as overall_assessment, claims, "
            "evidence_references, limitations, or next_steps in the final user-facing answer.\n"
            "Unsupported claims should be expressed as uncertainty or limitations, not as facts.\n"
            "Answer the user's exact question first; do not substitute a predefined forensic template."
        )
        final_user = (
            f"Investigation objective: {objective}\n"
            f"Investigation state:\n{json.dumps(state.compact_context(limit=20), ensure_ascii=False, default=str)}\n"
            f"{deterministic_section}"
            f"{coverage_section}\n\n"
            "Authoritative evidence index:\n" +
            "\n".join(
                f"[{e}] {state.evidence_records[e].get('text','')}"
                for e in state.evidence_ids
                if e in state.evidence_records
            )
        )
        try:
            final_answer = self._generate_final(final_system, final_user, source_file=source_file)
        except Exception as exc:
            # A few OpenAI-compatible gateways/model revisions can complete the
            # request without returning visible assistant text. Retry once with
            # a simpler plain-text contract. This is intentionally limited to
            # the empty-output condition; authentication/network/provider errors
            # must still surface normally.
            if "no analyst text" not in str(exc).lower() and "empty" not in str(exc).lower():
                raise
            retry_system = (
                "You are the final security analyst for LogAsis. Use only the "
                "supplied deterministic evidence. Return a concise plain-text assessment. "
                "Every factual or analytical claim must cite exact [EVID-xxx] IDs from the evidence. "
                "Separate facts from interpretations. Do not claim compromise, privilege escalation, "
                "exfiltration, attacker identity, or malicious intent unless explicitly established."
            )
            retry_user = (
                final_user
                + "\n\nIMPORTANT: Do not return JSON. Return 2-6 concise bullets under "
                "OBSERVED EVIDENCE and AI INTERPRETATION, with exact [EVID-xxx] citations."
            )
            final_answer = self._generate_final(retry_system, retry_user, source_file=source_file)
        # If the final analyst response contains no grounded claim, give the
        # provider one bounded repair pass. This repairs missing provenance
        # without generating a forensic answer in application code.
        if str(final_answer or "").strip() and not re.search(r"\[EVID-\d+\]", str(final_answer)) and not str(final_answer).lstrip().startswith("{"):
            repair_system = (
                "You are the grounding repair component of LogAsis. "
                "Repair provenance only. Do not add facts or conclusions. "
                "Return JSON with overall_assessment, claims, limitations, next_steps. "
                "Attach exact evidence_references from the supplied evidence."
            )
            repair_user = (
                f"Original analyst response:\n{final_answer}\n\n"
                "Authoritative evidence:\n" +
                "\n".join(
                    f"[{e}] {state.evidence_records[e].get('text','')}"
                    for e in state.evidence_ids if e in state.evidence_records
                )
            )
            try:
                repaired = self._generate(repair_system, repair_user)
                if str(repaired or "").strip():
                    repaired_text = str(repaired or "").strip()
                    if repaired_text and not (repaired_text.startswith("{") and '"action"' in repaired_text and '"claims"' not in repaired_text):
                        final_answer = repaired_text
            except Exception:
                pass

        if not str(final_answer or "").strip():
            # Preserve the provider-empty condition. Do not manufacture an AI
            # assessment from deterministic facts here; the caller will render
            # a deterministic fallback while keeping provider status
            # NO_PROVIDER_ASSESSMENT.
            final_answer = ""

        self._progress(100, "AI investigation complete.")
        return str(final_answer), state.to_report_data()
