from __future__ import annotations

"""Generic evidence packaging helpers.

This module intentionally contains no cybersecurity question taxonomy, intent
classifier, attack vocabulary, or answer rules. It only serializes arbitrary
parsed log fields into bounded evidence records.
"""

import json
import re
from typing import Any, Dict

import pandas as pd


def _safe_col(df: pd.DataFrame, name: str) -> pd.Series:
    if name not in df.columns:
        return pd.Series("", index=df.index, dtype="string")
    return df[name].fillna("").astype(str)


def _truncate(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + f"... [truncated {len(text) - limit} chars]"


def _row_text(row: Any) -> str:
    parts = []
    internal = {"timestamp_dt", "hour", "date", "raw_log"}
    keys = row.index if hasattr(row, "index") else row.keys()
    for key in keys:
        if str(key) in internal:
            continue
        value = row.get(key, "")
        if value is None:
            continue
        text = str(value).strip()
        if not text or text.lower() in {"nan", "nat", "none"}:
            continue
        parts.append(f"{key}={_truncate(text, 700)}")
    return "; ".join(parts)


def _question_tokens(question: str) -> list[str]:
    return [
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_.:/@-]{2,}", str(question or ""))
    ]


def _question_entities(question: str) -> list[str]:
    """Extract concrete identifiers only; no security meaning is assigned."""
    found: list[str] = []
    patterns = [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\bCVE-\d{4}-\d{4,8}\b",
        r"https?://[^\s,;]+",
        r"(?<!\w)(?:[A-Za-z]:[\\/]|/)[^\s,;]+",
    ]
    for pattern in patterns:
        for value in re.findall(pattern, str(question or ""), flags=re.I):
            value = str(value).strip()
            if value and value.lower() not in {x.lower() for x in found}:
                found.append(value)
    return found[:20]


def _generic_score(row: pd.Series, tokens: set[str], entities: list[str]) -> float:
    text = _row_text(row).lower()
    if not tokens and not entities:
        return 0.0
    score = 0.0
    for token in tokens:
        if token and token in text:
            score += 1.0
    for entity in entities:
        if entity.lower() in text:
            score += 4.0
    return score


def _semantic_hints(question: str) -> set[str]:
    """Lightweight semantic field hints improve retrieval without producing an
    answer. They only change which immutable records are handed to the AI."""
    q = str(question or "").lower()
    semantic = set()
    if re.search(r"\b(?:attacker'?s?|source)\s+ip\b|\bip address\b", q):
        semantic.update({"source_ip", "failed_login", "successful_login", "user_auth"})
    if re.search(r"\b(?:account|user)\b.*\bcompromised\b|\bcompromised\b.*\baccount\b", q):
        semantic.update({"successful_login"})
    if re.search(r"\b(?:tool|program)\b.*\b(?:enumeration|enumerate)\b|\bsystem enumeration\b", q):
        semantic.update({"linpeas", "system enumeration"})
    return semantic


def _index_scored_positions(
    event_index: Any,
    tokens: set[str],
    entities: list[str],
    semantic: set[str],
    frame_len: int,
) -> list[tuple[float, int]]:
    """Score rows through the persistent index instead of a full row scan.

    Semantics match the row-text scorer: +1 per matching query token, +4 per
    matching concrete entity, +6 per matching semantic hint. Query tokens can
    never span serialized row boundaries (both sides share one token charset),
    so matching against indexed field values plus field names is equivalent
    to substring matching over the serialized row text.
    """
    scores: dict[int, float] = {}
    weighted: list[tuple[str, float]] = [(token, 1.0) for token in tokens]
    weighted.extend((entity, 4.0) for entity in entities)
    weighted.extend((hint, 6.0) for hint in semantic)
    for term, weight in weighted:
        if len(str(term or "").strip()) < 2:
            continue
        for pos in event_index.match_postings(term):
            if 0 <= pos < frame_len:
                scores[pos] = scores.get(pos, 0.0) + weight
        for pos in event_index.field_name_postings(term):
            if 0 <= pos < frame_len:
                scores[pos] = scores.get(pos, 0.0) + weight
    return sorted(
        ((score, pos) for pos, score in scores.items() if score > 0),
        key=lambda item: (-item[0], item[1]),
    )


def build_evidence_context(
    df: pd.DataFrame,
    question: str,
    max_events: int = 40,
    event_index: Any = None,
) -> Dict[str, Any]:
    """Build a generic, question-scoped evidence bundle.

    Retrieval is lexical and schema-agnostic. It does not classify the question
    or decide what any event means. The AI decides how to investigate the bundle.

    When a persistent ``event_index`` is supplied and matches the frame,
    candidate scoring runs against the index instead of scanning every row,
    so per-question retrieval cost depends on matched postings rather than
    dataset size. Results are ranked identically to the scanning path.
    """
    max_events = max(1, int(max_events))
    if df is None:
        df = pd.DataFrame()
    tokens = set(_question_tokens(question))
    entities = _question_entities(question)
    semantic = _semantic_hints(question)

    use_index = (
        event_index is not None
        and len(df) > 0
        and getattr(event_index, "size", -1) == len(df)
    )

    if use_index:
        frame = df.reset_index(drop=True)
        scored = _index_scored_positions(event_index, tokens, entities, semantic, len(frame))
        positive_count = len(scored)
        selected = [(score, pos, frame.iloc[pos]) for score, pos in scored[:max_events]]
        if not selected:
            # Neutral sample fallback, identical to the scanning path when no
            # row matches: the first rows in dataset order.
            selected = [(0.0, pos, frame.iloc[pos]) for pos in range(min(max_events, len(frame)))]
    else:
        frame = df.copy().reset_index(drop=True)
        scored_rows = []
        for idx, row in frame.iterrows():
            score = _generic_score(row, tokens, entities)
            row_text = _row_text(row).lower()
            for hint in semantic:
                if hint in row_text:
                    score += 6.0
            scored_rows.append((score, idx, row))
        scored_rows.sort(key=lambda x: (-x[0], x[1]))
        positive_count = len([item for item in scored_rows if item[0] > 0])
        selected = [item for item in scored_rows if item[0] > 0][:max_events]
        if not selected and len(frame):
            # Returning a small neutral sample is a retrieval fallback, not an
            # answer. The AI can request more targeted evidence with its tools.
            selected = scored_rows[: min(max_events, len(scored_rows))]

    evidence_records = []
    evidence_lines = []
    for _, idx, row in selected:
        evid = f"EVID-{idx + 1:03d}"
        text = _row_text(row)
        record = {
            "evidence_id": evid,
            "source_position": int(idx),
            "text": text,
            "line": str(row.get("line", "")),
            "timestamp": str(row.get("timestamp", "")),
        }
        evidence_records.append(record)
        evidence_lines.append(f"[{evid}] {text}")

    retrieval = {
        "method": "index-backed-lexical-evidence-retrieval" if use_index else "generic-lexical-evidence-retrieval",
        "query": str(question or "").strip(),
        "query_terms": sorted(tokens)[:40],
        "query_entities": entities,
        "selected_evidence_ids": [r["evidence_id"] for r in evidence_records],
        "evidence_ids": [r["evidence_id"] for r in evidence_records],
        "selected_events": len(evidence_records),
        "document_count": int(len(df)),
        "seed_candidates": positive_count,
        "expanded_candidates": len(evidence_records),
        "evidence_bundle_version": "generic-1",
    }
    return {
        "question": str(question or "").strip(),
        "summary": {"event_count": int(len(df)), "total_events": int(len(df)), "field_count": int(len(df.columns))},
        "high_critical_event_count": int(
            _safe_col(df, "severity").str.lower().isin(["high", "critical"]).sum()
        ),
        "relevant_events": evidence_lines,
        "evidence_records": evidence_records,
        "retrieval": retrieval,
        "fields": [str(c) for c in df.columns if str(c) not in {"timestamp_dt", "hour", "date", "raw_log"}],
    }


def evidence_to_prompt(context: Dict[str, Any]) -> str:
    lines = [
        f"User question: {context.get('question', '')}",
        "",
        "You are investigating an immutable evidence bundle.",
        "The application has not interpreted the question for you. Decide what the evidence means.",
        "Use only the supplied records for factual claims and cite exact [EVID-xxx] labels.",
        "Do not invent evidence IDs or values.",
        "",
        "Dataset metadata:",
        json_safe(context.get("summary", {})),
        "Available fields:",
        json_safe(context.get("fields", [])),
        "",
        "Retrieval plan:",
        json_safe(context.get("retrieval", {})),
        "",
        "Relevant event evidence:",
    ]
    events = context.get("relevant_events") or []
    lines.extend(f"- {item}" for item in events) if events else lines.append("- No evidence was retrieved.")
    return "\n".join(lines)


def json_safe(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
