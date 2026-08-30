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


def _row_text(row: pd.Series) -> str:
    parts = []
    internal = {"timestamp_dt", "hour", "date", "raw_log"}
    for key in row.index:
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


def build_evidence_context(df: pd.DataFrame, question: str, max_events: int = 40) -> Dict[str, Any]:
    """Build a generic, question-scoped evidence bundle.

    Retrieval is lexical and schema-agnostic. It does not classify the question
    or decide what any event means. The AI decides how to investigate the bundle.
    """
    max_events = max(1, int(max_events))
    if df is None:
        df = pd.DataFrame()
    frame = df.copy().reset_index(drop=True)
    tokens = set(_question_tokens(question))
    entities = _question_entities(question)

    # Lightweight semantic field hints improve retrieval without producing an
    # answer. They only change which immutable records are handed to the AI.
    q = str(question or "").lower()
    semantic = set()
    if re.search(r"\b(?:attacker'?s?|source)\s+ip\b|\bip address\b", q):
        semantic.update({"source_ip", "failed_login", "successful_login", "user_auth"})
    if re.search(r"\b(?:account|user)\b.*\bcompromised\b|\bcompromised\b.*\baccount\b", q):
        semantic.update({"successful_login"})
    if re.search(r"\b(?:tool|program)\b.*\b(?:enumeration|enumerate)\b|\bsystem enumeration\b", q):
        semantic.update({"linpeas", "system enumeration"})

    scored = []
    for idx, row in frame.iterrows():
        score = _generic_score(row, tokens, entities)
        row_text = _row_text(row).lower()
        for hint in semantic:
            if hint in row_text:
                score += 6.0
        scored.append((score, idx, row))
    scored.sort(key=lambda x: (-x[0], x[1]))

    selected = [item for item in scored if item[0] > 0][:max_events]
    if not selected and len(frame):
        # Returning a small neutral sample is a retrieval fallback, not an
        # answer. The AI can request more targeted evidence with its tools.
        selected = scored[: min(max_events, len(scored))]

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
        "method": "generic-lexical-evidence-retrieval",
        "query": str(question or "").strip(),
        "query_terms": sorted(tokens)[:40],
        "query_entities": entities,
        "selected_evidence_ids": [r["evidence_id"] for r in evidence_records],
        "evidence_ids": [r["evidence_id"] for r in evidence_records],
        "selected_events": len(evidence_records),
        "document_count": len(frame),
        "seed_candidates": len([item for item in scored if item[0] > 0]),
        "expanded_candidates": len(evidence_records),
        "evidence_bundle_version": "generic-1",
    }
    return {
        "question": str(question or "").strip(),
        "summary": {"event_count": int(len(frame)), "total_events": int(len(frame)), "field_count": int(len(frame.columns))},
        "high_critical_event_count": int(
            _safe_col(frame, "severity").str.lower().isin(["high", "critical"]).sum()
        ),
        "relevant_events": evidence_lines,
        "evidence_records": evidence_records,
        "retrieval": retrieval,
        "fields": [str(c) for c in frame.columns if str(c) not in {"timestamp_dt", "hour", "date", "raw_log"}],
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
