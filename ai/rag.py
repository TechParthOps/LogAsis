from __future__ import annotations

"""Provider-independent Retrieval-Augmented Generation for LogAsis.

The retriever deliberately knows nothing about a particular vendor, log format,
or attack scenario. It indexes the normalized DataFrame *as data*, including
previously unknown/source-specific fields. A provider receives only the
retrieved evidence plus a small deterministic dataset profile.

The implementation is intentionally dependency-light. scikit-learn is used
when available for TF-IDF/cosine retrieval; a deterministic token-overlap
fallback is retained so LogAsis still works in minimal environments.
"""

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

import pandas as pd


_INTERNAL_COLUMNS = {"timestamp_dt", "hour", "date", "raw_log"}
_EMPTY = {"", "nan", "nat", "none", "null"}

# Small universal security-log vocabulary. This is intentionally a generic
# semantic bridge, not a per-format rule set: source fields are still discovered
# from the actual DataFrame and vendor-specific fields require no configuration.

def _text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def _tokens(value: str) -> list[str]:
    # Keep underscores and dotted field names useful while also exposing their
    # components (source_ip -> source + ip; EventData.CommandLine -> eventdata,
    # commandline). Character n-grams are supplied to TF-IDF separately.
    raw = re.findall(r"[A-Za-z0-9]+(?:[_./:-][A-Za-z0-9]+)*", value.lower())
    out: list[str] = []
    for token in raw:
        if len(token) >= 2:
            out.append(token)
        for part in re.split(r"[_./:-]+", token):
            if len(part) >= 2:
                out.append(part)
        # Cheap morphology improves generic questions without a security
        # scenario dictionary: accounts/account, processes/process, etc.
        if token.endswith("ies") and len(token) > 4:
            out.append(token[:-3] + "y")
        elif token.endswith("s") and len(token) > 4:
            out.append(token[:-1])
        elif token.endswith("ed") and len(token) > 5:
            out.append(token[:-2])
    return list(dict.fromkeys(out))


def _field_value_text(row: pd.Series) -> tuple[str, dict[str, str]]:
    fields: dict[str, str] = {}
    pieces: list[str] = []
    for column in row.index:
        name = str(column)
        if name in _INTERNAL_COLUMNS:
            continue
        value = _text(row.get(column, ""))
        if not value or value.lower() in _EMPTY:
            continue
        # Flatten simple dict/list values rather than dropping custom JSON
        # fields. This keeps arbitrary parser/source fields searchable.
        if isinstance(row.get(column), (dict, list, tuple)):
            value = _text(row.get(column))
        fields[name] = value[:1200]
        pieces.append(f"{name}={value[:1200]}")
    return " ".join(pieces), fields


def _stable_evidence_id(position: int) -> str:
    return f"EVID-{int(position) + 1:03d}"


def _expanded_query_text(query: str) -> str:
    # No security synonym dictionary: the query is supplied by the AI/user.
    return str(query or "").strip()


@dataclass(frozen=True)
class RAGDocument:
    evidence_id: str
    source_position: int
    text: str
    fields: dict[str, str]
    timestamp: str = ""
    severity: str = ""
    logical_chunk_id: str = ""


@dataclass
class RAGResult:
    records: list[dict[str, Any]]
    trace: dict[str, Any]


class LogRAGIndex:
    """In-memory index built from exactly one LogAsis analysis DataFrame."""

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy().reset_index(drop=True)
        self.documents: list[RAGDocument] = []
        self._build_documents()
        self._vectorizer = None
        self._matrix = None
        self._char_vectorizer = None
        self._char_matrix = None
        self._idf: dict[str, float] = {}
        self._doc_term_freq: list[Counter[str]] = []
        self._avg_doc_len = 0.0
        self._build_bm25_index()
        self._build_tfidf()

    @staticmethod
    def _group_field(columns: list[str]) -> str | None:
        """Find a session/request correlation field from the live schema."""
        patterns = (
            "session", "request_id", "requestid", "trace_id", "traceid",
            "transaction_id", "transactionid", "correlation_id", "correlationid",
            "flow_id", "flowid",
        )
        for column in columns:
            lowered = re.sub(r"[^a-z0-9_]", "", str(column).lower())
            if any(p in lowered for p in patterns):
                return str(column)
        return None

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        text = _text(value)
        if not text:
            return None
        try:
            parsed = pd.to_datetime(text, errors="coerce", utc=True)
            if pd.isna(parsed):
                return None
            return parsed.to_pydatetime()
        except Exception:
            return None

    def _logical_chunk_ids(self) -> list[str]:
        """Group nearby events without cutting individual log records.

        Session/request identifiers take precedence when present. Otherwise
        events are grouped into one-minute UTC windows. This is deliberately
        schema-discovered: no vendor field or attack scenario is assumed.
        """
        group_field = self._group_field([str(c) for c in self.df.columns])
        counters: dict[str, int] = {}
        chunk_ids: list[str] = []
        previous_time: datetime | None = None
        time_bucket = 0
        for position, (_, row) in enumerate(self.df.iterrows()):
            if group_field:
                value = _text(row.get(group_field, ""))
                if value:
                    key = f"FIELD:{group_field}={value}"
                    counters[key] = counters.get(key, 0) + 1
                    chunk_ids.append("CHUNK-FIELD-" + hashlib.sha1(key.encode("utf-8", "ignore")).hexdigest()[:10])
                    continue
            current = self._parse_timestamp(row.get("timestamp", ""))
            if current is None:
                chunk_ids.append(f"CHUNK-SEQ-{position // 50:05d}")
                continue
            bucket = int(current.timestamp() // 60)
            if previous_time is None or bucket != time_bucket:
                time_bucket = bucket
            previous_time = current
            chunk_ids.append(f"CHUNK-TIME-{time_bucket}")
        return chunk_ids

    def _build_documents(self) -> None:
        chunk_ids = self._logical_chunk_ids()
        for position, (_, row) in enumerate(self.df.iterrows()):
            body, fields = _field_value_text(row)
            if not body:
                body = f"row={position + 1}"
            self.documents.append(
                RAGDocument(
                    evidence_id=_stable_evidence_id(position),
                    source_position=position,
                    text=body,
                    fields=fields,
                    timestamp=_text(row.get("timestamp", "")),
                    severity=_text(row.get("severity", "")),
                    logical_chunk_id=chunk_ids[position] if position < len(chunk_ids) else f"CHUNK-SEQ-{position // 50:05d}",
                )
            )

    def _build_bm25_index(self) -> None:
        """Build a dependency-free BM25 keyword index over complete log records."""
        tokenized = [list(dict.fromkeys(_tokens(doc.text))) for doc in self.documents]
        self._doc_term_freq = [Counter(tokens) for tokens in tokenized]
        if not tokenized:
            self._idf, self._avg_doc_len = {}, 0.0
            return
        doc_count = len(tokenized)
        self._avg_doc_len = sum(len(tokens) for tokens in tokenized) / max(1, doc_count)
        document_frequency: Counter[str] = Counter()
        for tokens in tokenized:
            document_frequency.update(set(tokens))
        self._idf = {
            term: math.log(1.0 + (doc_count - freq + 0.5) / (freq + 0.5))
            for term, freq in document_frequency.items()
        }

    def _bm25_scores(self, query: str) -> list[float]:
        if not self.documents or not self._idf:
            return [0.0] * len(self.documents)
        query_terms = _tokens(query)
        if not query_terms:
            return [0.0] * len(self.documents)
        k1, b = 1.5, 0.75
        qfreq = Counter(query_terms)
        scores: list[float] = []
        for tf, doc in zip(self._doc_term_freq, self.documents):
            doc_len = sum(tf.values())
            score = 0.0
            for term, qf in qfreq.items():
                if term not in tf:
                    continue
                frequency = tf[term]
                numerator = frequency * (k1 + 1.0)
                denominator = frequency + k1 * (1.0 - b + b * doc_len / max(self._avg_doc_len, 1.0))
                score += self._idf.get(term, 0.0) * numerator / max(denominator, 1e-9)
            scores.append(float(score))
        return scores

    @staticmethod
    def _normalize_scores(values: list[float]) -> list[float]:
        if not values:
            return []
        high = max(values)
        low = min(values)
        if high <= low:
            return [1.0 if high > 0 else 0.0 for _ in values]
        return [(value - low) / (high - low) for value in values]

    def _build_tfidf(self) -> None:
        if not self.documents:
            return
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            vectorizer = TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                analyzer="word",
                token_pattern=r"(?u)\b[A-Za-z0-9][A-Za-z0-9_.:/-]*\b",
                min_df=1,
                sublinear_tf=True,
            )
            corpus = [d.text for d in self.documents]
            self._vectorizer = vectorizer
            self._matrix = vectorizer.fit_transform(corpus)
            # Character n-grams make natural-language retrieval tolerant of
            # morphology and vendor naming differences (authenticated vs
            # authentication, EventData.CommandLine vs commandline) without
            # requiring a hard-coded security synonym table.
            from sklearn.feature_extraction.text import TfidfVectorizer as _CharTfidf
            char_vectorizer = _CharTfidf(
                lowercase=True,
                strip_accents="unicode",
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=1,
                sublinear_tf=True,
            )
            self._char_vectorizer = char_vectorizer
            self._char_matrix = char_vectorizer.fit_transform(corpus)
        except Exception:
            # Retrieval remains functional via deterministic overlap scoring.
            self._vectorizer = None
            self._matrix = None
            self._char_vectorizer = None
            self._char_matrix = None

    @property
    def field_catalog(self) -> list[str]:
        return sorted({field for doc in self.documents for field in doc.fields})

    def _cosine_scores(self, query: str) -> list[float]:
        if self._vectorizer is None or self._matrix is None:
            return [0.0] * len(self.documents)
        try:
            vector = self._vectorizer.transform([query])
            scores = (self._matrix @ vector.T).toarray().ravel()
            if self._char_vectorizer is not None and self._char_matrix is not None:
                char_vector = self._char_vectorizer.transform([query])
                char_scores = (self._char_matrix @ char_vector.T).toarray().ravel()
                scores = 0.65 * scores + 0.35 * char_scores
            return [float(x) for x in scores]
        except Exception:
            return [0.0] * len(self.documents)

    @staticmethod
    def _generic_overlap(query: str, document: RAGDocument) -> float:
        q = set(_tokens(query))
        if not q:
            return 0.0
        doc_tokens = set(_tokens(document.text))
        if not doc_tokens:
            return 0.0
        return len(q & doc_tokens) / math.sqrt(len(q) * len(doc_tokens))

    @staticmethod
    def _entity_hits(query: str, document: RAGDocument) -> int:
        # Entities are discovered from the question, not from a fixed security
        # schema. This handles IPs, hashes, paths, domains, CVEs, filenames,
        # UUIDs and other concrete identifiers without configuration.
        patterns = [
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"\bCVE-\d{4}-\d{4,8}\b",
            r"\b[0-9a-fA-F]{32,128}\b",
            r"https?://[^\s\"']+",
            r"(?:[A-Za-z]:[\\/]|/)[^\s,;]+",
        ]
        hits = 0
        qlower = query.lower()
        lower_doc = document.text.lower()
        for pattern in patterns:
            for entity in re.findall(pattern, qlower, flags=re.I):
                if entity.lower() in lower_doc:
                    hits += 1
        return hits

    @staticmethod
    def _field_hits(query: str, document: RAGDocument) -> int:
        qtokens = set(_tokens(query))
        if not qtokens:
            return 0
        hits = 0
        for field in document.fields:
            field_tokens = set(_tokens(field))
            if qtokens & field_tokens:
                hits += len(qtokens & field_tokens)
        return hits

    @staticmethod
    def _severity_boost(query: str, document: RAGDocument) -> float:
        q = query.lower()
        # This is deliberately generic ranking behavior for broad risk review,
        # not an attack detector. Severity is only a tie-break/ranking signal.
        broad = any(word in q for word in ("risk", "risky", "severe", "important", "suspicious", "threat", "incident"))
        if not broad:
            return 0.0
        return {"critical": 0.10, "high": 0.07, "medium": 0.03}.get(document.severity.lower(), 0.0)

    def retrieve(self, question: str, top_k: int = 24) -> RAGResult:
        top_k = max(1, min(int(top_k), max(1, len(self.documents))))
        query = str(question or "").strip()
        retrieval_query = _expanded_query_text(query)

        # Hybrid retrieval: BM25 provides exact log-token matching, TF-IDF/char
        # similarity provides softer semantic/shape matching, and entity/field
        # hits protect concrete identifiers and source-specific field names.
        bm25 = self._bm25_scores(retrieval_query)
        bm25_n = self._normalize_scores(bm25)
        cosine = self._cosine_scores(retrieval_query)
        cosine_n = self._normalize_scores(cosine)

        scored: list[tuple[float, int, RAGDocument, dict[str, float]]] = []
        q_tokens = set(_tokens(retrieval_query))
        for idx, document in enumerate(self.documents):
            overlap = self._generic_overlap(retrieval_query, document)
            entity_hits = self._entity_hits(query, document)
            field_hits = self._field_hits(retrieval_query, document)
            exact_hits = sum(1 for token in q_tokens if token in set(_tokens(document.text)))
            exact_n = min(1.0, exact_hits / max(1, len(q_tokens)))
            score = (
                bm25_n[idx] * 0.50
                + cosine_n[idx] * 0.30
                + overlap * 0.10
                + exact_n * 0.07
                + min(entity_hits, 3) / 3.0 * 0.02
                + min(field_hits, 4) / 4.0 * 0.01
            )
            scored.append((score, idx, document, {
                "bm25": bm25[idx],
                "tfidf_cosine": cosine[idx],
                "token_overlap": overlap,
                "exact_keyword_hits": float(exact_hits),
                "entity_hits": float(entity_hits),
                "field_hits": float(field_hits),
            }))

        scored.sort(key=lambda item: (-item[0], item[2].source_position))
        positive = [item for item in scored if item[0] > 0.000001]

        # Exact identifiers are never weakened by a broad semantic match.
        if positive and not any(self._entity_hits(query, item[2]) for item in positive):
            best = positive[0][0]
            positive = [item for item in positive if item[0] >= best * 0.45]

        selected = (positive if positive else scored)[:top_k]

        # Logical expansion: once a relevant event is found, nearby/session
        # events can be included for correlation. This does not change ranking
        # or invent facts; it only supplies the surrounding evidence window.
        if selected and top_k > 1 and len(selected) < top_k:
            chunk_keys = {item[2].logical_chunk_id for item in selected}
            expanded = list(selected)
            seen = {item[2].evidence_id for item in expanded}
            for item in scored:
                if item[2].logical_chunk_id in chunk_keys and item[2].evidence_id not in seen:
                    expanded.append(item)
                    seen.add(item[2].evidence_id)
                    if len(expanded) >= top_k:
                        break
            selected = expanded[:top_k]

        selected.sort(key=lambda item: item[2].source_position)
        records: list[dict[str, Any]] = []
        for score, _, document, components in selected:
            records.append({
                "evidence_id": document.evidence_id,
                "source_position": document.source_position,
                "text": document.text,
                "source_fields": dict(document.fields),
                "timestamp": document.timestamp,
                "severity": document.severity,
                "logical_chunk_id": document.logical_chunk_id,
                "retrieval_score": round(float(score), 6),
                "retrieval_components": components,
            })

        trace = {
            "method": "hybrid-rag-bm25-tfidf",
            "query": query,
            "expanded_query": retrieval_query,
            "top_k": top_k,
            "document_count": len(self.documents),
            "selected_count": len(records),
            "selected_evidence_ids": [r["evidence_id"] for r in records],
            "evidence_ids": [r["evidence_id"] for r in records],
            "indexed_fields": self.field_catalog,
            "semantic_backend": "tfidf-word+char" if self._vectorizer is not None else "token-overlap",
            "keyword_backend": "bm25",
            "logical_chunking": "session/request/correlation field, else 60-second time window",
            "logical_chunk_count": len({d.logical_chunk_id for d in self.documents}),
        }
        return RAGResult(records=records, trace=trace)


def build_rag_context(
    df: pd.DataFrame,
    question: str,
    *,
    top_k: int = 24,
    index: LogRAGIndex | None = None,
) -> dict[str, Any]:
    """Create a provider-ready RAG package from the current log view.

    Pass a shared ``index`` (for example ``LogDataset.get_rag_index()``) so
    repeated questions reuse one index build instead of rebuilding per call.
    """
    if index is None:
        index = LogRAGIndex(df)
    result = index.retrieve(question, top_k=top_k)
    severity = df.get("severity", pd.Series("", index=df.index)).fillna("").astype(str).str.lower()
    profile = {
        "event_count": int(len(df)),
        "column_count": int(len(df.columns)),
        "fields": [str(c) for c in df.columns if str(c) not in _INTERNAL_COLUMNS],
        "severity_counts": {str(k): int(v) for k, v in severity.value_counts().head(10).items() if str(k).strip()},
    }
    return {
        "question": str(question or "").strip(),
        "profile": profile,
        "retrieval": result.trace,
        "evidence_records": result.records,
        "relevant_events": [f"[{r['evidence_id']}] {r['text']}" for r in result.records],
    }


def rag_to_prompt(context: dict[str, Any]) -> str:
    """Serialize only retrieved evidence for an AI provider."""
    lines = [
        "You are LogAsis RAG Analyst.",
        "The supplied retrieved records are the only evidence you may use for concrete claims.",
        "Answer the exact user question first.",
        "Do not invent, rename, merge, or alter evidence IDs.",
        "Do not treat a successful login as proof of compromise unless the evidence itself establishes compromise.",
        "Distinguish OBSERVED FACTS from GROUNDED INTERPRETATIONS.",
        "Every concrete claim must cite one or more exact [EVID-xxx] records containing that fact.",
        "If the retrieved evidence is insufficient, say what is not established instead of guessing.",
        "Return JSON only with: overall_assessment, claims, limitations, next_steps.",
        "Each claim must contain text, type (VERIFIED_FACT|GROUNDED_INTERPRETATION|UNSUPPORTED_CLAIM), evidence_references, confidence.",
        "",
        f"User question: {context.get('question', '')}",
        "",
        "Dataset profile (descriptive only):",
        str(context.get("profile", {})),
        "",
        "RAG retrieval trace:",
        str(context.get("retrieval", {})),
        "",
        "RETRIEVED EVIDENCE:",
    ]
    records = context.get("evidence_records") or []
    if records:
        for record in records:
            lines.append(f"[{record.get('evidence_id')}] {record.get('text', '')}")
    else:
        lines.append("No evidence records were retrieved for this question.")
    return "\n".join(lines)
