from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable


class EventIndex:
    """Lightweight in-memory index for large loaded log datasets.

    The index is deliberately read-only after build. It provides:
      - exact-value lookup for common fields
      - token lookup for broad searches
      - stable row-position results
      - cheap intersection/union of candidate positions

    It is an acceleration layer only. Security conclusions remain owned by
    the existing deterministic engines.
    """

    SEARCH_FIELDS = (
        "timestamp", "event_type", "source_ip", "destination_ip",
        "username", "process_name", "command", "pid", "ppid", "uid",
        "euid", "auid", "audit_serial", "action", "severity",
        "message", "line",
    )

    def __init__(self, events: Iterable[dict[str, Any]] | None = None):
        self._events: list[dict[str, Any]] = []
        self._field_values: dict[str, defaultdict[str, set[int]]] = {}
        self._tokens: defaultdict[str, set[int]] = defaultdict(set)
        self._search_fields: tuple[str, ...] = self.SEARCH_FIELDS
        self.build(events or [])

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        # Keep tokens conservative: this is a candidate index, not a parser.
        return {token for token in re.findall(r"[a-z0-9_./:@+-]{2,}", text.lower())}

    def build(self, events: Iterable[dict[str, Any]]) -> None:
        self._events = [dict(event) for event in events]
        # Keep the established normalized fields, then add every populated
        # source-specific field from the current log. This makes filtering and
        # lookup schema-aware without hardcoding a particular log vendor.
        dynamic_fields = []
        for event in self._events:
            for field, value in event.items():
                field = str(field)
                if field in self.SEARCH_FIELDS or field in {"timestamp_dt", "hour", "date", "raw_log"}:
                    continue
                if str(value or "").strip() and str(value).strip().lower() not in {"nan", "nat", "none"}:
                    if field not in dynamic_fields:
                        dynamic_fields.append(field)
        self._search_fields = tuple(dict.fromkeys((*self.SEARCH_FIELDS, *dynamic_fields)))
        self._field_values = {
            field: defaultdict(set) for field in self._search_fields
        }
        self._tokens = defaultdict(set)

        for pos, event in enumerate(self._events):
            for field in self._search_fields:
                value = self._norm(event.get(field))
                if value:
                    self._field_values[field][value].add(pos)
                    for token in self._tokenize(value):
                        self._tokens[token].add(pos)

    @property
    def size(self) -> int:
        return len(self._events)

    def exact(self, field: str, value: Any) -> list[int]:
        field = str(field or "")
        if field not in self._field_values:
            return []
        return sorted(self._field_values[field].get(self._norm(value), set()))

    def token_candidates(self, query: str) -> list[int]:
        tokens = self._tokenize(query)
        if not tokens:
            return []
        postings = [self._tokens[token] for token in tokens if token in self._tokens]
        if not postings:
            return []
        # AND semantics produce a small candidate set; caller can perform the
        # authoritative substring check on those candidates.
        result = set(postings[0])
        for posting in postings[1:]:
            result.intersection_update(posting)
        return sorted(result)

    def field_candidates(self, field: str, query: str) -> list[int]:
        q = self._norm(query)
        if not q or field not in self._field_values:
            return []
        # Exact hits are by far the common case.
        exact = self._field_values[field].get(q)
        if exact:
            return sorted(exact)

        # Fall back to values containing the query, but only across distinct
        # field values, avoiding a full event-by-event scan in the caller.
        positions: set[int] = set()
        for value, rows in self._field_values[field].items():
            if q in value:
                positions.update(rows)
        return sorted(positions)

    def all_positions(self) -> range:
        return range(len(self._events))


# local import kept at bottom so the module stays dependency-light
import re
