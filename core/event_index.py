from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable


class EventIndex:
    """Persistent in-memory index for large loaded log datasets.

    The index is deliberately read-only after build. It provides:
      - exact-value lookup for common and dynamic fields
      - token lookup for broad searches
      - stable row-position results
      - cheap intersection/union of candidate positions
      - timestamp range queries via sorted timestamp array
      - prefix-based value discovery for high-cardinality fields
      - facet/aggregation counts over any field
      - entity and correlation field indexes

    It is an acceleration layer only. Security conclusions remain owned by
    the existing deterministic engines.
    """

    SEARCH_FIELDS = (
        "timestamp", "event_type", "source_ip", "destination_ip",
        "username", "process_name", "command", "pid", "ppid", "uid",
        "euid", "auid", "audit_serial", "action", "severity",
        "message", "line",
    )

    _INTERNAL_FIELDS = {"timestamp_dt", "hour", "date", "raw_log"}
    _EMPTY_VALUES = {"", "nan", "nat", "none", "null"}

    _CORRELATION_PATTERNS = (
        "session", "request_id", "requestid", "trace_id", "traceid",
        "transaction_id", "transactionid", "correlation_id", "correlationid",
        "flow_id", "flowid", "audit_serial", "pid", "ppid",
    )

    _ENTITY_FIELDS = {
        "ip": ("source_ip", "destination_ip", "src_ip", "dst_ip", "client_ip", "remote_ip"),
        "username": ("username", "user", "account", "acct", "targetusername", "subjectusername"),
        "process": ("process_name", "image", "exe", "process"),
        "pid": ("pid", "processid", "newprocessid"),
        "ppid": ("ppid", "parentprocessid"),
        "file": ("file", "filename", "targetfilename", "filepath", "objectname"),
        "hash": ("hashes", "hash", "sha256", "sha1", "md5"),
        "domain": ("domain", "hostname", "host", "fqdn", "queryname"),
        "url": ("url", "uri", "request_url"),
        "cve": ("cve", "cve_id"),
        "command": ("command", "commandline", "cmdline", "processcommandline"),
    }

    def __init__(self, events: Iterable[dict[str, Any]] | None = None):
        self._events: list[dict[str, Any]] = []
        self._field_values: dict[str, defaultdict[str, set[int]]] = {}
        self._tokens: defaultdict[str, set[int]] = defaultdict(set)
        self._search_fields: tuple[str, ...] = self.SEARCH_FIELDS
        self._timestamp_array: list[tuple[datetime | None, int]] = []
        self._sorted_timestamps: list[tuple[datetime, int]] = []
        self._prefix_index: dict[str, dict[str, set[str]]] = {}
        self._correlation_fields: dict[str, str] = {}
        self._entity_indexes: dict[str, dict[str, set[int]]] = {}
        self._field_cardinality: dict[str, int] = {}
        self._field_distinct_cache: dict[str, list[str]] = {}
        self._facet_cache: dict[tuple[str, Any], dict[str, int]] = {}
        self._term_cache: dict[str, frozenset[int]] = {}
        self.build(events or [])

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return {token for token in re.findall(r"[a-z0-9_./:@+-]{2,}", text.lower())}

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ):
            try:
                return datetime.strptime(text, fmt)
            except (ValueError, TypeError):
                continue
        return None

    def build(self, events: Iterable[dict[str, Any]]) -> None:
        self._events = [dict(event) for event in events]
        dynamic_fields = []
        for event in self._events:
            for field, value in event.items():
                field = str(field)
                if field in self.SEARCH_FIELDS or field in self._INTERNAL_FIELDS:
                    continue
                if str(value or "").strip() and str(value).strip().lower() not in self._EMPTY_VALUES:
                    if field not in dynamic_fields:
                        dynamic_fields.append(field)
        self._search_fields = tuple(dict.fromkeys((*self.SEARCH_FIELDS, *dynamic_fields)))
        self._field_values = {
            field: defaultdict(set) for field in self._search_fields
        }
        self._tokens = defaultdict(set)
        self._timestamp_array = []
        self._sorted_timestamps = []
        self._prefix_index = {}
        self._correlation_fields = {}
        self._entity_indexes = {}
        self._field_cardinality = {}
        self._field_distinct_cache = {}
        self._facet_cache = {}
        self._term_cache = {}

        for pos, event in enumerate(self._events):
            for field in self._search_fields:
                value = self._norm(event.get(field))
                if value:
                    self._field_values[field][value].add(pos)
                    for token in self._tokenize(value):
                        self._tokens[token].add(pos)

            ts = self._parse_timestamp(event.get("timestamp"))
            self._timestamp_array.append((ts, pos))
            if ts is not None:
                self._sorted_timestamps.append((ts, pos))

        self._sorted_timestamps.sort(key=lambda x: (x[0], x[1]))

        for field in self._search_fields:
            self._field_cardinality[field] = len(self._field_values[field])

        self._discover_correlation_fields()
        self._build_entity_indexes()
        self._build_prefix_indexes()

    def _discover_correlation_fields(self) -> None:
        for field in self._search_fields:
            normalized = re.sub(r"[^a-z0-9_]", "", field.lower())
            for pattern in self._CORRELATION_PATTERNS:
                if pattern in normalized:
                    self._correlation_fields[field] = pattern
                    break

    def _build_entity_indexes(self) -> None:
        for entity_type, field_names in self._ENTITY_FIELDS.items():
            index: dict[str, set[int]] = {}
            for field in field_names:
                if field in self._field_values:
                    for value, positions in self._field_values[field].items():
                        if value and value not in self._EMPTY_VALUES:
                            if value not in index:
                                index[value] = set()
                            index[value].update(positions)
            if index:
                self._entity_indexes[entity_type] = index

    def _build_prefix_indexes(self) -> None:
        for field in self._search_fields:
            cardinality = self._field_cardinality.get(field, 0)
            if cardinality > 100:
                prefix_map: dict[str, set[str]] = {}
                for value in self._field_values[field]:
                    for length in (3, 5, 8):
                        if len(value) >= length:
                            prefix = value[:length]
                            if prefix not in prefix_map:
                                prefix_map[prefix] = set()
                            prefix_map[prefix].add(value)
                self._prefix_index[field] = prefix_map

    @property
    def size(self) -> int:
        return len(self._events)

    @property
    def search_fields(self) -> tuple[str, ...]:
        return self._search_fields

    @property
    def correlation_fields(self) -> dict[str, str]:
        return dict(self._correlation_fields)

    @property
    def entity_indexes(self) -> dict[str, dict[str, set[int]]]:
        return self._entity_indexes

    @property
    def field_cardinality(self) -> dict[str, int]:
        return dict(self._field_cardinality)

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
        result = set(postings[0])
        for posting in postings[1:]:
            result.intersection_update(posting)
        return sorted(result)

    def field_candidates(self, field: str, query: str) -> list[int]:
        q = self._norm(query)
        if not q or field not in self._field_values:
            return []
        exact = self._field_values[field].get(q)
        if exact:
            return sorted(exact)
        positions: set[int] = set()
        for value, rows in self._field_values[field].items():
            if q in value:
                positions.update(rows)
        return sorted(positions)

    def match_postings(self, term: str) -> frozenset[int]:
        """Rows whose indexed field values contain term as a token substring.

        Exact token hits are O(1). Terms that are not exact tokens fall back
        to a substring scan over the distinct token vocabulary (not over
        rows), which stays cheap even for large datasets. Results are cached
        per term for the lifetime of the index.
        """
        text = str(term or "").strip().lower()
        if len(text) < 2:
            return frozenset()
        cached = self._term_cache.get(text)
        if cached is not None:
            return cached
        posting = self._tokens.get(text)
        if posting is not None:
            result = frozenset(posting)
        else:
            matched: set[int] = set()
            for token, rows in self._tokens.items():
                if text in token:
                    matched.update(rows)
            result = frozenset(matched)
        self._term_cache[text] = result
        return result

    def field_name_postings(self, term: str) -> frozenset[int]:
        """Rows with a non-empty value in any field whose name contains term.

        Row-text lexical scoring in the AI evidence layer also matches query
        terms against field names (for example ``source_ip`` appearing in the
        serialized row). This keeps index-backed scoring behaviorally aligned
        with that path.
        """
        text = str(term or "").strip().lower()
        if len(text) < 2:
            return frozenset()
        cache_key = f"\x00field:{text}"
        cached = self._term_cache.get(cache_key)
        if cached is not None:
            return cached
        matched: set[int] = set()
        for field in self._search_fields:
            if text in field:
                for rows in self._field_values.get(field, {}).values():
                    matched.update(rows)
        result = frozenset(matched)
        self._term_cache[cache_key] = result
        return result

    def all_positions(self) -> range:
        return range(len(self._events))

    def distinct_values(self, field: str, limit: int | None = None) -> list[str]:
        field = str(field or "")
        cache_key = (field, limit)
        if field in self._field_distinct_cache and limit is None:
            return list(self._field_distinct_cache[field])
        if field not in self._field_values:
            return []
        values = sorted(self._field_values[field].keys(), key=lambda v: v.casefold())
        if limit is not None:
            values = values[:limit]
        if limit is None:
            self._field_distinct_cache[field] = list(values)
        return values

    def prefix_values(self, field: str, prefix: str, limit: int = 100) -> list[str]:
        field = str(field or "")
        prefix = self._norm(prefix)
        if not prefix:
            return self.distinct_values(field, limit)
        if field in self._prefix_index and prefix in self._prefix_index[field]:
            return sorted(self._prefix_index[field][prefix], key=lambda v: v.casefold())[:limit]
        if field in self._field_values:
            return sorted(
                [v for v in self._field_values[field] if v.startswith(prefix)],
                key=lambda v: v.casefold(),
            )[:limit]
        return []

    def timestamp_range(self, start: datetime, end: datetime) -> list[int]:
        if not self._sorted_timestamps:
            return []
        left = self._bisect_left(start)
        right = self._bisect_right(end)
        return [pos for _, pos in self._sorted_timestamps[left:right]]

    def _bisect_left(self, target: datetime) -> int:
        lo, hi = 0, len(self._sorted_timestamps)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._sorted_timestamps[mid][0] < target:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _bisect_right(self, target: datetime) -> int:
        lo, hi = 0, len(self._sorted_timestamps)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._sorted_timestamps[mid][0] <= target:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def facet_counts(self, field: str, positions: set[int] | None = None, limit: int = 50) -> dict[str, int]:
        field = str(field or "")
        cache_key = (field, frozenset(positions) if positions is not None else None)
        if cache_key in self._facet_cache:
            return dict(self._facet_cache[cache_key])
        if field not in self._field_values:
            return {}
        counts: dict[str, int] = {}
        for value, rows in self._field_values[field].items():
            if positions is not None:
                count = len(rows & positions)
            else:
                count = len(rows)
            if count > 0:
                counts[value] = count
        sorted_counts = dict(sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:limit])
        self._facet_cache[cache_key] = sorted_counts
        return sorted_counts

    def entity_lookup(self, entity_type: str, value: str) -> list[int]:
        entity_type = str(entity_type or "").lower()
        if entity_type not in self._entity_indexes:
            return []
        return sorted(self._entity_indexes[entity_type].get(self._norm(value), set()))

    def correlation_lookup(self, field: str, value: Any) -> list[int]:
        return self.exact(field, value)

    def get_event(self, position: int) -> dict[str, Any] | None:
        if 0 <= position < len(self._events):
            return self._events[position]
        return None

    def get_events(self, positions: list[int]) -> list[dict[str, Any]]:
        return [self._events[p] for p in positions if 0 <= p < len(self._events)]

    def intersect(self, *position_sets: set[int] | list[int]) -> list[int]:
        if not position_sets:
            return list(range(len(self._events)))
        sets = [set(s) for s in position_sets if s]
        if not sets:
            return list(range(len(self._events)))
        result = sets[0]
        for s in sets[1:]:
            result = result & s
        return sorted(result)

    def union(self, *position_sets: set[int] | list[int]) -> list[int]:
        if not position_sets:
            return []
        result: set[int] = set()
        for s in position_sets:
            result.update(s)
        return sorted(result)

    def complement(self, positions: set[int] | list[int]) -> list[int]:
        all_set = set(range(len(self._events)))
        return sorted(all_set - set(positions))

    def clear_caches(self) -> None:
        self._facet_cache.clear()
        self._field_distinct_cache.clear()
        self._term_cache.clear()


import re
