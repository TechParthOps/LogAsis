"""Retrieval cache for LogAsis.

Caches retrieval results by (dataset_id, query, parameters, index_version).
Invalidates automatically when the dataset changes.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any


class RetrievalCache:
    """Cache for evidence retrieval results.

    Key: (dataset_id, normalized_query, parameters_hash, index_version)
    Value: {records, trace, timestamp}

    Entries are invalidated when the dataset_id changes (new log loaded).
    """

    def __init__(self, max_entries: int = 128):
        self._cache: dict[str, dict[str, Any]] = {}
        self._max_entries = max(1, int(max_entries))
        self._dataset_id: str | None = None
        self._hits = 0
        self._misses = 0

    def _key(self, dataset_id: str, query: str, params: dict[str, Any] | None = None) -> str:
        normalized_query = " ".join(str(query or "").lower().split())
        param_str = json.dumps(params or {}, sort_keys=True, default=str)
        raw = f"{dataset_id}|{normalized_query}|{param_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(
        self,
        dataset_id: str,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if self._dataset_id != dataset_id:
            self.clear()
            self._dataset_id = dataset_id
        key = self._key(dataset_id, query, params)
        entry = self._cache.get(key)
        if entry is not None:
            self._hits += 1
            return entry
        self._misses += 1
        return None

    def put(
        self,
        dataset_id: str,
        query: str,
        result: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> None:
        if self._dataset_id != dataset_id:
            self.clear()
            self._dataset_id = dataset_id
        key = self._key(dataset_id, query, params)
        self._cache[key] = {
            "records": result.get("records", []),
            "trace": result.get("trace", {}),
            "timestamp": time.time(),
        }
        while len(self._cache) > self._max_entries:
            oldest_key = min(self._cache, key=lambda k: self._cache[k]["timestamp"])
            self._cache.pop(oldest_key)

    def clear(self) -> None:
        self._cache.clear()
        self._dataset_id = None

    @property
    def stats(self) -> dict[str, int]:
        return {
            "hits": self._hits,
            "misses": self._misses,
            "size": len(self._cache),
            "hit_rate": round(self._hits / max(1, self._hits + self._misses), 4),
        }
