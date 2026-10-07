from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any
from datetime import date, datetime, time

def sha256_file(path: str|Path, chunk_size: int=1024*1024) -> str:
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        while chunk:=f.read(chunk_size): h.update(chunk)
    return h.hexdigest()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8",errors="replace")).hexdigest()

def _json_default(value: Any):
    """Canonical JSON representation for non-JSON-native evidence values."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    # pandas.Timestamp and similar datetime-like objects expose isoformat().
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        default=_json_default,
    )


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))

def build_evidence_manifest(source_file: str|Path, events: list[dict[str,Any]], evidence: list[dict[str,Any]]|None=None) -> dict[str,Any]:
    p=Path(source_file)
    manifest={"source_file":str(p),"source_sha256":sha256_file(p) if p.exists() else "",
              "event_count":len(events),"event_set_sha256":sha256_json(events),
              "evidence_count":len(evidence or []),"evidence_set_sha256":sha256_json(evidence or [])}
    return manifest
