from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class WorkspaceSessionStore:
    """Persistent UI/session preferences, separate from crash recovery.

    This file contains navigation and filter state only. It is never used as
    evidence, findings, case conclusions, or analysis output.
    """

    SCHEMA_VERSION = 1

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "workspace_session.json"

    def save(self, state: dict[str, Any]) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "saved_at": time.time(),
            "state": dict(state),
        }
        fd, tmp_name = tempfile.mkstemp(prefix=".session-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        finally:
            try:
                Path(tmp_name).unlink()
            except FileNotFoundError:
                pass

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("schema_version") != self.SCHEMA_VERSION:
                return None
            state = payload.get("state")
            return dict(state) if isinstance(state, dict) else None
        except (OSError, ValueError, TypeError):
            return None

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
