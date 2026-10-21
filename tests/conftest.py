"""Shared fixtures for the LogAsis test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.log_dataset import LogDataset  # noqa: E402

BENCHMARK_DIR = Path(r"E:\LogAsis_AI_Analyst_Benchmark")


def make_events(spec: list[dict]) -> pd.DataFrame:
    """Build a normalized DataFrame from raw event dicts (as the parser would)."""
    from core.analytics import events_to_dataframe

    return events_to_dataframe(spec)


@pytest.fixture
def auth_like_events() -> pd.DataFrame:
    """Small authentication-style dataset mirroring benchmark structure."""
    events = []
    # 6 failed logins from an attacker IP
    for i in range(1, 7):
        events.append({
            "event_uid": f"SIM-A-{i:04d}",
            "timestamp": f"2026-09-15T08:{i:02d}:00Z",
            "event_type": "authentication",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.20.1.10",
            "destination_port": "22",
            "user": "svc_backup",
            "process": "",
            "action": "failed_login",
            "severity": "medium",
            "host": "linux-auth-01",
            "message": "SSH authentication failed for invalid or supplied credentials",
            "auth_method": "ssh",
        })
    # 2 successful logins after the failures
    for i in range(1, 3):
        events.append({
            "event_uid": f"SIM-B-{i:04d}",
            "timestamp": f"2026-09-15T09:{i:02d}:00Z",
            "event_type": "authentication",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.20.1.10",
            "destination_port": "22",
            "user": "svc_backup",
            "process": "",
            "action": "successful_login",
            "severity": "low",
            "host": "linux-auth-01",
            "message": "SSH authentication succeeded",
            "auth_method": "ssh",
        })
    # 3 unrelated events from a benign IP (custom vendor field present)
    for i in range(1, 4):
        events.append({
            "event_uid": f"SIM-N-{i:04d}",
            "timestamp": f"2026-09-15T10:{i:02d}:00Z",
            "event_type": "web_access",
            "source_ip": "203.0.113.5",
            "destination_ip": "10.20.2.15",
            "destination_port": "443",
            "user": "analyst",
            "process": "nginx",
            "action": "allowed",
            "severity": "low",
            "host": "web-prod-01",
            "message": "Routine request",
            "custom_vendor_field": f"value-{i}",
        })
    return make_events(events)


@pytest.fixture
def auth_dataset(auth_like_events) -> LogDataset:
    return LogDataset(auth_like_events, source_file="sim_auth.jsonl")


class FakeProvider:
    """Deterministic scripted provider for pipeline tests."""

    name = "FakeProvider"
    model = "fake-model"
    base_url = "http://localhost"
    supports_agentic_investigation = True
    supports_chunked_synthesis = False

    def __init__(self, responses: list[str] | None = None, fail_after: int | None = None):
        self.responses = list(responses or [])
        self.calls: list[tuple[str, str]] = []
        self.fail_after = fail_after
        self._count = 0

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append((system_prompt[:80], user_prompt[:200]))
        self._count += 1
        if self.fail_after is not None and self._count > self.fail_after:
            raise TimeoutError("simulated provider timeout")
        if self.responses:
            return self.responses.pop(0)
        return "finish"

    def generate_with_progress(self, system_prompt: str, user_prompt: str, progress_callback=None):
        return self.generate(system_prompt, user_prompt)


@pytest.fixture
def fake_provider():
    return FakeProvider()


def skip_without_benchmark():
    return pytest.mark.skipif(not BENCHMARK_DIR.exists(), reason="benchmark corpus not available")
