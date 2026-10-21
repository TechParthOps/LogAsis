"""Tests for the AI investigation runtime: tools, coverage, malformed
provider responses, provider failures, and the full agent pipeline."""

from __future__ import annotations

import pytest

from ai.agent import LogInvestigatorAgent
from ai.investigation_agent import (
    AgenticInvestigationRuntime,
    InvestigationToolLayer,
    COMPLETED_SUFFICIENT,
    PARTIAL,
)
from core.log_dataset import LogDataset
from tests.conftest import FakeProvider


@pytest.fixture
def dataset(auth_like_events):
    return LogDataset(auth_like_events, source_file="sim.jsonl")


@pytest.fixture
def tools(dataset):
    return InvestigationToolLayer(dataset.df, event_index=dataset.event_index)


class TestCountEventsTool:
    def test_exact_count_never_sampled(self, tools):
        out = tools.count_events(action="failed_login")
        assert out["exact_count"] == 6
        assert out["exhaustive"] is True
        assert out["dataset_size"] == 11

    def test_count_with_query_and_filters(self, tools):
        out = tools.count_events(query="SSH authentication failed", action="failed_login")
        assert out["exact_count"] == 6

    def test_count_zero_is_exact(self, tools):
        out = tools.count_events(source_ip="192.0.2.99")
        assert out["exact_count"] == 0
        assert out["exhaustive"] is True


class TestInvestigationRuntime:
    def test_coverage_and_completion_accounted(self, dataset):
        provider = FakeProvider(responses=[
            '{"action":"count_events","arguments":{"action":"failed_login"},"reason":"count failures"}',
            '{"action":"finish","arguments":{},"reason":"sufficient"}',
        ])
        runtime = AgenticInvestigationRuntime(provider, max_steps=4, max_tool_calls=8)
        answer, report = runtime.run("How many failed logins from 198.51.100.23?", dataset.df, dataset=dataset)
        assert report["completion_status"] == COMPLETED_SUFFICIENT
        assert report["coverage"]["total_events"] == 11
        assert report["coverage"]["coverage_status"] == "COMPLETE"
        assert report["deterministic_counts"], "count_events results must be recorded"
        assert report["deterministic_counts"][-1]["exact_count"] == 6

    def test_budget_exhaustion_is_partial_not_complete(self, dataset):
        provider = FakeProvider(responses=[
            '{"action":"search_events","arguments":{"query":"failed"},"reason":"looking"}',
        ])
        runtime = AgenticInvestigationRuntime(provider, max_steps=1, max_tool_calls=8)
        _, report = runtime.run("Investigate the activity", dataset.df, dataset=dataset)
        assert report["completion_status"] == PARTIAL
        assert "maximum" in report["termination_reason"]

    def test_unparseable_planner_response_fails_explicitly(self, dataset):
        provider = FakeProvider(responses=["not json at all", "still not json", "nope", "nope"])
        runtime = AgenticInvestigationRuntime(provider, max_steps=2, max_tool_calls=8)
        _, report = runtime.run("Investigate", dataset.df, dataset=dataset)
        # A planner/provider failure is a FAILED investigation, never a
        # silently 'completed' one.
        assert report["completion_status"] == PARTIAL or report["completion_status"] == "FAILED"
        assert report["completion_status"] == "FAILED"
        assert any("investigation plan" in q.lower() for q in report["unresolved_questions"])

    def test_provider_timeout_propagates(self, dataset):
        provider = FakeProvider(fail_after=0)
        runtime = AgenticInvestigationRuntime(provider, max_steps=2, max_tool_calls=8)
        with pytest.raises(TimeoutError):
            runtime.run("Investigate", dataset.df, dataset=dataset)


class TestAgentPipeline:
    def test_deterministic_question_needs_no_provider(self, dataset):
        agent = LogInvestigatorAgent(provider=None)
        answer = agent.answer(
            "How many failed SSH authentication attempts came from 198.51.100.23?",
            dataset.df, dataset=dataset,
        )
        assert "There are 6 matching events" in answer
        assert "EVID & GROUNDING" in answer.upper() or "EVIDENCE & GROUNDING" in answer
        assert "DETERMINISTIC" in answer.upper()

    def test_deterministic_answer_with_provider_still_skips_provider(self, dataset):
        provider = FakeProvider()
        agent = LogInvestigatorAgent(provider)
        answer = agent.answer(
            "How many failed logins came from 198.51.100.23?", dataset.df, dataset=dataset
        )
        assert provider.calls == []  # no provider round-trips
        assert "6" in answer

    def test_fabricated_evidence_id_never_rendered_as_fact(self, dataset):
        provider = FakeProvider(responses=[
            '{"action":"finish","arguments":{},"reason":"done"}',
            json_dumps({
                "overall_assessment": "Assessment complete.",
                "claims": [
                    {"text": "The attacker used IP 203.0.113.99.", "type": "VERIFIED_FACT",
                     "evidence_references": ["EVID-999"], "confidence": "HIGH"},
                ],
                "limitations": [], "next_steps": [],
            }),
        ])
        agent = LogInvestigatorAgent(provider)
        # A causality question with no resolvable observation sets routes to
        # the AI runtime; the fabricated citation must be rejected there.
        # (Risk-story summaries ARE answered deterministically since the
        # incident-profile upgrade, so they no longer exercise this path.)
        answer = agent.answer("Why did the attacker target this server?", dataset.df, dataset=dataset)
        assert "REJECTED AI CLAIMS" in answer or "UNKNOWN EVIDENCE" in answer.upper()


def json_dumps(obj):
    import json

    return json.dumps(obj)


class TestConversationContext:
    def test_context_resolves_this_source(self, dataset):
        agent = LogInvestigatorAgent(provider=None)
        first = agent.answer(
            "How many blocked events came from 203.0.113.5?", dataset.df, dataset=dataset
        )
        assert "3" in first
        follow_up = agent.answer(
            "How many events involved this source?", dataset.df, dataset=dataset,
            conversation_context=["How many blocked events came from 203.0.113.5?"],
        )
        assert follow_up is not None
        assert "3" in follow_up
