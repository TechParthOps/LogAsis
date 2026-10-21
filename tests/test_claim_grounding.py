"""Tests for claim grounding: fabricated citations, unsupported claims,
contradictions, causal claims, and count corroboration."""

from __future__ import annotations

import json

import pytest

from ai.claim_grounding import normalize_provider_analysis
from ai.evidence_grounding import extract_evidence_ids


def _ctx(claims_records=12, deterministic_counts=None):
    records = [
        {
            "evidence_id": f"EVID-{i:03d}",
            "text": (
                f"failed_login from 198.51.100.23 user=svc_backup auth_method=ssh "
                f"event_type=authentication [{i}]"
            ),
        }
        for i in range(1, claims_records + 1)
    ]
    return {
        "evidence_records": records,
        "retrieval": {"evidence_ids": [r["evidence_id"] for r in records]},
        "deterministic_counts": deterministic_counts or [],
        "auto_cite_uncited_claims": False,
    }


def _run(answer_obj, context):
    return normalize_provider_analysis(json.dumps(answer_obj), context)


class TestFabricatedCitations:
    def test_unknown_evidence_id_rejected(self):
        out = _run(
            {"claims": [{"text": "The attacker used 198.51.100.23.", "type": "VERIFIED_FACT",
                          "evidence_references": ["EVID-999"]}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"
        assert "Unknown evidence reference" in out["claims"][0]["reason"]

    def test_extract_evidence_ids_normalizes(self):
        assert extract_evidence_ids("see [evid-7] and EVID-12") == ["EVID-007", "EVID-012"]


class TestUnsupportedClaims:
    def test_failed_auth_does_not_prove_compromise(self):
        out = _run(
            {"claims": [{"text": "The account svc_backup was compromised by the attacker.",
                          "type": "VERIFIED_FACT", "evidence_references": ["EVID-001"]}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"

    def test_blocked_connection_does_not_prove_exfiltration(self):
        records = [{"evidence_id": "EVID-001", "text": "blocked outbound connection to 192.0.2.91 bytes_sent=0"}]
        ctx = {"evidence_records": records, "retrieval": {"evidence_ids": ["EVID-001"]},
               "deterministic_counts": [], "auto_cite_uncited_claims": False}
        out = _run(
            {"claims": [{"text": "This proves data exfiltration to 192.0.2.91 succeeded.",
                          "type": "VERIFIED_FACT", "evidence_references": ["EVID-001"]}]},
            ctx,
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"

    def test_sudo_use_alone_does_not_prove_privilege_escalation(self):
        records = [{"evidence_id": "EVID-001", "text": "sudo command executed user=deploy uid=1000 command=ls"}]
        ctx = {"evidence_records": records, "retrieval": {"evidence_ids": ["EVID-001"]},
               "deterministic_counts": [], "auto_cite_uncited_claims": False}
        out = _run(
            {"claims": [{"text": "The user escalated privileges to root.", "type": "VERIFIED_FACT",
                          "evidence_references": ["EVID-001"]}]},
            ctx,
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"

    def test_cve_in_log_does_not_prove_exploitation(self):
        records = [{"evidence_id": "EVID-001", "text": "scanner report mentions CVE-2026-1234 in banner"}]
        ctx = {"evidence_records": records, "retrieval": {"evidence_ids": ["EVID-001"]},
               "deterministic_counts": [], "auto_cite_uncited_claims": False}
        out = _run(
            {"claims": [{"text": "CVE-2026-1234 was exploited successfully.", "type": "VERIFIED_FACT",
                          "evidence_references": ["EVID-001"]}]},
            ctx,
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"

    def test_claim_without_citations_rejected(self):
        out = _run(
            {"claims": [{"text": "Something happened on the network.", "type": "VERIFIED_FACT",
                          "evidence_references": []}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"


class TestContradictions:
    def test_success_claim_contradicted_by_failed_evidence(self):
        records = [{"evidence_id": "EVID-001", "text": "failed_login user=amy res=failed"}]
        ctx = {"evidence_records": records, "retrieval": {"evidence_ids": ["EVID-001"]},
               "deterministic_counts": [], "auto_cite_uncited_claims": False}
        out = _run(
            {"claims": [{"text": "A successful login was observed for amy.", "type": "VERIFIED_FACT",
                          "evidence_references": ["EVID-001"]}]},
            ctx,
        )
        assert out["claims"][0]["type"] == "CONTRADICTED_CLAIM"


class TestDeterministicCountCorroboration:
    def test_true_dataset_count_accepted_beyond_bundle_sample(self):
        # The bundle holds 12 records but the deterministic query found 45;
        # the true dataset-level claim must be accepted, not rejected.
        counts = [{"query": "failed_login 198.51.100.23", "exact_count": 45, "dataset_size": 2500}]
        out = _run(
            {"claims": [{"text": "There are 45 failed logins from 198.51.100.23.",
                          "type": "VERIFIED_FACT", "evidence_references": ["EVID-001"]}]},
            _ctx(deterministic_counts=counts),
        )
        assert out["claims"][0]["type"] == "VERIFIED_FACT"

    def test_contradicted_dataset_count_rejected(self):
        counts = [{"query": "failed_login 198.51.100.23", "exact_count": 45, "dataset_size": 2500}]
        out = _run(
            {"claims": [{"text": "There are 900 failed logins from 198.51.100.23.",
                          "type": "VERIFIED_FACT", "evidence_references": ["EVID-001"]}]},
            _ctx(deterministic_counts=counts),
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"
        assert "deterministic full-dataset query" in out["claims"][0]["reason"]


class TestCausalGuard:
    def test_causal_claim_without_linkage_rejected(self):
        out = _run(
            {"claims": [{"text": "The failed logins caused the later successful login.",
                          "type": "GROUNDED_INTERPRETATION", "evidence_references": ["EVID-001"]}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] == "UNSUPPORTED_CLAIM"
        assert "causal" in out["claims"][0]["reason"]

    def test_negated_causal_statement_allowed(self):
        out = _run(
            {"claims": [{"text": "Temporal proximity does not establish that one event caused the other.",
                          "type": "GROUNDED_INTERPRETATION", "evidence_references": ["EVID-001"]}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] != "UNSUPPORTED_CLAIM"


class TestHypothesisClass:
    def test_hypothesis_preserved_as_distinct_type(self):
        out = _run(
            {"claims": [{"text": "A hypothesis is that the activity was an automated scanner.",
                          "type": "HYPOTHESIS", "evidence_references": ["EVID-001"]}]},
            _ctx(),
        )
        assert out["claims"][0]["type"] == "HYPOTHESIS"
        assert out["claims"][0]["validation_status"] == "ACCEPTED_AS_INTERPRETATION"


class TestClaimVerificationModule:
    def test_is_word_no_longer_promotes_to_fact(self):
        from core.event_index import EventIndex
        from core.claim_verification import ClaimVerifier

        idx = EventIndex([{"message": "analysis of this histogram was performed", "action": "info"}])
        verifier = ClaimVerifier(idx)
        claim = verifier.verify_claim("This analysis was performed and observed.", ["EVID-001"])
        # "is"/"was" substrings must no longer classify the claim as a
        # HIGH-confidence verified fact without concrete support.
        assert claim.claim_type != "VERIFIED_FACT" or claim.confidence != "HIGH"

    def test_concrete_supported_claim_verified(self):
        from core.event_index import EventIndex
        from core.claim_verification import ClaimVerifier

        idx = EventIndex([{"message": "failed login from 198.51.100.23 user=svc_backup"}])
        verifier = ClaimVerifier(idx)
        claim = verifier.verify_claim("Failed login from 198.51.100.23 for user=svc_backup.", ["EVID-001"])
        assert claim.claim_type == "VERIFIED_FACT"
