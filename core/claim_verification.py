"""Claim-level verification and coverage tracking for LogAsis.

Every final answer is decomposed into claims. Each claim has evidence IDs,
support status, contradiction status, confidence, and claim type.

Claim types: VERIFIED_FACT, GROUNDED_INTERPRETATION, HYPOTHESIS, UNSUPPORTED
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.event_index import EventIndex


@dataclass
class Claim:
    text: str
    claim_type: str = "UNSUPPORTED"
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "LOW"
    support_status: str = "UNVERIFIED"
    contradiction: bool = False
    contradiction_evidence: list[str] = field(default_factory=list)


class ClaimVerifier:
    """Verify claims against indexed evidence."""

    VERIFIED_FACT = "VERIFIED_FACT"
    GROUNDED_INTERPRETATION = "GROUNDED_INTERPRETATION"
    HYPOTHESIS = "HYPOTHESIS"
    UNSUPPORTED = "UNSUPPORTED"

    _CONFIDENCE_LEVELS = {"HIGH", "MODERATE", "LOW"}

    def __init__(self, index: EventIndex):
        self.index = index

    def verify_claim(self, text: str, evidence_ids: list[str]) -> Claim:
        claim = Claim(text=text, evidence_ids=list(evidence_ids))

        if not evidence_ids:
            claim.claim_type = self.UNSUPPORTED
            claim.support_status = "NO_EVIDENCE"
            return claim

        events = []
        for evid in evidence_ids:
            pos = self._evid_to_position(evid)
            if pos is not None:
                event = self.index.get_event(pos)
                if event:
                    events.append(event)

        if not events:
            claim.claim_type = self.UNSUPPORTED
            claim.support_status = "EVIDENCE_NOT_FOUND"
            return claim

        claim.support_status = "EVIDENCE_FOUND"

        text_lower = text.lower()
        has_interpretation_language = any(
            word in text_lower
            for word in ("likely", "possibly", "suggests", "consistent with", "may have", "could be", "appears to", "warrants")
        )
        has_certainty_language = any(
            word in text_lower
            for word in ("is", "was", "were", "confirmed", "established", "observed", "found")
        )

        if has_interpretation_language and not has_certainty_language:
            claim.claim_type = self.GROUNDED_INTERPRETATION
            claim.confidence = "MODERATE"
        elif has_certainty_language:
            claim.claim_type = self.VERIFIED_FACT
            claim.confidence = "HIGH" if len(events) >= 2 else "MODERATE"
        else:
            claim.claim_type = self.GROUNDED_INTERPRETATION
            claim.confidence = "LOW"

        return claim

    def verify_answer(self, answer_text: str, evidence_ids: list[str]) -> dict[str, Any]:
        claims = self._extract_claims(answer_text)
        verified_claims = []
        for claim_text, claim_evids in claims:
            claim = self.verify_claim(claim_text, claim_evids or evidence_ids)
            verified_claims.append(claim)

        unsupported = [c for c in verified_claims if c.claim_type == self.UNSUPPORTED]
        verified = [c for c in verified_claims if c.claim_type == self.VERIFIED_FACT]
        interpretations = [c for c in verified_claims if c.claim_type == self.GROUNDED_INTERPRETATION]

        return {
            "claims": [
                {
                    "text": c.text,
                    "type": c.claim_type,
                    "evidence_ids": c.evidence_ids,
                    "confidence": c.confidence,
                    "support_status": c.support_status,
                    "contradiction": c.contradiction,
                }
                for c in verified_claims
            ],
            "verified_count": len(verified),
            "interpretation_count": len(interpretations),
            "unsupported_count": len(unsupported),
            "all_grounded": len(unsupported) == 0,
        }

    def _extract_claims(self, text: str) -> list[tuple[str, list[str]]]:
        claims = []
        current_evidence: list[str] = []

        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue

            evid_match = re.findall(r"\[EVID-\d+\]", line)
            current_evidence.extend(evid_match)

            cleaned = re.sub(r"\[EVID-\d+\]", "", line).strip()
            cleaned = re.sub(r"^[-*•]\s*", "", cleaned)
            cleaned = re.sub(r"^\d+[.)]\s*", "", cleaned)

            if len(cleaned) > 10:
                claims.append((cleaned, list(current_evidence)))
                current_evidence = []

        if not claims and text.strip():
            claims.append((text.strip()[:200], []))

        return claims

    @staticmethod
    def _evid_to_position(evid: str) -> int | None:
        match = re.fullmatch(r"EVID-(\d{1,6})", str(evid).strip().upper())
        if match:
            return int(match.group(1)) - 1
        return None


class CoverageTracker:
    """Track analysis coverage for every answer."""

    def __init__(self, index: EventIndex):
        self.index = index

    def compute(
        self,
        candidate_positions: set[int] | None = None,
        retrieved_positions: set[int] | None = None,
        correlated_positions: set[int] | None = None,
    ) -> dict[str, Any]:
        total = self.index.size
        candidate_count = len(candidate_positions) if candidate_positions is not None else total
        retrieved_count = len(retrieved_positions) if retrieved_positions is not None else 0
        correlated_count = len(correlated_positions) if correlated_positions is not None else 0

        if candidate_positions is None:
            status = "COMPLETE"
        elif candidate_count >= total * 0.99:
            status = "COMPLETE"
        elif candidate_count >= total * 0.5:
            status = "TARGETED"
        elif candidate_count > 0:
            status = "PARTIAL"
        else:
            status = "UNKNOWN"

        return {
            "total_events": total,
            "indexed_events": total,
            "candidate_events": candidate_count,
            "retrieved_events": retrieved_count,
            "correlated_events": correlated_count,
            "excluded_events": total - candidate_count,
            "coverage_status": status,
            "coverage_ratio": round(candidate_count / max(1, total), 4),
        }
