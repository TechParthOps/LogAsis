from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pandas as pd

from ai.context import build_evidence_context, evidence_to_prompt


@dataclass(frozen=True)
class LargeLogPlan:
    event_count: int
    relevant_event_count: int
    prompt_chars: int
    chunk_count: int
    strategy: str
    max_events: int = 160


def _estimate_tokens(text: str) -> int:
    # Conservative English/log approximation. This is intentionally only a
    # planning metric; provider-side token accounting remains authoritative.
    return max(1, len(text) // 4)


def build_large_log_context(
    df: pd.DataFrame,
    question: str,
    *,
    max_events: int = 160,
    max_prompt_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a larger-but-bounded investigation context for AI analysis.

    The raw dataframe is never serialized wholesale. Deterministic analytics
    select the evidence that is useful for the question first.
    """
    context = build_evidence_context(df, question, max_events=max_events)
    prompt = evidence_to_prompt(context)
    estimated_tokens = _estimate_tokens(prompt)

    # Provider context limits must be enforced before the HTTP request.  The
    # previous implementation bounded event *count* but not serialized prompt
    # size, so a small number of verbose audit records could still exceed a
    # hosted model's context window. Rebuild the immutable bundle with a smaller
    # event budget until the complete prompt is comfortably inside the target.
    if max_prompt_tokens is not None and estimated_tokens > max_prompt_tokens:
        candidate_sizes = [
            min(max_events, 60), min(max_events, 45), min(max_events, 30),
            min(max_events, 20), min(max_events, 12), min(max_events, 8),
            min(max_events, 4), min(max_events, 2), min(max_events, 1),
        ]
        for candidate in dict.fromkeys(x for x in candidate_sizes if x > 0):
            if candidate >= max_events:
                continue
            # Tight prompt budgets should aggressively bound evidence count.
            # Four records is the conservative floor used for provider-facing
            # requests; token accounting is still checked below.
            if max_prompt_tokens <= 1000 and candidate > 4:
                continue
            candidate_context = build_evidence_context(df, question, max_events=candidate)
            candidate_prompt = evidence_to_prompt(candidate_context)
            candidate_tokens = _estimate_tokens(candidate_prompt)
            context, prompt, estimated_tokens = candidate_context, candidate_prompt, candidate_tokens
            if estimated_tokens <= max_prompt_tokens:
                break

    relevant_count = len(context.get("relevant_events", []))

    # Keep a conservative single-request ceiling for OpenAI-compatible
    # providers. Gemini's native File API can bypass this text ceiling.
    # Prompt size is not the only constraint. Local models often have much
    # smaller practical context windows than hosted models, so keep each
    # provider request bounded by evidence count as well as estimated tokens.
    if max_events <= 80 and relevant_count > 60:
        # Cloud/free-tier path: deliberately keep one request. The event
        # selection is already question-aware and ranked before this point.
        strategy = "question-aware-bounded"
        chunks = 1
    elif relevant_count <= 60:
        strategy = "bounded-evidence"
        chunks = 1
    else:
        strategy = "question-aware-chunks"
        chunks = max(2, (relevant_count + 59) // 60)

    relevant_events = list(context.get("relevant_events", []))
    chunk_size = 60
    if chunks <= 1:
        event_chunks = [relevant_events] if relevant_events else [[]]
    else:
        event_chunks = [relevant_events[i:i + chunk_size] for i in range(0, len(relevant_events), chunk_size)] or [[]]

    return {
        "context": context,
        "prompt": prompt,
        "estimated_tokens": estimated_tokens,
        "event_chunks": event_chunks,
        "plan": LargeLogPlan(
            event_count=int(len(df)),
            relevant_event_count=relevant_count,
            prompt_chars=len(prompt),
            chunk_count=chunks,
            strategy=strategy,
            max_events=max_events,
        ),
    }


def plan_summary(plan: LargeLogPlan) -> str:
    return (
        f"{plan.event_count:,} events • {plan.relevant_event_count:,} relevant evidence events • "
        f"{plan.strategy} • bounded to {plan.max_events:,} events"
    )
