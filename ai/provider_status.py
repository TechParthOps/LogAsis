from __future__ import annotations

"""In-session AI provider availability state.

This module deliberately does not try to bypass provider quotas. A 429 is a
provider-side limit, so LogAsis records a short cooldown and prevents repeated
requests until that window expires. State is process-local and contains no API
keys or evidence.
"""

from dataclasses import dataclass
import time


@dataclass
class ProviderAvailability:
    available: bool = True
    reason: str = ""
    retry_after_seconds: float = 0.0
    checked_at: float = 0.0

    @property
    def remaining_seconds(self) -> int:
        if self.available:
            return 0
        return max(0, int(self.retry_after_seconds - (time.monotonic() - self.checked_at) + 0.999))

    @property
    def is_blocked(self) -> bool:
        return not self.available and self.remaining_seconds > 0


class ProviderStatusRegistry:
    def __init__(self, default_cooldown: float = 60.0):
        self.default_cooldown = max(1.0, float(default_cooldown))
        self._states: dict[str, ProviderAvailability] = {}

    def mark_rate_limited(self, provider: str, retry_after: str | None = None) -> ProviderAvailability:
        seconds = self._parse_retry_after(retry_after)
        if seconds is None:
            seconds = self.default_cooldown
        state = ProviderAvailability(
            available=False,
            reason="rate_limit",
            retry_after_seconds=seconds,
            checked_at=time.monotonic(),
        )
        self._states[self._key(provider)] = state
        return state

    def mark_available(self, provider: str) -> ProviderAvailability:
        state = ProviderAvailability(available=True, checked_at=time.monotonic())
        self._states[self._key(provider)] = state
        return state

    def clear(self, provider: str) -> None:
        self._states.pop(self._key(provider), None)

    def get(self, provider: str) -> ProviderAvailability:
        key = self._key(provider)
        state = self._states.get(key)
        if state is None:
            return ProviderAvailability(available=True, checked_at=time.monotonic())
        if not state.is_blocked and not state.available:
            # Cooldown elapsed: make the provider available for the next request.
            state.available = True
            state.reason = ""
            state.retry_after_seconds = 0.0
        return state

    def is_blocked(self, provider: str) -> bool:
        return self.get(provider).is_blocked

    @staticmethod
    def _key(provider: str) -> str:
        return str(provider or "").strip().lower()

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if value is None:
            return None
        try:
            seconds = float(str(value).strip())
            if seconds >= 0:
                return min(seconds, 3600.0)
        except (TypeError, ValueError):
            pass
        return None


_registry = ProviderStatusRegistry()


def get_provider_status(provider: str) -> ProviderAvailability:
    return _registry.get(provider)


def mark_provider_rate_limited(provider: str, retry_after: str | None = None) -> ProviderAvailability:
    return _registry.mark_rate_limited(provider, retry_after)


def mark_provider_available(provider: str) -> ProviderAvailability:
    return _registry.mark_available(provider)


def clear_provider_status(provider: str) -> None:
    _registry.clear(provider)
