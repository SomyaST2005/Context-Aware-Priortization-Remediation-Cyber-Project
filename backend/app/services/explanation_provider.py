"""
Explanation provider abstraction (Phase 8, services layer).

Application boundary:

    Application
        ↓
    ExplanationProvider.generate(structured_prompt)
        ↓
    structured ProviderDraft
        ↓
    schema validation + grounding validation (analysis layer)
        ↓
    ExplanationResponse

No vendor-specific implementation lives here in the MVP. Tests use
scripted fakes; production defaults to the deterministic fallback path
assembled without any model call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


class ProviderError(Exception):
    """Base class for provider failures (unavailable, timeouts, rate limits)."""


class ProviderTimeoutError(ProviderError):
    """The provider did not respond in time."""


class ProviderRateLimitError(ProviderError):
    """The provider refused the request due to rate limiting."""


@dataclass
class ProviderDraft:
    """Structured draft returned by a provider (model or scripted fake)."""

    summary: Dict[str, Any]
    key_factors: List[Dict[str, Any]] = field(default_factory=list)
    impact: List[Dict[str, Any]] = field(default_factory=list)
    changes: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "key_factors": list(self.key_factors),
            "impact": list(self.impact),
            "changes": list(self.changes),
            "limitations": list(self.limitations),
        }


class ExplanationProvider(Protocol):
    """Replaceable provider interface. Server-side configuration only."""

    def generate(self, prompt: Dict[str, Any]) -> ProviderDraft:
        """Generate a structured draft from a structured prompt."""
        ...  # pragma: no cover


class DeterministicFallbackProvider:
    """Fallback path: renders deterministic claims without any model call."""

    def __init__(self, renderer: Any = None) -> None:
        self._renderer = renderer

    def generate(self, prompt: Dict[str, Any]) -> ProviderDraft:
        raise ProviderError(
            "DeterministicFallbackProvider does not generate model drafts; "
            "use render_fallback() instead"
        )


class ScriptedFakeProvider:
    """Test-only scripted provider. No network access."""

    def __init__(
        self,
        draft: Optional[ProviderDraft] = None,
        error: Optional[Exception] = None,
    ) -> None:
        self._draft = draft
        self._error = error
        self.calls: List[Dict[str, Any]] = []

    def generate(self, prompt: Dict[str, Any]) -> ProviderDraft:
        self.calls.append(prompt)
        if self._error is not None:
            raise self._error
        if self._draft is None:
            raise ProviderError("ScriptedFakeProvider has no draft configured")
        return self._draft


_default_provider: Optional[ExplanationProvider] = None


def get_default_provider() -> ExplanationProvider:
    """Return the configured provider (server-side configuration only).

    Selection is driven by Settings: AI_PROVIDER chooses the adapter,
    provider-specific keys authorize it. Missing credentials fall back to
    the deterministic path; unknown provider names fail closed.
    """
    if _default_provider is not None:
        return _default_provider
    from backend.app.core.config import settings

    name = str(getattr(settings, "AI_PROVIDER", "none") or "none").lower()
    if name == "groq":
        api_key = str(getattr(settings, "GROQ_API_KEY", "") or "")
        if not api_key:
            return DeterministicFallbackProvider()
        try:
            from backend.app.services.groq_provider import GroqExplanationProvider
        except ImportError:
            # Optional AI dependency absent: analysis stays usable via fallback.
            return DeterministicFallbackProvider()
        try:
            return GroqExplanationProvider(
                api_key=api_key,
                model=str(getattr(settings, "AI_MODEL", "") or "openai/gpt-oss-120b"),
                timeout=float(getattr(settings, "AI_TIMEOUT_SECONDS", 30.0)),
                max_retries=int(getattr(settings, "AI_MAX_RETRIES", 1)),
                base_url=str(getattr(settings, "AI_BASE_URL", "") or "") or None,
            )
        except ImportError:
            # The 'groq' package is not installed: fall back, never break analysis.
            return DeterministicFallbackProvider()
    if name in ("openai", "gemini"):
        raise ValueError(
            f"AI provider '{name}' is not implemented yet; "
            "configure AI_PROVIDER=groq or AI_PROVIDER=none"
        )
    if name == "none":
        return DeterministicFallbackProvider()
    raise ValueError(
        f"Unknown AI_PROVIDER '{name}'; expected one of groq, openai, gemini, none"
    )


def set_default_provider(provider: Optional[ExplanationProvider]) -> None:
    """Override the configured provider (used by tests and server setup)."""
    global _default_provider
    _default_provider = provider
