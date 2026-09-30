"""
Groq explanation provider adapter (Phase 8A).

Uses the official Groq Python SDK with strict JSON Schema structured
outputs to produce ProviderDraft objects. Only transport lives here:
evidence assembly, prompt building, grounding validation, and fallback
all remain in backend/app/analysis/explanation.py.

No secrets are logged, returned, or embedded in exceptions.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from backend.app.services.explanation_provider import (
    ProviderDraft,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)

PROVIDER_NAME = "groq"
DEFAULT_MODEL = "openai/gpt-oss-120b"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 1

# Strict JSON Schema mirroring ProviderDraft. Every object sets
# additionalProperties: false and every field is required, per the
# strict structured-output contract.
DRAFT_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "statement": {"type": "string"},
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["statement", "evidence_refs"],
            "additionalProperties": False,
        },
        "key_factors": {
            "type": "array",
            "items": {"$ref": "#/$defs/claim"},
        },
        "impact": {
            "type": "array",
            "items": {"$ref": "#/$defs/claim"},
        },
        "changes": {
            "type": "array",
            "items": {"$ref": "#/$defs/claim"},
        },
        "limitations": {
            "type": "array",
            "items": {"$ref": "#/$defs/claim"},
        },
    },
    "required": ["summary", "key_factors", "impact", "changes", "limitations"],
    "additionalProperties": False,
    "$defs": {
        "claim": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["FACT", "INTERPRETATION", "LIMITATION"]},
                "statement": {"type": "string"},
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["type", "statement", "evidence_refs"],
            "additionalProperties": False,
        }
    },
}


def _is_retryable(exc: BaseException) -> bool:
    """Classify transport errors: retryable vs immediately fatal."""
    name = type(exc).__name__
    if "Timeout" in name or isinstance(exc, TimeoutError):
        return True
    if "RateLimit" in name:
        return True
    if "Connection" in name:
        return True
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and status >= 500:
        return True
    return False


def _is_auth_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    if "Authentication" in name or "PermissionDenied" in name:
        return True
    status = getattr(exc, "status_code", None)
    return status in (401, 403)


def _retry_after_seconds(exc: BaseException, timeout: float) -> float:
    """Honor Retry-After within the remaining timeout budget."""
    try:
        raw = None
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None) or getattr(exc, "headers", None) or {}
        for key in ("retry-after", "Retry-After"):
            if key in headers:
                raw = headers[key]
                break
        delay = float(raw) if raw is not None else 1.0
    except (TypeError, ValueError):
        delay = 1.0
    return max(0.0, min(delay, timeout))


class GroqExplanationProvider:
    """ExplanationProvider backed by the Groq chat completions API."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_url: Optional[str] = None,
        client: Any = None,
    ) -> None:
        if not api_key:
            raise ValueError("GroqExplanationProvider requires a non-empty API key")
        self._model = model
        self._timeout = timeout
        self._max_retries = max_retries
        if client is not None:
            self._client = client
        else:
            self._client = self._build_client(api_key, timeout, base_url)

    @staticmethod
    def _build_client(api_key: str, timeout: float, base_url: Optional[str]):
        try:
            from groq import Groq
        except ImportError as exc:
            raise ProviderError(
                "The 'groq' package is not installed; "
                "install it to use the Groq provider"
            ) from exc
        kwargs: Dict[str, Any] = {"api_key": api_key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url
        # Retries are managed explicitly by generate() per AI_MAX_RETRIES;
        # disable the SDK's own retry loop to keep behavior deterministic.
        kwargs["max_retries"] = 0
        return Groq(**kwargs)

    def _messages(self, prompt: Dict[str, Any]) -> List[Dict[str, str]]:
        system_text = (
            prompt.get("system_instructions", "")
            + "\n\n"
            + prompt.get("grounding_rules", "")
        )
        user_text = prompt.get("evidence_data", "")
        question = prompt.get("user_question")
        if question:
            user_text += "\n\n" + question
        return [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ]

    def _parse_draft(self, content: Any) -> ProviderDraft:
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("Groq returned an empty model response")
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProviderError("Groq returned malformed JSON output") from exc
        if not isinstance(data, dict):
            raise ProviderError("Groq returned a non-object structured output")
        try:
            return ProviderDraft(
                summary=data.get("summary", {}),
                key_factors=data.get("key_factors", []),
                impact=data.get("impact", []),
                changes=data.get("changes", []),
                limitations=data.get("limitations", []),
            )
        except Exception as exc:
            raise ProviderError("Groq returned an invalid draft structure") from exc

    def generate(self, prompt: Dict[str, Any]) -> ProviderDraft:
        """Call Groq with strict structured output; map errors to provider types."""
        messages = self._messages(prompt)
        attempts = 1 + max(0, int(self._max_retries))
        last_error: Optional[BaseException] = None
        for attempt in range(attempts):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "name": "explanation_draft",
                            "strict": True,
                            "schema": DRAFT_JSON_SCHEMA,
                        },
                    },
                )
                content = response.choices[0].message.content
                return self._parse_draft(content)
            except ProviderError:
                raise
            except Exception as exc:
                if _is_auth_error(exc):
                    raise ProviderError("Groq authentication failed") from exc
                last_error = exc
                if "RateLimit" in type(exc).__name__:
                    if attempt < attempts - 1:
                        time.sleep(_retry_after_seconds(exc, self._timeout))
                        continue
                    raise ProviderRateLimitError("Groq rate limit exceeded") from exc
                if "Timeout" in type(exc).__name__ or isinstance(exc, TimeoutError):
                    if attempt < attempts - 1:
                        continue
                    raise ProviderTimeoutError("Groq request timed out") from exc
                if _is_retryable(exc):
                    if attempt < attempts - 1:
                        continue
                    raise ProviderError("Groq service unavailable") from exc
                raise ProviderError("Groq request failed") from exc
        raise ProviderError("Groq request failed") from last_error
