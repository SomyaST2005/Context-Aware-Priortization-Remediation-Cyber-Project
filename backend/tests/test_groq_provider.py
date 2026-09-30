"""
Tests for the Groq explanation provider adapter (Phase 8A).

No live network calls. The Groq SDK client is replaced with scripted
fakes injected through the provider constructor. No credentials exist
anywhere in this file.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from backend.app.services import explanation_provider as provider_mod
from backend.app.services.explanation_provider import (
    ProviderDraft,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)
from backend.app.services.groq_provider import GroqExplanationProvider

from backend.app.core.config import settings


VALID_DRAFT = {
    "summary": {"statement": "Ranked 1 with score 2.5.", "evidence_refs": ["E1"]},
    "key_factors": [
        {"type": "FACT", "statement": "Participates in 2 paths.", "evidence_refs": ["E2"]}
    ],
    "impact": [],
    "changes": [],
    "limitations": [],
}


class FakeTimeoutError(Exception):
    """Name contains 'Timeout' so the adapter classifies it as a timeout."""


class FakeRateLimitError(Exception):
    """Name contains 'RateLimit' so the adapter classifies it as rate limited."""

    def __init__(self):
        self.status_code = 429
        self.response = SimpleNamespace(headers={"retry-after": "0"})


class FakeAuthenticationError(Exception):
    """Mirrors groq.AuthenticationError: fatal, never retried."""

    def __init__(self, message="bad key"):
        super().__init__(message)
        self.status_code = 401


class FakeConnectionError(Exception):
    """Name contains 'Connection' so the adapter treats it as retryable."""


class FakeServerError(Exception):
    def __init__(self):
        self.status_code = 500


class FakeCompletions:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


class FakeChat:
    def __init__(self, script):
        self.completions = FakeCompletions(script)


class FakeGroqClient:
    def __init__(self, script):
        self.chat = FakeChat(script)


def make_response(content):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def make_provider(script, **kwargs):
    params = {
        "api_key": "test-key",
        "model": "openai/gpt-oss-120b",
        "timeout": 5.0,
        "max_retries": 1,
    }
    params.update(kwargs)
    return (
        GroqExplanationProvider(client=FakeGroqClient(script), **params),
        params,
    )


def test_successful_completion_and_draft_conversion():
    provider, _ = make_provider([make_response(json.dumps(VALID_DRAFT))])
    draft = provider.generate(
        {
            "system_instructions": "sys",
            "grounding_rules": "rules",
            "evidence_data": "data",
            "user_question": None,
        }
    )
    assert isinstance(draft, ProviderDraft)
    assert draft.summary["statement"].startswith("Ranked 1")
    assert draft.key_factors[0]["type"] == "FACT"


def test_configured_model_passed_to_sdk():
    provider, _ = make_provider(
        [make_response(json.dumps(VALID_DRAFT))], model="openai/gpt-oss-20b"
    )
    prompt = {
        "system_instructions": "sys",
        "grounding_rules": "rules",
        "evidence_data": "data",
        "user_question": None,
    }
    provider.generate(prompt)
    assert provider._model == "openai/gpt-oss-20b"


def test_strict_json_schema_requested():
    provider, _ = make_provider([make_response(json.dumps(VALID_DRAFT))])
    captured = provider._client.chat.completions
    provider.generate(
        {
            "system_instructions": "sys",
            "grounding_rules": "rules",
            "evidence_data": "data",
            "user_question": None,
        }
    )
    kwargs = captured.calls[0]
    assert kwargs["model"] == "openai/gpt-oss-120b"
    fmt = kwargs["response_format"]
    assert fmt["type"] == "json_schema"
    assert fmt["json_schema"]["strict"] is True
    schema = fmt["json_schema"]["schema"]
    assert schema["type"] == "object"
    assert "summary" in schema["properties"]
    assert "key_factors" in schema["properties"]


def test_prompt_messages_passed():
    provider, _ = make_provider([make_response(json.dumps(VALID_DRAFT))])
    captured = provider._client.chat.completions
    provider.generate(
        {
            "system_instructions": "SYS",
            "grounding_rules": "RULES",
            "evidence_data": "EVIDENCE",
            "user_question": "Q",
        }
    )
    messages = captured.calls[0]["messages"]
    assert messages[0]["role"] == "system"
    assert "SYS" in messages[0]["content"]
    assert "RULES" in messages[0]["content"]
    assert messages[1]["role"] == "user"
    assert "EVIDENCE" in messages[1]["content"]
    assert "Q" in messages[1]["content"]


def test_malformed_response_handling():
    provider, _ = make_provider([make_response("not json{{{")])
    with pytest.raises(ProviderError):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )


def test_empty_response_handling():
    provider, _ = make_provider([make_response("   ")])
    with pytest.raises(ProviderError):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )


def test_auth_failure_no_retry():
    provider, _ = make_provider([FakeAuthenticationError("bad key")])
    captured = provider._client.chat.completions
    with pytest.raises(ProviderError, match="authentication"):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )
    assert len(captured.calls) == 1


def test_timeout_handling():
    provider, _ = make_provider(
        [FakeTimeoutError("slow"), FakeTimeoutError("slow")], max_retries=1
    )
    with pytest.raises(ProviderTimeoutError):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )


def test_rate_limit_handling():
    provider, _ = make_provider(
        [FakeRateLimitError(), FakeRateLimitError()], max_retries=1
    )
    with pytest.raises(ProviderRateLimitError):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )


def test_connection_failure_retried():
    provider, _ = make_provider(
        [FakeConnectionError("down"), make_response(json.dumps(VALID_DRAFT))],
        max_retries=1,
    )
    captured = provider._client.chat.completions
    draft = provider.generate(
        {
            "system_instructions": "s",
            "grounding_rules": "g",
            "evidence_data": "e",
            "user_question": None,
        }
    )
    assert draft.summary["statement"].startswith("Ranked 1")
    assert len(captured.calls) == 2


def test_server_error_retried_then_success():
    provider, _ = make_provider(
        [FakeServerError(), make_response(json.dumps(VALID_DRAFT))], max_retries=1
    )
    draft = provider.generate(
        {
            "system_instructions": "s",
            "grounding_rules": "g",
            "evidence_data": "e",
            "user_question": None,
        }
    )
    assert isinstance(draft, ProviderDraft)


def test_retry_then_success():
    provider, _ = make_provider(
        [FakeTimeoutError("slow"), make_response(json.dumps(VALID_DRAFT))],
        max_retries=1,
    )
    captured = provider._client.chat.completions
    draft = provider.generate(
        {
            "system_instructions": "s",
            "grounding_rules": "g",
            "evidence_data": "e",
            "user_question": None,
        }
    )
    assert isinstance(draft, ProviderDraft)
    assert len(captured.calls) == 2


def test_retry_exhaustion():
    provider, _ = make_provider(
        [FakeTimeoutError("s"), FakeTimeoutError("s"), FakeTimeoutError("s")],
        max_retries=1,
    )
    captured = provider._client.chat.completions
    with pytest.raises(ProviderTimeoutError):
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )
    assert len(captured.calls) == 2


def test_missing_api_key_rejected_at_construction():
    with pytest.raises(ValueError, match="non-empty API key"):
        GroqExplanationProvider(api_key="")


def test_missing_key_selects_fallback(monkeypatch):
    monkeypatch.setattr(provider_mod, "_default_provider", None)
    monkeypatch.setattr(settings, "AI_PROVIDER", "groq")
    monkeypatch.setattr(settings, "GROQ_API_KEY", "")
    assert isinstance(
        provider_mod.get_default_provider(),
        provider_mod.DeterministicFallbackProvider,
    )


def _minimal_finding_payload():
    return {
        "finding_id": "finding-01",
        "asset_id": "asset-web-01",
        "vulnerability_id": "vuln-1",
        "cvss_normalized": 0.98,
        "epss_score": 0.85,
        "epss_available": True,
        "known_exploited": True,
        "severity_category": "CRITICAL",
        "path_participation_count": 2,
        "max_path_feasibility": 0.45,
        "max_path_feasibility_normalized": 0.31,
        "avg_path_feasibility": 0.3,
        "crown_jewel_reachable": True,
        "unique_entry_points": 1,
        "unique_crown_jewels": 1,
        "min_path_depth": 2,
        "max_path_depth": 4,
        "asset_criticality_normalized": 0.78,
        "is_entry_point": True,
        "is_crown_jewel": False,
        "blast_radius_asset_count": 3,
        "blast_radius_crown_jewels": 1,
        "blast_radius_max_depth": 4,
        "blast_radius_min_cost": 1.0,
        "blast_radius_max_prob": 0.9,
        "finding_chokepoint_score": 1.0,
        "finding_path_feasibility_criticality": 0.75,
        "finding_path_count": 2,
        "asset_chokepoint_score": 0.5,
        "asset_path_feasibility_criticality": 0.45,
        "asset_path_count": 2,
        "remediation_cost": 5.0,
        "implementation_complexity": "LOW",
        "downtime_required": False,
        "action_type": None,
        "baseline_is_entry_point": None,
        "operational_rank": 1,
        "operational_score": 2.5,
        "ordering_tiers": [0, 0, 0],
        "tiebreaker": "finding-01",
    }


def _minimal_finding_result():
    from backend.app.analysis import explanation as ex_mod

    profile = _minimal_finding_payload()
    return {
        "profile": profile,
        "operational_rank": 1,
        "ordering_keys": {
            "tiers": [0, 0, 0],
            "composite_score": 2.5,
            "tiebreaker": "finding-01",
            "finding_id": "finding-01",
            "asset_id": "asset-web-01",
        },
        "operational_score": 2.5,
        "evidence": {},
        "scenario_id": "s1",
        "computed_at": "2026-09-30T00:00:00+00:00",
    }


def test_provider_selection_groq(monkeypatch):
    import backend.app.services.groq_provider as groq_mod

    created = {}

    class StubProvider:
        def __init__(self, **kwargs):
            created.update(kwargs)

        def generate(self, prompt):
            raise AssertionError("must not be called in selection test")

    monkeypatch.setattr(groq_mod, "GroqExplanationProvider", StubProvider)
    monkeypatch.setattr(provider_mod, "_default_provider", None)
    monkeypatch.setattr(settings, "AI_PROVIDER", "groq")
    monkeypatch.setattr(settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(settings, "AI_MODEL", "openai/gpt-oss-120b")
    provider = provider_mod.get_default_provider()
    assert isinstance(provider, StubProvider)
    assert created["api_key"] == "test-key"
    assert created["model"] == "openai/gpt-oss-120b"
    assert "test-key" != created.get("model")


def test_unknown_provider_fails_closed(monkeypatch):
    monkeypatch.setattr(provider_mod, "_default_provider", None)
    monkeypatch.setattr(settings, "AI_PROVIDER", "bogus-vendor")
    with pytest.raises(ValueError, match="Unknown AI_PROVIDER"):
        provider_mod.get_default_provider()


def test_api_key_not_logged_or_returned(caplog):
    import logging

    provider, _ = make_provider([make_response(json.dumps(VALID_DRAFT))])
    with caplog.at_level(logging.DEBUG):
        draft = provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )
    assert "test-key" not in caplog.text
    assert "test-key" not in json.dumps(draft.to_dict())


def test_api_key_not_in_errors():
    provider, _ = make_provider([FakeAuthenticationError("bad")])
    try:
        provider.generate(
            {
                "system_instructions": "s",
                "grounding_rules": "g",
                "evidence_data": "e",
                "user_question": None,
            }
        )
        raise AssertionError("expected ProviderError")
    except ProviderError as exc:
        assert "test-key" not in str(exc)


def test_deterministic_result_survives_provider_failure():
    # Orchestration-level: a failing Groq-shaped provider yields UNAVAILABLE
    # while deterministic evidence stays intact (uses real assembler).
    from backend.app.analysis import explanation as ex_mod

    assembled = ex_mod.assemble_finding_evidence(_minimal_finding_result())

    class FailingGroqLike:
        def generate(self, prompt):
            raise ProviderTimeoutError("slow")

    explanation, status, origin = ex_mod.explain_with_provider(
        assembled, FailingGroqLike(), None
    )
    assert status == "UNAVAILABLE"
    assert origin == "none"
    assert explanation["key_factors"] == []


def test_fallback_still_works():
    from backend.app.analysis import explanation as ex_mod

    assembled = ex_mod.assemble_finding_evidence(_minimal_finding_result())
    provider = provider_mod.DeterministicFallbackProvider()
    explanation, status, origin = ex_mod.explain_with_provider(
        assembled, provider, None
    )
    assert status == "FALLBACK"
    assert origin == "fallback-template"
    assert explanation["summary"]["statement"]
