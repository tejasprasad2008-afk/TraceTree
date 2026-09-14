from __future__ import annotations

import json

import pytest

from npm_adaptive.planner_providers import (
    HarnessPlannerProviderError,
    OllamaHarnessPlannerClient,
    OpenRouterHarnessPlannerClient,
    create_harness_planner_client,
)


class _Response:
    def __init__(self, payload, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


def _context():
    return {
        "schema_version": "tracetree.harness_plan.v1",
        "callable_exports": [{"entrypoint": "demo", "name": "probe", "parameters": []}],
        "profiles": [{"profile_id": "node-library-v1", "fixture_ids": [], "network_policy": "none"}],
    }


def test_ollama_client_uses_local_structured_chat_without_source(monkeypatch):
    captured = {}

    def _post(url, *, json, headers, timeout):
        captured.update(url=url, payload=json, headers=headers, timeout=timeout)
        return _Response({"message": {"content": '{"schema_version":"tracetree.harness_plan.v1"}'}})

    monkeypatch.setattr("npm_adaptive.planner_providers.requests.post", _post)
    client = OllamaHarnessPlannerClient(base_url="http://localhost:11434", model="test-model")

    response = client.propose_harness_plan(_context())

    assert response.startswith("{")
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["payload"]["stream"] is False
    assert captured["payload"]["format"]["additionalProperties"] is False
    assert "source" not in captured["payload"]["messages"][1]["content"]
    assert "trace_evidence" not in captured["payload"]["messages"][1]["content"]


def test_openrouter_client_uses_strict_schema_and_never_puts_key_in_prompt(monkeypatch):
    captured = {}

    def _post(url, *, json, headers, timeout):
        captured.update(url=url, payload=json, headers=headers, timeout=timeout)
        return _Response(
            {"choices": [{"message": {"content": json_module.dumps({"schema_version": "tracetree.harness_plan.v1"})}}]}
        )

    json_module = json
    monkeypatch.setattr("npm_adaptive.planner_providers.requests.post", _post)
    client = OpenRouterHarnessPlannerClient(api_key="test-openrouter-key", model="vendor/test-model")

    response = client.propose_harness_plan(_context())

    assert response == '{"schema_version": "tracetree.harness_plan.v1"}'
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["payload"]["response_format"]["json_schema"]["strict"] is True
    assert captured["headers"]["Authorization"] == "Bearer test-openrouter-key"
    assert "test-openrouter-key" not in captured["payload"]["messages"][1]["content"]


def test_provider_selection_and_endpoint_guards(monkeypatch):
    assert isinstance(create_harness_planner_client("ollama"), OllamaHarnessPlannerClient)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(HarnessPlannerProviderError, match="OPENROUTER_API_KEY"):
        OpenRouterHarnessPlannerClient(api_key="")
    monkeypatch.delenv("TRACETREE_OLLAMA_ALLOW_REMOTE", raising=False)
    with pytest.raises(HarnessPlannerProviderError, match="localhost"):
        OllamaHarnessPlannerClient(base_url="http://ollama.example.test:11434")
    with pytest.raises(HarnessPlannerProviderError, match="openrouter.ai"):
        OpenRouterHarnessPlannerClient(
            api_key="test-openrouter-key", base_url="https://unexpected.example.test"
        )
