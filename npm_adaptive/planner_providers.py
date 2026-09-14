"""Concrete, least-privilege model clients for adaptive harness planning.

Both providers receive only the allowlisted planner context assembled by
``planner.request_validated_plan``. They return untrusted JSON which is then
validated against the package map and adaptive gate before it can be used.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

import requests

from .planner import HarnessPlannerClient, HarnessPlannerResponseError


_LOCAL_OLLAMA_HOSTS = {"localhost", "127.0.0.1", "::1"}
_MAX_CONTEXT_BYTES = 64 * 1024
_REQUEST_TIMEOUT_SECONDS = 45


class HarnessPlannerProviderError(RuntimeError):
    """Raised for safe, provider-neutral planner transport failures."""


class OllamaHarnessPlannerClient:
    """Local Ollama adapter using its structured-output chat endpoint."""

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = _REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        configured_url = base_url or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
        self.base_url = _validate_ollama_base_url(configured_url)
        self.model = model or os.getenv("OLLAMA_MODEL") or "qwen2.5-coder:7b"
        self.timeout_seconds = _validate_timeout(timeout_seconds)

    def propose_harness_plan(self, context: Mapping[str, Any]) -> str:
        response_schema = harness_plan_json_schema()
        prompt = _planner_prompt(context, response_schema)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a non-executing npm harness planner. Return only one JSON "
                        "object matching the supplied schema. Never return markdown, source code, "
                        "shell commands, paths, credentials, environment variables, or network requests."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": response_schema,
            # A validated harness plan is intentionally tiny. Keeping this
            # tightly bounded avoids slow local generations and gratuitous
            # context use, including a possible single repair pass.
            "options": {"temperature": 0, "num_predict": 128},
        }
        response = _post_json(
            f"{self.base_url}/api/chat",
            payload,
            {"Content-Type": "application/json"},
            self.timeout_seconds,
            provider="Ollama",
        )
        message = response.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise HarnessPlannerResponseError("Ollama response did not contain message.content")
        return content


class OpenRouterHarnessPlannerClient:
    """OpenRouter adapter using non-streaming strict structured output."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = _REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY") or ""
        if not self.api_key:
            raise HarnessPlannerProviderError("OPENROUTER_API_KEY is required for the OpenRouter planner")
        configured_url = base_url or os.getenv("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
        self.base_url = _validate_openrouter_base_url(configured_url)
        self.model = model or os.getenv("OPENROUTER_MODEL") or "qwen/qwen3-coder"
        self.timeout_seconds = _validate_timeout(timeout_seconds)

    def propose_harness_plan(self, context: Mapping[str, Any]) -> str:
        response_schema = harness_plan_json_schema()
        prompt = _planner_prompt(context, response_schema)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a non-executing npm harness planner. Return only a JSON object "
                        "that conforms to the required schema. Do not return markdown, source code, "
                        "shell commands, paths, credentials, environment variables, or network requests."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "temperature": 0,
            "max_completion_tokens": 1024,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "tracetree_harness_plan",
                    "strict": True,
                    "schema": response_schema,
                },
            },
        }
        response = _post_json(
            f"{self.base_url}/chat/completions",
            payload,
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "X-OpenRouter-Title": "TraceTree adaptive planner",
            },
            self.timeout_seconds,
            provider="OpenRouter",
        )
        choices = response.get("choices")
        first = choices[0] if isinstance(choices, list) and choices else None
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise HarnessPlannerResponseError("OpenRouter response did not contain choices[0].message.content")
        return content


def create_harness_planner_client(provider: str) -> HarnessPlannerClient:
    """Create an explicitly selected provider; no model call occurs here."""

    selected = provider.strip().lower()
    if selected == "ollama":
        return OllamaHarnessPlannerClient()
    if selected == "openrouter":
        return OpenRouterHarnessPlannerClient()
    raise HarnessPlannerProviderError("planner provider must be ollama or openrouter")


def harness_plan_json_schema() -> Dict[str, Any]:
    """Static response shape; dynamic package facts are checked after parsing."""

    action_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "entrypoint": {"type": "string"},
            "loader": {"type": "string", "enum": ["import", "require"]},
            "export_name": {"type": "string"},
            "operation": {"type": "string", "const": "call"},
            "fixtures": {"type": "array", "items": {"type": "string"}, "maxItems": 4},
            "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 5000},
        },
        "required": ["entrypoint", "loader", "export_name", "operation", "fixtures", "timeout_ms"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string", "const": "tracetree.harness_plan.v1"},
            "profile_id": {"type": "string"},
            "attempt_budget": {"type": "integer", "minimum": 1, "maximum": 3},
            "actions": {"type": "array", "minItems": 1, "maxItems": 10, "items": action_schema},
        },
        "required": ["schema_version", "profile_id", "attempt_budget", "actions"],
    }


def _planner_prompt(context: Mapping[str, Any], response_schema: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(context, sort_keys=True, separators=(",", ":"))
        schema = json.dumps(response_schema, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise HarnessPlannerResponseError("planner context is not JSON serialisable") from exc
    if len(encoded.encode("utf-8")) > _MAX_CONTEXT_BYTES:
        raise HarnessPlannerResponseError("planner context exceeds 64 KiB")
    return (
        "Choose the smallest useful direct-call HarnessPlan using only the allowlisted "
        "entrypoints, callable exports, profiles, and fixture IDs in this context.\n"
        "For a function with statically listed parameters, supply no more fixtures than "
        "its parameter count. Use no fixtures for a zero-parameter function.\n"
        "RESPONSE_SCHEMA:\n"
        f"{schema}\n"
        "CONTEXT:\n"
        f"{encoded}"
    )


def _post_json(
    url: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout_seconds: float,
    *,
    provider: str,
) -> Dict[str, Any]:
    try:
        response = requests.post(url, json=dict(payload), headers=dict(headers), timeout=timeout_seconds)
    except requests.RequestException as exc:
        raise HarnessPlannerProviderError(f"{provider} planner request failed") from exc
    if response.status_code != 200:
        raise HarnessPlannerProviderError(
            f"{provider} planner returned HTTP {response.status_code}"
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise HarnessPlannerResponseError(f"{provider} planner response was not JSON") from exc
    if not isinstance(body, dict):
        raise HarnessPlannerResponseError(f"{provider} planner response was not an object")
    return body


def _validate_ollama_base_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HarnessPlannerProviderError("OLLAMA_BASE_URL must be an absolute HTTP(S) URL")
    allow_remote = os.getenv("TRACETREE_OLLAMA_ALLOW_REMOTE", "").strip() == "1"
    if parsed.hostname not in _LOCAL_OLLAMA_HOSTS and not allow_remote:
        raise HarnessPlannerProviderError(
            "OLLAMA_BASE_URL must use localhost unless TRACETREE_OLLAMA_ALLOW_REMOTE=1"
        )
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise HarnessPlannerProviderError("OLLAMA_BASE_URL must be an origin without a path or query")
    return normalized


def _validate_openrouter_base_url(value: str) -> str:
    normalized = value.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme != "https" or not parsed.hostname:
        raise HarnessPlannerProviderError("OPENROUTER_BASE_URL must be an HTTPS URL")
    allowed = parsed.hostname == "openrouter.ai"
    allow_custom = os.getenv("TRACETREE_OPENROUTER_ALLOW_CUSTOM_BASE_URL", "").strip() == "1"
    if not allowed and not allow_custom:
        raise HarnessPlannerProviderError(
            "OPENROUTER_BASE_URL must use openrouter.ai unless TRACETREE_OPENROUTER_ALLOW_CUSTOM_BASE_URL=1"
        )
    if parsed.params or parsed.query or parsed.fragment:
        raise HarnessPlannerProviderError("OPENROUTER_BASE_URL must not contain query or fragment data")
    return normalized


def _validate_timeout(value: float) -> float:
    if not 1 <= value <= 120:
        raise ValueError("planner timeout must be between 1 and 120 seconds")
    return value
