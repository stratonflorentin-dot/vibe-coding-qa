"""Describes the configured AI provider/model and its capabilities.

The existing :class:`ChatProvider` already speaks the OpenAI chat-completions
shape, which OpenRouter, OpenAI, Groq, Ollama and vLLM all expose — so one HTTP
client serves every adapter kind and the registry's job is to *label* the
configured endpoint and advertise capabilities, never to duplicate transport.

It never returns the API key or any secret: only the provider kind, a safe
host, the model id, capability flags and configuration/health status.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable
from urllib.parse import urlsplit

from ..ai.provider import AIConfig


class Capability(str, Enum):
    CHAT = "chat"
    CODE = "code"
    REASONING = "reasoning"
    STRUCTURED_OUTPUT = "structured_output"


#: Substring heuristics for capability inference from a model id. Conservative:
#: unknown models are assumed chat-only until proven otherwise.
_REASONING_HINTS = ("gpt-4", "gpt-5", "o1", "o3", "o4", "claude", "opus", "sonnet", "deepseek-r", "r1", "reason", "qwen2.5", "llama-3.1-70", "llama-3.3")
_CODE_HINTS = ("code", "coder", "codestral", "deepseek", "qwen", "claude", "gpt-4", "gpt-5", "devstral")
_STRUCTURED_HINTS = ("gpt-4", "gpt-5", "o1", "o3", "claude", "opus", "sonnet", "mistral", "qwen")


def _adapter_kind(base_url: str) -> str:
    host = urlsplit(base_url or "").netloc.lower()
    if "11434" in host or "ollama" in host:
        return "ollama"
    if "8000" in host or "vllm" in host:
        return "vllm"
    return "openai_compatible"


def _safe_host(base_url: str) -> str:
    parts = urlsplit(base_url or "")
    return parts.netloc or "(unset)"


def capabilities_for(model: str) -> set[Capability]:
    name = (model or "").lower()
    caps = {Capability.CHAT}
    if any(h in name for h in _REASONING_HINTS):
        caps.add(Capability.REASONING)
    if any(h in name for h in _CODE_HINTS):
        caps.add(Capability.CODE)
    if any(h in name for h in _STRUCTURED_HINTS):
        caps.add(Capability.STRUCTURED_OUTPUT)
    return caps


class ModelRegistry:
    """Read-only view of the configured provider/model, secrets stripped."""

    def __init__(self, config_provider: Callable[[], AIConfig]):
        self._config = config_provider

    def _entry(self) -> dict:
        cfg = self._config()
        caps = sorted(c.value for c in capabilities_for(cfg.model)) if cfg.model else []
        return {
            "provider_id": (cfg.provider or "").lower() or "unconfigured",
            "provider_name": cfg.provider or "Not configured",
            "adapter_kind": _adapter_kind(cfg.base_url),
            "host": _safe_host(cfg.base_url),  # host only — never the key
            "model_id": cfg.model,
            "capabilities": caps,
            # context window is not reliably known across providers; left null
            # rather than guessed.
            "context_window": None,
            "structured_output": Capability.STRUCTURED_OUTPUT.value in caps,
            "configured": cfg.enabled,
            "timeout_seconds": cfg.timeout,
        }

    def providers(self) -> list[dict]:
        entry = self._entry()
        return [{
            "id": entry["provider_id"],
            "name": entry["provider_name"],
            "adapter_kind": entry["adapter_kind"],
            "host": entry["host"],
            "configured": entry["configured"],
            "supported_adapters": ["openai_compatible", "ollama", "vllm"],
        }]

    def models(self) -> list[dict]:
        entry = self._entry()
        if not entry["model_id"]:
            return []
        return [{
            "provider_id": entry["provider_id"],
            "model_id": entry["model_id"],
            "capabilities": entry["capabilities"],
            "structured_output": entry["structured_output"],
            "context_window": entry["context_window"],
            "configured": entry["configured"],
        }]

    def is_configured(self) -> bool:
        return self._config().enabled

    def model_capabilities(self) -> set[Capability]:
        cfg = self._config()
        return capabilities_for(cfg.model) if cfg.enabled else set()


__all__ = ["Capability", "ModelRegistry", "capabilities_for"]
