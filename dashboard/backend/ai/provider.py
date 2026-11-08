"""OpenAI-compatible chat provider used by the AI features.

The provider is deliberately small and stdlib-only (``urllib``) so the optional
AI features add no runtime dependency to the core engine. It is provider-neutral:
any endpoint that speaks the OpenAI chat-completions shape works (OpenRouter,
Groq, Ollama, vLLM, OpenAI, ...).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from vibe_coding_qa.scanners import redact_secrets


class AIError(RuntimeError):
    """Raised when an AI call cannot be completed. Message is client-safe."""


@dataclass(frozen=True)
class AIConfig:
    provider: str
    api_key: str
    base_url: str
    model: str
    timeout: int
    max_output_tokens: int
    share_source_context: bool

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and self.provider.lower() not in ("", "none", "false", "0")


class ChatProvider:
    """Minimal OpenAI-compatible chat client."""

    MAX_RESPONSE_BYTES = 1_000_000
    MAX_OUTPUT_TOKENS = 16_000

    def __init__(self, config: AIConfig):
        self.config = config

    def complete(self, messages: list[dict], *, max_tokens: int | None = None, temperature: float = 0.2) -> str:
        if not self.config.enabled:
            raise AIError("No AI provider is configured.")
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": message["role"], "content": redact_secrets(str(message["content"]))}
                for message in messages
            ],
            "temperature": temperature,
            "max_tokens": min(
                max_tokens or self.config.max_output_tokens,
                self.MAX_OUTPUT_TOKENS,
            ),
        }
        request = urllib.request.Request(
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
                if len(raw) > self.MAX_RESPONSE_BYTES:
                    raise AIError("The AI provider response exceeded the size limit.")
                data = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise AIError(f"The AI provider rejected the request (HTTP {exc.code}).") from exc
        except urllib.error.URLError as exc:
            raise AIError(f"The AI provider could not be reached ({type(exc.reason).__name__}).") from exc
        except AIError:
            raise
        except (TimeoutError, OSError) as exc:
            raise AIError(f"The AI request failed ({type(exc).__name__}).") from exc
        except json.JSONDecodeError as exc:
            raise AIError("The AI provider returned an unreadable response.") from exc

        try:
            choices = data.get("choices") or []
            content = choices[0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise AIError("The AI provider returned no message content.") from exc
        return str(content or "").strip()

    def check(self) -> str:
        """Run a one-token round trip to confirm the configuration works."""
        reply = self.complete(
            [{"role": "user", "content": "Reply with the single word: ready"}],
            max_tokens=8,
            temperature=0.0,
        )
        return reply[:80]
