"""Optional AI-assisted review provider interface.

The core scanner works without an AI provider. When VCQA_AI_PROVIDER and
VCQA_AI_API_KEY are configured, the engine can ask a compatible API for
additional context on selected findings.
"""

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from . import Finding


class AIProvider(ABC):
    @abstractmethod
    def review(self, finding: Finding, context_lines: list[str] | None = None) -> dict[str, Any]:
        """Return an explanation and remediation hints for a finding."""

    @abstractmethod
    def name(self) -> str:
        """Provider identifier for reports."""


class NullAIProvider(AIProvider):
    def name(self) -> str:
        return "none"

    def review(self, finding: Finding, context_lines: list[str] | None = None) -> dict[str, Any]:
        return {
            "provider": self.name(),
            "enabled": False,
            "note": "AI review is not configured.",
        }


class OpenRouterAIProvider(AIProvider):
    """Provider for OpenRouter, Groq, or any OpenAI-compatible chat endpoint."""

    def __init__(self, api_key: str, base_url: str = "https://openrouter.ai/api/v1", model: str = "openai/gpt-3.5-turbo", timeout: int = 30):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def name(self) -> str:
        return f"openrouter-compatible:{self.model}"

    def review(self, finding: Finding, context_lines: list[str] | None = None) -> dict[str, Any]:
        snippet = "\n".join(context_lines) if context_lines else ""
        prompt = (
            f"You are a senior security engineer reviewing a static-analysis finding.\n\n"
            f"Rule: {finding.rule}\n"
            f"Severity: {finding.severity.value}\n"
            f"File: {finding.file}:{finding.line}\n"
            f"Message: {finding.message}\n"
            f"Suggestion: {finding.suggestion}\n"
            f"Code context:\n{snippet}\n\n"
            f"Explain why this matters, identify the likely root cause, and suggest a targeted code change. Keep it concise."
        )
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {
                "provider": self.name(),
                "enabled": True,
                "rule": finding.rule,
                "file": str(finding.file),
                "line": finding.line,
                "explanation": content,
            }
        except urllib.error.HTTPError as exc:
            return {
                "provider": self.name(),
                "enabled": True,
                "error": f"HTTP {exc.code}: {exc.reason}",
            }
        except Exception as exc:
            return {
                "provider": self.name(),
                "enabled": True,
                "error": str(exc),
            }


def get_ai_provider() -> AIProvider:
    provider = os.environ.get("VCQA_AI_PROVIDER", "").lower()
    if provider in ("", "none", "false", "0"):
        return NullAIProvider()
    api_key = os.environ.get("VCQA_AI_API_KEY")
    if not api_key:
        return NullAIProvider()
    base_url = os.environ.get("VCQA_AI_BASE_URL", "https://openrouter.ai/api/v1")
    model = os.environ.get("VCQA_AI_MODEL", "openai/gpt-3.5-turbo")
    return OpenRouterAIProvider(api_key=api_key, base_url=base_url, model=model)


def review_findings(repo: Path, findings: list[Finding], provider: AIProvider | None = None) -> list[dict[str, Any]]:
    if provider is None:
        provider = get_ai_provider()
    if isinstance(provider, NullAIProvider):
        return []
    reviews: list[dict[str, Any]] = []
    for finding in findings:
        if finding.severity.value not in ("critical", "high"):
            continue
        context: list[str] = []
        file_path = repo / finding.file
        if file_path.is_file():
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                start = max(0, finding.line - 4)
                end = min(len(lines), finding.line + 3)
                context = lines[start:end]
            except Exception:
                pass
        reviews.append(provider.review(finding, context))
    return reviews
