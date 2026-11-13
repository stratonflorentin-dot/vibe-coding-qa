"""The Vibe Intelligence Gateway.

Central coordinator: it validates a task contract, resolves and authorises the
target project, prepares the minimum redacted context, routes to a deterministic
handler or an AI model, executes, records task + model-execution metadata, and
returns a structured result. It is an abstraction over the existing AI
capabilities, not a replacement — and it never applies code or deploys anything;
that stays in the controlled remediation + release-gate workflows.
"""

from __future__ import annotations

import time

from ..ai.provider import ChatProvider
from ..ai.service import AIService
from ..config import Settings
from ..persistence.store import Store
from .context_engine import ContextEngine, PreparedContext
from .contracts import (
    Confidence,
    ExecutionKind,
    IntelligenceRequest,
    IntelligenceResult,
    Operation,
    REQUIRED_FIELDS,
    TaskStatus,
)
from .exceptions import IntelligenceError, InvalidTaskError, ProjectNotFoundError
from .handlers import HANDLERS, HandlerContext, HandlerOutput
from .model_registry import ModelRegistry
from .router import RouteDecision, Router
from .tool_broker import ToolBroker


class IntelligenceGateway:
    def __init__(self, store: Store, ai_service: AIService, settings: Settings):
        self.store = store
        self.ai = ai_service
        self.settings = settings
        self.registry = ModelRegistry(ai_service.config)
        self.router = Router(self.registry)
        self.context = ContextEngine(store)
        self.tools = ToolBroker(store, ai_service)

    # ----------------------------------------------------------------- public
    def execute(self, request: IntelligenceRequest, *, user: dict) -> IntelligenceResult:
        operation = request.operation
        self._validate_required(request)
        repository = self._resolve_repository(request)
        task = self.store.create_intelligence_task(
            # The synthetic operator (open/credential mode) has id 0, which is
            # not a real users row; store NULL rather than violate the FK.
            user_id=user.get("id") or None,
            project_id=repository["id"] if repository else None,
            operation=operation.value,
        )
        task_id = task["id"]
        started = time.monotonic()
        try:
            prepared = self.context.prepare(request, repository) if repository else PreparedContext()
            decision = self.router.route(operation)
            if not decision.available:
                latency = int((time.monotonic() - started) * 1000)
                self.store.record_model_execution(task_id=task_id, provider_id=None, model_id=None,
                    execution_status=TaskStatus.UNAVAILABLE.value, latency_ms=latency, fallback_used=False)
                self.store.complete_intelligence_task(task_id, status=TaskStatus.UNAVAILABLE.value)
                return self._unavailable(task_id, operation, decision, latency)

            provider = ChatProvider(self.ai.config()) if decision.execution_kind is ExecutionKind.AI else None
            hc = HandlerContext(
                store=self.store, ai=self.ai, provider=provider, prepared=prepared,
                request=request, repository=repository, route=decision,
                broker=self.tools, user=user, task_id=task_id,
            )
            output: HandlerOutput = HANDLERS[operation](hc)
            latency = int((time.monotonic() - started) * 1000)

            cfg = self.ai.config()
            used_ai = decision.execution_kind is ExecutionKind.AI and not output.fallback_used
            self.store.record_model_execution(
                task_id=task_id,
                provider_id=(cfg.provider or None) if used_ai else None,
                model_id=(cfg.model or None) if used_ai else None,
                execution_status=output.status.value,
                latency_ms=latency,
                fallback_used=output.fallback_used,
            )
            self.store.complete_intelligence_task(task_id, status=output.status.value)
            return self._envelope(task_id, operation, decision, output, latency, used_ai)
        except IntelligenceError as exc:
            self.store.complete_intelligence_task(task_id, status=TaskStatus.FAILED.value, error_code=exc.code)
            raise
        except Exception as exc:  # noqa: BLE001 - never leak internals
            self.store.complete_intelligence_task(task_id, status=TaskStatus.FAILED.value, error_code="internal_error")
            raise IntelligenceError("The intelligence task failed unexpectedly.", code="internal_error") from exc

    def health(self) -> dict:
        task_count = self.store.db.query_one("SELECT COUNT(*) AS count FROM intelligence_tasks")["count"]
        execution_count = self.store.db.query_one("SELECT COUNT(*) AS count FROM model_executions")["count"]
        return {
            "configured": self.registry.is_configured(),
            "providers": len(self.registry.providers()),
            "models": len(self.registry.models()),
            "tasks": task_count,
            "model_executions": execution_count,
            "operations": [op.value for op in Operation if op is not Operation.ASSISTANT_CHAT],
        }

    def providers(self) -> list[dict]:
        return self.registry.providers()

    def models(self) -> list[dict]:
        return self.registry.models()

    def get_task(self, task_id: int) -> dict | None:
        return self.store.get_intelligence_task(task_id)

    # --------------------------------------------------------------- internals
    def _validate_required(self, request: IntelligenceRequest) -> None:
        missing = [field for field in REQUIRED_FIELDS[request.operation] if getattr(request, field) is None]
        if missing:
            raise InvalidTaskError(
                f"Operation '{request.operation.value}' requires: {', '.join(missing)}."
            )

    def _resolve_repository(self, request: IntelligenceRequest) -> dict | None:
        if request.repository_id is not None:
            repo = self.store.get_repository(request.repository_id)
            if repo is None:
                raise ProjectNotFoundError(f"Repository {request.repository_id} was not found.")
            return repo
        if request.finding_id is not None:
            finding = self.store.get_finding(request.finding_id)
            if finding is None:
                raise InvalidTaskError(f"Finding {request.finding_id} was not found.")
            repo = self.store.get_repository(finding["repository_id"])
            if repo is None:
                raise ProjectNotFoundError("The finding's repository was not found.")
            return repo
        for scan_id in (request.head_scan_id, request.scan_id):
            if scan_id is not None:
                scan = self.store.get_scan(scan_id)
                if scan is None:
                    raise InvalidTaskError(f"Scan {scan_id} was not found.")
                repo = self.store.get_repository(scan["repository_id"])
                if repo is None:
                    raise ProjectNotFoundError("The scan's repository was not found.")
                return repo
        return None

    def _envelope(
        self, task_id: int, operation: Operation, decision: RouteDecision,
        output: HandlerOutput, latency: int, used_ai: bool,
    ) -> IntelligenceResult:
        cfg = self.ai.config()
        limitations = list(dict.fromkeys(output.limitations + list(decision.notes)))
        return IntelligenceResult(
            task_id=task_id,
            operation=operation,
            status=output.status,
            execution_kind=decision.execution_kind,
            confidence=output.confidence,
            summary=output.summary,
            data=output.data,
            evidence=output.evidence,
            limitations=limitations,
            provider=(cfg.provider or None) if used_ai else None,
            model=(cfg.model or None) if used_ai else None,
            fallback_used=output.fallback_used,
            latency_ms=latency,
        )

    def _unavailable(self, task_id: int, operation: Operation, decision: RouteDecision, latency: int) -> IntelligenceResult:
        return IntelligenceResult(
            task_id=task_id,
            operation=operation,
            status=TaskStatus.UNAVAILABLE,
            execution_kind=ExecutionKind.AI,
            confidence=Confidence.UNKNOWN,
            summary="This operation needs an AI provider, which is not configured.",
            limitations=list(decision.notes) or ["No AI provider is configured."],
            latency_ms=latency,
        )


__all__ = ["IntelligenceGateway"]
