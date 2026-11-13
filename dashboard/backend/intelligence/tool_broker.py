"""Policy checked access to existing dashboard capabilities only.

The broker has no shell, arbitrary URL, or generic function execution tool.
It validates an explicit allow list and records metadata without arguments or
results, which may contain untrusted repository content.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..accounts import Role, role_at_least
from ..ai.service import AIService
from ..persistence.store import Store
from ..services.intel import build_architecture, build_dependencies
from ..security import ValidationError


@dataclass(frozen=True)
class ToolSpec:
    minimum_role: Role
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()


class ToolBroker:
    """Broker for bounded analysis and existing remediation workflows."""
    SPECS = {
        "architecture": ToolSpec(Role.VIEWER, ("repository_id",)),
        "dependencies": ToolSpec(Role.VIEWER, ("repository_id",), ("osv",)),
        "scan_results": ToolSpec(Role.VIEWER, ("scan_id",)),
        "propose_remediation": ToolSpec(Role.SECURITY_ANALYST, ("finding_id",)),
        "approve_remediation": ToolSpec(Role.ADMINISTRATOR, ("proposal_id", "confirm"), ("run_tests", "explicit_permission")),
    }

    def __init__(self, store: Store, ai: AIService):
        self.store, self.ai = store, ai

    def call(self, name: str, arguments: dict[str, Any], *, user: dict, task_id: int | None = None) -> dict:
        spec = self.SPECS.get(name)
        args = arguments if isinstance(arguments, dict) else {}
        status = "rejected"
        try:
            if spec is None:
                raise ValueError("Unknown intelligence tool.")
            if not isinstance(arguments, dict) or set(arguments) - set(spec.required) - set(spec.optional):
                raise ValueError("Invalid tool arguments.")
            if any(key not in arguments for key in spec.required):
                raise ValueError("Missing required tool arguments.")
            if not role_at_least(user.get("role", "viewer"), spec.minimum_role):
                raise PermissionError("Caller is not permitted to use this tool.")
            args = self._validate(name, arguments)
            result = self._execute(name, args)
            status = "completed"
            return {"tool": name, "status": status, "result": result}
        except Exception:
            if status != "rejected":
                status = "failed"
            raise
        finally:
            # Keep audit records free of potentially sensitive/untrusted values.
            names = ",".join(sorted(args))
            self.store.record_intelligence_tool_call(task_id=task_id, user_id=user.get("id") or None,
                tool_name=name, argument_names=names, status=status)
            self.store.add_audit(action="intelligence_tool", user_id=user.get("id") or None,
                                 username=user.get("username"), target=name,
                                 detail=f"status={status}; argument_names={names}")

    def _validate(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        result = dict(args)
        ids = {"repository_id", "scan_id", "finding_id", "proposal_id"}
        for key in ids & result.keys():
            if isinstance(result[key], bool) or not isinstance(result[key], int) or result[key] < 1:
                raise ValueError("Tool identifiers must be positive integers.")
        for key in ("osv", "confirm", "run_tests", "explicit_permission"):
            if key in result and not isinstance(result[key], bool):
                raise ValueError("Tool flags must be boolean.")
        if name == "approve_remediation" and result["confirm"] is not True:
            raise ValidationError("Remediation approval requires explicit confirmation.")
        return result

    def _execute(self, name: str, args: dict[str, Any]) -> Any:
        if name == "architecture":
            repo = self.store.get_repository(args["repository_id"])
            if repo is None: raise ValueError("Repository not found.")
            return build_architecture(self.store, repo)
        if name == "dependencies":
            repo = self.store.get_repository(args["repository_id"])
            if repo is None: raise ValueError("Repository not found.")
            return build_dependencies(self.store, repo, osv=args.get("osv", False))
        if name == "scan_results":
            scan = self.store.get_scan(args["scan_id"])
            if scan is None: raise ValueError("Scan not found.")
            findings, total = self.store.list_findings(scan_id=scan["id"], limit=200)
            return {"scan": scan, "findings": findings, "total_findings": total}
        if name == "propose_remediation":
            return self.ai.propose_remediation(args["finding_id"])
        if name == "approve_remediation":
            return self.ai.approve_remediation(args["proposal_id"], confirm=True,
                run_tests=args.get("run_tests", False),
                explicit_permission=args.get("explicit_permission", False))
        raise ValueError("Unknown intelligence tool.")


__all__ = ["ToolBroker", "ToolSpec"]
