"""Task-based routing between deterministic handlers and AI models.

Each operation declares whether it is answered deterministically (from scan
data / static analysis) or prefers an AI model with a required capability. The
router never *silently* downgrades: when the configured model lacks a required
capability, or no provider is configured, it records that explicitly so the
gateway can report reduced confidence or an ``unavailable`` status.
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ExecutionKind, Operation
from .model_registry import Capability, ModelRegistry


@dataclass(frozen=True)
class RoutePolicy:
    kind: ExecutionKind
    capability: Capability | None
    #: True when the operation can still return useful deterministic evidence
    #: with no AI provider (so it degrades to a PARTIAL result rather than
    #: UNAVAILABLE).
    degradable: bool


@dataclass(frozen=True)
class RouteDecision:
    execution_kind: ExecutionKind
    required_capability: Capability | None
    capability_satisfied: bool
    degraded: bool          # preferred AI but fell back to deterministic
    available: bool         # False => no capable path; gateway returns UNAVAILABLE
    notes: tuple[str, ...]


ROUTING: dict[Operation, RoutePolicy] = {
    Operation.MAP_ARCHITECTURE: RoutePolicy(ExecutionKind.DETERMINISTIC, None, True),
    Operation.ANALYZE_REGRESSION: RoutePolicy(ExecutionKind.DETERMINISTIC, None, True),
    Operation.SUMMARIZE_VERIFICATION: RoutePolicy(ExecutionKind.DETERMINISTIC, None, True),
    Operation.ANALYZE_PROJECT: RoutePolicy(ExecutionKind.AI, Capability.CODE, True),
    Operation.DISCOVER_FEATURES: RoutePolicy(ExecutionKind.AI, Capability.CODE, True),
    Operation.GENERATE_TEST_PLAN: RoutePolicy(ExecutionKind.AI, Capability.REASONING, True),
    Operation.DIAGNOSE_FAILURE: RoutePolicy(ExecutionKind.AI, Capability.REASONING, True),
    # A repair proposal needs a model; without one there is no diff to return.
    Operation.PROPOSE_REPAIR: RoutePolicy(ExecutionKind.AI, Capability.CODE, False),
}


class Router:
    def __init__(self, registry: ModelRegistry):
        self.registry = registry

    def route(self, operation: Operation) -> RouteDecision:
        policy = ROUTING.get(operation)
        if policy is None:
            # Unknown operations are rejected earlier; be safe here.
            return RouteDecision(ExecutionKind.DETERMINISTIC, None, True, False, False, ())

        if policy.kind is ExecutionKind.DETERMINISTIC:
            return RouteDecision(ExecutionKind.DETERMINISTIC, None, True, False, True, ())

        # AI-preferred.
        if not self.registry.is_configured():
            if policy.degradable:
                return RouteDecision(
                    ExecutionKind.DETERMINISTIC, policy.capability, False, True, True,
                    ("No AI provider is configured; returning deterministic evidence only.",),
                )
            return RouteDecision(
                ExecutionKind.AI, policy.capability, False, False, False,
                ("No AI provider is configured for this operation.",),
            )

        caps = self.registry.model_capabilities()
        satisfied = policy.capability is None or policy.capability in caps
        notes: tuple[str, ...] = ()
        if not satisfied:
            notes = (
                f"The configured model does not advertise the "
                f"'{policy.capability.value}' capability; result quality may be lower.",
            )
        return RouteDecision(ExecutionKind.AI, policy.capability, satisfied, False, True, notes)


__all__ = ["RouteDecision", "RoutePolicy", "ROUTING", "Router"]
