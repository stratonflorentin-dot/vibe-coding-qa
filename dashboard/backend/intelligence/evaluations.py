"""Evaluation foundation for Vibe Intelligence.

Before building proprietary models we must be able to *measure* quality. v1
provides the primitives: validating that a result's evidence references point at
real artefacts (not invented paths/ids), scoring a result's structural health,
and a small synthetic benchmark describing the hard cases to test against.

Model-reported confidence is kept strictly separate from measured accuracy: a
result may claim HIGH confidence yet fail evidence validation.
"""

from __future__ import annotations

from ..persistence.store import Store
from .contracts import EvidenceKind, IntelligenceResult


def validate_evidence(result: IntelligenceResult, store: Store) -> list[str]:
    """Return a list of invalid evidence references (empty == all valid).

    Findings and scans must exist; file references must be non-empty paths.
    Architecture/dependency refs are structural pointers and accepted as-is.
    """
    problems: list[str] = []
    for ref in result.evidence:
        if ref.kind is EvidenceKind.FINDING:
            try:
                if store.get_finding(int(ref.ref)) is None:
                    problems.append(f"finding {ref.ref} does not exist")
            except (TypeError, ValueError):
                problems.append(f"finding ref '{ref.ref}' is not an id")
        elif ref.kind is EvidenceKind.SCAN:
            try:
                if store.get_scan(int(ref.ref)) is None:
                    problems.append(f"scan {ref.ref} does not exist")
            except (TypeError, ValueError):
                problems.append(f"scan ref '{ref.ref}' is not an id")
        elif ref.kind is EvidenceKind.FILE:
            if not ref.ref or not ref.ref.strip():
                problems.append("empty file reference")
    return problems


def score_result(result: IntelligenceResult, store: Store) -> dict:
    """Structural quality signals for one result (not a model judgement)."""
    invalid = validate_evidence(result, store)
    return {
        "structured_output_valid": True,  # it is a validated Pydantic envelope
        "has_evidence": bool(result.evidence),
        "evidence_all_valid": not invalid,
        "invalid_evidence": invalid,
        "declares_limitations": bool(result.limitations),
        "fallback_used": result.fallback_used,
        "latency_ms": result.latency_ms,
        "reported_confidence": result.confidence.value,
    }


#: Synthetic benchmark classes (described, not customer code). Each names a
#: behaviour the intelligence must handle correctly; concrete fixtures are added
#: as the handlers mature.
BENCHMARK_CASES = [
    {"id": "clear_root_cause", "desc": "A failure with an unambiguous root cause and clean evidence."},
    {"id": "misleading_logs", "desc": "Logs that point at the wrong component."},
    {"id": "missing_evidence", "desc": "A failure report with insufficient evidence to diagnose."},
    {"id": "ambiguous_cause", "desc": "Several plausible root causes."},
    {"id": "invalid_model_response", "desc": "The provider returns malformed or empty output."},
    {"id": "incorrect_repair", "desc": "A proposed repair that does not address the root cause."},
    {"id": "unsupported_task", "desc": "A task the gateway should refuse or mark unavailable."},
]


__all__ = ["BENCHMARK_CASES", "score_result", "validate_evidence"]
