"""Production-readiness scoring and release gate."""

import os
from typing import Any

from . import Finding, ModuleResult, ScanResult, Severity, Status


MODULE_WEIGHTS = {
    "security": 1.5,
    "database": 1.4,
    "dependencies": 1.2,
    "infrastructure": 1.2,
    "quality": 1.0,
    "compliance": 1.1,
    "performance": 0.8,
}

SEVERITY_PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

CONFIDENCE_MULTIPLIER = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.5,
}

EXPLOITABILITY_MULTIPLIER = {
    "security": 1.5,
    "database": 1.4,
    "dependencies": 1.2,
    "infrastructure": 1.2,
    "compliance": 1.0,
    "quality": 0.9,
    "performance": 0.8,
}

EXPLOITABLE_RULES = {
    "security:client-side-secret",
    "security:generic-api-key",
    "security:sql-injection-risk",
    "security:unsafe-shell-execution",
    "security:path-traversal-risk",
    "security:ssrf-risk",
    "security:private-key",
    "security:aws-access-key",
    "security:openai-key",
    "security:stripe-key",
    "security:supabase-service-key",
    "security:firebase-insecure-rules",
    "database:table-without-rls",
    "database:editable-role-field",
    "database:client-role-update",
}


def _finding_key(f: Finding) -> tuple:
    return (f.rule, str(f.file), f.line)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = _finding_key(f)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def _penalty_for(f: Finding) -> float:
    base = float(SEVERITY_PENALTY.get(f.severity, 0))
    confidence = CONFIDENCE_MULTIPLIER.get(f.confidence, 0.8)
    exploitability = EXPLOITABILITY_MULTIPLIER.get(f.module, 1.0)
    if f.rule in EXPLOITABLE_RULES:
        exploitability *= 1.2
    return round(base * confidence * exploitability, 2)


def score_module(findings: list[Finding], max_score: float = 100.0) -> tuple[float, Status, list[dict[str, Any]]]:
    unique = deduplicate_findings(findings)
    if not unique:
        return max_score, Status.PASS, []
    deductions: list[dict[str, Any]] = []
    penalty = 0.0
    for f in unique:
        p = _penalty_for(f)
        penalty += p
        deductions.append({
            "rule": f.rule,
            "file": str(f.file),
            "line": f.line,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "penalty": p,
            "reason": f"{f.severity.value} {f.rule} in {f.module}",
        })
    score = max(0.0, max_score - penalty)
    if any(f.severity == Severity.CRITICAL for f in unique):
        return score, Status.BLOCK, deductions
    if any(f.severity == Severity.HIGH for f in unique):
        return score, Status.FAIL, deductions
    return score, Status.PASS, deductions


def assess(result: ScanResult, minimum_score: int | None = None) -> dict:
    if minimum_score is None:
        minimum_score = int(os.environ.get("VCQA_MINIMUM_SCORE", "60"))
    score_explanation: dict[str, Any] = {"deductions": [], "modules": []}
    for module in result.modules:
        module.findings = deduplicate_findings(module.findings)
        module.score, module.status, deductions = score_module(module.findings)
        score_explanation["modules"].append({
            "module": module.module,
            "score": module.score,
            "status": module.status.value,
            "deductions": deductions,
        })
        score_explanation["deductions"].extend(deductions)

    weighted_sum = 0.0
    total_weight = 0.0
    for module in result.modules:
        weight = MODULE_WEIGHTS.get(module.module, 1.0)
        weighted_sum += module.score * weight
        total_weight += weight
    overall = round(weighted_sum / total_weight, 2) if total_weight else 0.0

    gate = "pass"
    if result.release_blocked:
        gate = "block"
    elif overall < minimum_score or result.high_count > 0:
        gate = "fail"

    score_explanation["overall_score"] = overall
    score_explanation["minimum_score"] = minimum_score
    score_explanation["weights"] = MODULE_WEIGHTS

    return {
        "overall_score": overall,
        "gate": gate,
        "weights": MODULE_WEIGHTS,
        "score_explanation": score_explanation,
        "criteria": {
            "critical_blocks_release": True,
            "high_fails_release": True,
            "minimum_score": minimum_score,
        },
    }


def release_decision(result: ScanResult) -> str:
    if result.release_blocked:
        return "BLOCKED: critical issues or failing tests must be resolved before release."
    if result.high_count > 0:
        return "FAIL: high-severity findings remain; fix before release."
    if result.overall_score < 60:
        return "FAIL: overall readiness score is below 60."
    return "PASS: no critical or high issues and score is above the release threshold."


def coverage_gaps(result: ScanResult) -> list[str]:
    gaps: list[str] = []
    architecture = result.tests.get("architecture", {})
    if not architecture.get("has_tests"):
        gaps.append("No automated test runner detected; runtime behavior is unverified.")
    if not architecture.get("lockfiles"):
        gaps.append("No dependency lockfile found; supply-chain reproducibility is unverified.")
    if not architecture.get("auth_providers"):
        gaps.append("No authentication provider detected; review access-control assumptions.")
    if not architecture.get("ci_files"):
        gaps.append("No CI workflow detected; build and deployment processes are unaudited.")
    if not architecture.get("has_gitignore"):
        gaps.append("No .gitignore detected; secret leaks are more likely.")
    if not result.modules:
        gaps.append("No scanner modules produced results.")
    return gaps
