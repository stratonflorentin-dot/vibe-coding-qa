"""Production-readiness scoring and release gate."""

from . import Finding, ModuleResult, ScanResult, Severity, Status


MODULE_WEIGHTS = {
    "security": 1.5,
    "database": 1.4,
    "quality": 1.0,
    "infrastructure": 1.2,
    "performance": 0.8,
    "compliance": 1.1,
}


def score_module(findings: list[Finding], max_score: float = 100.0) -> tuple[float, Status]:
    if not findings:
        return max_score, Status.PASS
    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 3, Severity.INFO: 0}
    penalty = sum(weights.get(f.severity, 0) for f in findings)
    score = max(0.0, max_score - penalty)
    if any(f.severity == Severity.CRITICAL for f in findings):
        return score, Status.BLOCK
    if any(f.severity == Severity.HIGH for f in findings):
        return score, Status.FAIL
    return score, Status.PASS


def assess(result: ScanResult) -> dict:
    for module in result.modules:
        module.score, module.status = score_module(module.findings)

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
    elif overall < 60 or result.high_count > 0:
        gate = "fail"

    return {
        "overall_score": overall,
        "gate": gate,
        "weights": MODULE_WEIGHTS,
        "criteria": {
            "critical_blocks_release": True,
            "high_fails_release": True,
            "minimum_score": 60,
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
