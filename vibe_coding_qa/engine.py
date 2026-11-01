"""Engine orchestrator: run scanners, tests, fixes, gates, and reports."""

import os
import subprocess
from pathlib import Path

from . import ModuleResult, ScanResult, Severity, Status
from .fixes import FixEngine, suggest_fixes
from .gates import assess, release_decision
from .repo import cleanup_repo, load_repository, repo_metadata
from .scanners.compliance import ComplianceScanner
from .scanners.database import DatabaseScanner
from .scanners.infrastructure import InfrastructureScanner
from .scanners.performance import PerformanceScanner
from .scanners.quality import QualityScanner
from .scanners.security import SecurityScanner


SCANNERS = [
    SecurityScanner,
    QualityScanner,
    DatabaseScanner,
    InfrastructureScanner,
    PerformanceScanner,
    ComplianceScanner,
]


def run_scan(repo: Path, metadata: bool = False) -> ScanResult:
    modules: list[ModuleResult] = []
    for scanner_cls in SCANNERS:
        scanner = scanner_cls(repo)
        findings = scanner.scan()
        modules.append(ModuleResult(
            module=scanner.module,
            status=Status.PASS,
            score=100.0,
            findings=findings,
        ))
    result = ScanResult(repo=repo, modules=modules)
    assess(result)
    if metadata:
        result.tests["repo_metadata"] = repo_metadata(repo)
    return result


def run_tests(repo: Path, command: str | None = None, timeout: int = 300) -> dict:
    if command:
        cmd = command.split()
    elif (repo / "package.json").is_file():
        cmd = ["npm", "test"]
    elif (repo / "pyproject.toml").is_file() or (repo / "setup.py").is_file():
        cmd = ["python", "-m", "pytest"]
    else:
        return {"status": Status.SKIP, "command": None, "summary": "No test runner detected."}

    env = os.environ.copy()
    env["CI"] = "true"
    env["NODE_ENV"] = "test"
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return {
            "status": Status.PASS if result.returncode == 0 else Status.FAIL,
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "summary": result.stdout[-1500:] if len(result.stdout) > 1500 else result.stdout,
        }
    except FileNotFoundError as exc:
        return {"status": Status.SKIP, "command": " ".join(cmd), "summary": f"Command not found: {exc}"}
    except subprocess.TimeoutExpired:
        return {"status": Status.FAIL, "command": " ".join(cmd), "summary": "Test command timed out."}


def run_pipeline(
    source: str,
    *,
    output_dir: Path | str | None = None,
    run_tests_flag: bool = True,
    apply_fixes: bool = False,
    dry_run_fixes: bool = True,
    github_token: str | None = None,
    test_command: str | None = None,
    keep_clone: bool = False,
) -> ScanResult:
    workdir: Path | None = None
    try:
        workdir = load_repository(source, token=github_token)
        result = run_scan(workdir, metadata=True)

        if dry_run_fixes or apply_fixes:
            engine = FixEngine(workdir, dry_run=not apply_fixes)
            engine.apply(result.findings)

        if run_tests_flag:
            result.tests = run_tests(workdir, command=test_command)

        # Re-assess after potential fixes/tests.
        assess(result)

        if output_dir:
            from .reporters import write_reports
            write_reports(result, Path(output_dir))

        return result
    finally:
        if workdir and not keep_clone and str(workdir) != str(Path(source).resolve()):
            cleanup_repo(workdir)


def critical_summary(result: ScanResult) -> str:
    parts = [
        f"Overall score: {result.overall_score}",
        f"Critical: {result.critical_count}",
        f"High: {result.high_count}",
        release_decision(result),
    ]
    return " | ".join(parts)
