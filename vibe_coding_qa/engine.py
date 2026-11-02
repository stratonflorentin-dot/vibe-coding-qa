"""Engine orchestrator: run scanners, tests, fixes, gates, and reports."""

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

from . import ModuleResult, ScanResult, Severity, Status
from .ai_review import get_ai_provider, review_findings
from .fixes import FixEngine, suggest_fixes
from .gates import assess, release_decision
from .profile import analyze_repo
from .repo import cleanup_repo, load_repository, repo_metadata
from .scanners.compliance import ComplianceScanner
from .scanners.database import DatabaseScanner
from .scanners.dependencies import DependencyScanner
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
    DependencyScanner,
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
        result.tests["architecture"] = analyze_repo(repo).to_dict()
    return result


def run_tests(repo: Path, command: str | None = None, timeout: int = 300, no_execution: bool = False) -> dict:
    if no_execution:
        return {"status": Status.SKIP, "command": None, "summary": "Test execution disabled by --no-execution.", "duration_ms": 0}

    # Destructive terms that should never be run automatically
    destructive_terms = ("rm -rf", "rm -fr", "rm -r", "kubectl delete", "drop", "deploy", "serverless deploy", "sls deploy")

    if command:
        # Use shlex.split to properly handle shell-style quoting
        try:
            cmd = shlex.split(command)
        except ValueError as exc:
            return {"status": Status.SKIP, "command": command, "summary": f"Invalid command syntax: {exc}", "duration_ms": 0}
        lowered = command.lower()
        if any(term in lowered for term in destructive_terms):
            return {
                "status": Status.SKIP,
                "command": command,
                "summary": f"Refusing to run potentially destructive command: {command}",
                "duration_ms": 0,
            }
    else:
        cmd = _detect_test_command(repo)
        if cmd is None:
            return {"status": Status.SKIP, "command": None, "summary": "No test runner detected.", "duration_ms": 0}

    env = os.environ.copy()
    env["CI"] = "true"
    env["NODE_ENV"] = "test"
    command_str = " ".join(shlex.quote(c) for c in cmd)
    if any(term in command_str.lower() for term in destructive_terms):
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": f"Refusing to run potentially destructive command: {command_str}",
            "duration_ms": 0,
        }

    start = time.time()
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
        duration_ms = int((time.time() - start) * 1000)
        status = Status.PASS if result.returncode == 0 else Status.FAIL
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        summary = output[-2000:] if len(output) > 2000 else output
        skipped = _count_skipped(output)
        return {
            "status": status,
            "command": command_str,
            "returncode": result.returncode,
            "summary": summary,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": duration_ms,
            "skipped": skipped,
            "warning": "Test scripts execute project code. Review scripts before running in production environments.",
        }
    except FileNotFoundError as exc:
        return {"status": Status.SKIP, "command": command_str, "summary": f"Command not found: {exc}", "duration_ms": int((time.time() - start) * 1000)}
    except subprocess.TimeoutExpired:
        return {"status": Status.FAIL, "command": command_str, "summary": "Test command timed out.", "duration_ms": int((time.time() - start) * 1000)}


def _detect_test_command(repo: Path) -> list[str] | None:
    profile = analyze_repo(repo)
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            scripts = data.get("scripts", {})
            for key in ("test", "tests", "test:ci", "test:unit", "test:lib"):
                if key in scripts:
                    runner = {
                        "pnpm": "pnpm",
                        "yarn": "yarn",
                        "npm": "npm",
                        "bun": "bun",
                    }.get(profile.package_manager, "npm")
                    return [runner, "run", key]
        except Exception:
            pass
    if profile.test_runners:
        if "pytest" in profile.test_runners:
            return ["python", "-m", "pytest"]
    return None


def _count_skipped(output: str) -> int | None:
    if not output:
        return None
    # pytest: "1 skipped" ; jest: "Tests: 1 skipped"
    match = re.search(r"(\d+)\s+skipped", output, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def run_pipeline(
    source: str,
    *,
    output_dir: Path | str | None = None,
    run_tests_flag: bool = True,
    no_execution: bool = False,
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

        ai_reviews = review_findings(workdir, result.findings, provider=get_ai_provider())
        if ai_reviews:
            result.tests["ai_reviews"] = ai_reviews

        if dry_run_fixes or apply_fixes:
            engine = FixEngine(workdir, dry_run=not apply_fixes)
            engine.apply(result.findings)
            result.tests["fixes"] = {"applied": engine.applied, "skipped": engine.skipped, "dry_run": engine.dry_run}

        if run_tests_flag:
            result.tests.update(run_tests(workdir, command=test_command, no_execution=no_execution))

        # Re-assess after potential fixes/tests.
        assessment = assess(result)
        result._assessment = assessment

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
