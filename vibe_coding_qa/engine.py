"""Engine orchestrator: run scanners, tests, fixes, gates, and reports."""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from . import ModuleResult, ScanResult, Severity, Status
from .ai_review import get_ai_provider, review_findings
from .fixes import FixEngine, suggest_fixes
from .gates import assess, release_decision
from .profile import analyze_repo
from .repo import cleanup_repo, load_repository, repo_metadata
from .scanners import redact_secrets
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


ProgressCallback = Callable[[str, str, str, dict], None]


def _emit(progress: "ProgressCallback | None", stage: str, status: str, message: str = "", data: dict | None = None) -> None:
    """Report a real scan stage to an optional progress callback.

    The observer is best-effort: a failing callback must never break a scan.
    """
    if progress is None:
        return
    try:
        progress(stage, status, message, data or {})
    except Exception:
        pass


def run_scan(
    repo: Path,
    metadata: bool = False,
    progress: "ProgressCallback | None" = None,
    modules: list[str] | None = None,
    minimum_score: int | None = None,
) -> ScanResult:
    _emit(progress, "preparation", "running", "Preparing repository for analysis")
    selected = set(modules) if modules is not None else None
    result_modules: list[ModuleResult] = []
    for scanner_cls in SCANNERS:
        if selected is not None and scanner_cls.module not in selected:
            _emit(progress, "scanner", "skipped", f"{scanner_cls.module} analysis skipped by scan profile", {"module": scanner_cls.module})
            continue
        scanner = scanner_cls(repo)
        _emit(progress, "scanner", "running", f"Running {scanner.module} analysis", {"module": scanner.module})
        findings = scanner.scan()
        result_modules.append(ModuleResult(
            module=scanner.module,
            status=Status.PASS,
            score=100.0,
            findings=findings,
            notes=getattr(scanner, "notes", []),
        ))
        _emit(progress, "scanner", "completed", f"{scanner.module} analysis complete", {"module": scanner.module, "findings": len(findings)})
    result = ScanResult(repo=repo, modules=result_modules)
    assess(result, minimum_score=minimum_score)
    if metadata:
        _emit(progress, "technology", "running", "Detecting technology stack and architecture")
        result.tests["repo_metadata"] = repo_metadata(repo)
        result.tests["architecture"] = analyze_repo(repo).to_dict()
        _emit(progress, "technology", "completed", "Technology detection complete")
    return result


def _test_environment() -> dict[str, str]:
    allowed = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR",
        "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
        "LANG", "LC_ALL", "LC_CTYPE", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
        "NPM_CONFIG_CACHE", "CI", "NODE_ENV",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}



def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    max_output_bytes: int = 1_000_000,
) -> tuple[subprocess.CompletedProcess, bool, bool]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    output_lock = threading.Lock()
    output_exceeded = threading.Event()

    def drain(name: str, stream) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            with output_lock:
                remaining = max_output_bytes - len(captured["stdout"]) - len(captured["stderr"])
                if remaining > 0:
                    captured[name].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_exceeded.set()
            if output_exceeded.is_set():
                try:
                    process.kill()
                except OSError:
                    pass
                return

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
    for reader in readers:
        reader.join()
    for stream in (process.stdout, process.stderr):
        if stream and not stream.closed:
            stream.close()
    stdout = bytes(captured["stdout"]).decode("utf-8", errors="replace")
    stderr = bytes(captured["stderr"]).decode("utf-8", errors="replace")
    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    return completed, timed_out, output_exceeded.is_set()


def _copy_test_snapshot(repo: Path, max_bytes: int = 256 * 1024 * 1024) -> tuple[Path, Path]:
    source = repo.resolve()
    temporary_root = Path(tempfile.mkdtemp(prefix="vcqa-test-snapshot-"))
    snapshot = temporary_root / "repo"
    snapshot.mkdir()
    excluded_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".pytest_cache", ".aws", ".ssh", ".gnupg"}
    excluded_files = {".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "credentials.json", "service-account.json"}
    excluded_extensions = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer"}
    total_bytes = 0
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name for name in directories
            if name not in excluded_dirs and not (current_path / name).is_symlink()
        ]
        relative_dir = current_path.relative_to(source)
        target_dir = snapshot / relative_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        # The container is unprivileged (--cap-drop ALL) and cannot override file
        # permissions, so ensure the snapshot stays traversable/readable even when
        # the host umask is restrictive.
        try:
            os.chmod(target_dir, 0o755)
        except OSError:
            pass
        for name in files:
            source_file = current_path / name
            lowered = name.lower()
            if source_file.is_symlink() or lowered in excluded_files:
                continue
            if lowered.startswith(".env") and lowered != ".env.example":
                continue
            if source_file.suffix.lower() in excluded_extensions:
                continue
            try:
                source_file.resolve().relative_to(source)
            except ValueError:
                continue
            try:
                remaining = max_bytes - total_bytes
                with source_file.open("rb") as stream:
                    content = stream.read(remaining + 1)
                if len(content) > remaining:
                    shutil.rmtree(temporary_root, ignore_errors=True)
                    raise ValueError(f"Test snapshot exceeds the {max_bytes} byte limit.")
                total_bytes += len(content)
                try:
                    text = content.decode("utf-8")
                    if "\0" in text:
                        continue
                    target_file = target_dir / name
                    target_file.write_text(redact_secrets(text), encoding="utf-8")
                    try:
                        os.chmod(target_file, 0o644)
                    except OSError:
                        pass
                except UnicodeDecodeError:
                    continue
            except OSError:
                continue
    return temporary_root, snapshot


def _test_image(command: list[str], configured: str | None) -> str:
    image = configured or os.environ.get("VCQA_TEST_CONTAINER_IMAGE")
    if not image:
        executable = Path(command[0]).name.lower() if command else ""
        image = "node:22-bookworm-slim" if executable in {"npm", "npx", "pnpm", "yarn", "bun"} else "python:3.12-slim"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]*", image):
        raise ValueError("Test container image contains unsupported characters.")
    return image


def _empty_counts() -> dict[str, int | None]:
    return {"discovered": None, "executed": None, "passed": None, "failed": None, "skipped": None, "errors": None}


def _normalized_counts(discovered, passed, failed, skipped, errors) -> dict[str, int]:
    passed = int(passed or 0)
    failed = int(failed or 0)
    skipped = int(skipped or 0)
    errors = int(errors or 0)
    executed = passed + failed + errors
    discovered = int(discovered if discovered is not None else executed + skipped)
    if discovered < executed + skipped:
        discovered = executed + skipped
    return {
        "discovered": discovered,
        "executed": executed,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
    }


def _parse_unittest_output(output: str) -> dict[str, int] | None:
    match = re.search(r"Ran (\d+) tests? in", output)
    if not match:
        return None
    discovered = int(match.group(1))
    failed = errors = skipped = 0
    failed_header = re.search(r"FAILED \(([^)]*)\)", output)
    if failed_header:
        body = failed_header.group(1)
        failure_match = re.search(r"failures=(\d+)", body)
        error_match = re.search(r"errors=(\d+)", body)
        skip_match = re.search(r"skipped=(\d+)", body)
        failed = int(failure_match.group(1)) if failure_match else 0
        errors = int(error_match.group(1)) if error_match else 0
        skipped = int(skip_match.group(1)) if skip_match else 0
    else:
        ok_match = re.search(r"^OK(?: \(([^)]*)\))?", output, re.MULTILINE)
        if ok_match and ok_match.group(1):
            skip_match = re.search(r"skipped=(\d+)", ok_match.group(1))
            if skip_match:
                skipped = int(skip_match.group(1))
    passed = max(0, discovered - skipped - failed - errors)
    return _normalized_counts(discovered, passed, failed, skipped, errors)


def _parse_pytest_output(output: str) -> dict[str, int] | None:
    # Require a pytest-specific signal so Jest/Vitest summaries do not match.
    no_tests = re.search(r"no tests ran in \d+\.\d+s", output, re.IGNORECASE)
    collected = re.search(r"collected (\d+) item", output)
    summary = re.search(
        r"(?m)^[=\s]*(?:\d+ (?:passed|failed|errors?|skipped|xfailed|xpassed|warnings?|deselected)[,\s]*)+in \d+\.\d+s",
        output,
    )
    if not (no_tests or collected or summary):
        return None

    def grab(label: str) -> int:
        found = re.search(r"(\d+) " + label + r"\b", output)
        return int(found.group(1)) if found else 0

    passed = grab("passed")
    failed = grab("failed")
    skipped = grab("skipped")
    errors = grab("errors") or grab("error")
    discovered = passed + failed + errors + skipped
    if collected:
        discovered = max(discovered, int(collected.group(1)))
    return _normalized_counts(discovered, passed, failed, skipped, errors)


def _parse_jest_output(output: str) -> dict[str, int] | None:
    match = re.search(r"^Tests:\s*(.+)$", output, re.MULTILINE)
    if not match:
        return None
    line = match.group(1)

    def grab(label: str) -> int:
        found = re.search(r"(\d+) " + label + r"\b", line)
        return int(found.group(1)) if found else 0

    failed = grab("failed")
    passed = grab("passed")
    skipped = grab("skipped")
    todo = grab("todo")
    total_match = re.search(r"(\d+) total", line)
    discovered = int(total_match.group(1)) if total_match else passed + failed + skipped + todo
    return _normalized_counts(discovered, passed, failed, skipped, 0)


def _parse_vitest_output(output: str) -> dict[str, int] | None:
    match = re.search(r"^\s*Tests\s+(.+)$", output, re.MULTILINE)
    if not match:
        return None
    line = match.group(1)

    def grab(label: str) -> int:
        found = re.search(r"(\d+) " + label + r"\b", line)
        return int(found.group(1)) if found else 0

    failed = grab("failed")
    passed = grab("passed")
    skipped = grab("skipped")
    if not (failed or passed or skipped):
        return None
    total_match = re.search(r"\((\d+)\)", line)
    discovered = int(total_match.group(1)) if total_match else passed + failed + skipped
    return _normalized_counts(discovered, passed, failed, skipped, 0)


_TEST_OUTPUT_PARSERS = (
    ("unittest", _parse_unittest_output),
    ("pytest", _parse_pytest_output),
    ("jest", _parse_jest_output),
    ("vitest", _parse_vitest_output),
)


def classify_test_results(output: str, returncode: int) -> dict:
    """Classify a test run from its output and exit code.

    Returns a normalized structure with ``status``, ``reason``, ``runner`` and
    ``counts``. A zero exit code alone never yields PASS: verified results must
    be recognised from the runner output.
    """
    for runner, parser in _TEST_OUTPUT_PARSERS:
        counts = parser(output)
        if counts is None:
            continue
        failed = counts["failed"] or 0
        errors = counts["errors"] or 0
        discovered = counts["discovered"] or 0
        executed = counts["executed"] or 0
        if failed or errors:
            return {"status": Status.FAIL, "reason": "tests_failed", "runner": runner, "counts": counts}
        if discovered == 0:
            return {"status": Status.SKIP, "reason": "zero_tests_discovered", "runner": runner, "counts": counts}
        if executed == 0:
            return {"status": Status.SKIP, "reason": "all_tests_skipped", "runner": runner, "counts": counts}
        if returncode != 0:
            return {"status": Status.FAIL, "reason": "non_zero_exit", "runner": runner, "counts": counts}
        return {"status": Status.PASS, "reason": "tests_passed", "runner": runner, "counts": counts}
    return {"status": Status.SKIP, "reason": "no_recognizable_results", "runner": None, "counts": _empty_counts()}



def run_tests(
    repo: Path,
    command: str | None = None,
    timeout: int = 300,
    no_execution: bool = False,
    explicit_permission: bool = False,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    test_image: str | None = None,
    max_snapshot_mb: int = 256,
    max_write_mb: int = 64,
) -> dict:
    """
    Run tests with security isolation.

    Args:
        repo: Repository path
        command: Test command to run (uses shlex.split for proper quoting)
        timeout: Wall-clock timeout in seconds
        no_execution: If True, skip execution entirely
        explicit_permission: Must be True to actually run tests (safety gate)
        max_memory_mb: Memory limit in MB (enforced where the platform supports resource limits)
        max_cpu_seconds: CPU time limit in seconds (enforced where the platform supports resource limits)

    Returns:
        Dict with test results including status, command, summary, etc.
    """
    if no_execution:
        return {
            "status": Status.SKIP,
            "command": None,
            "summary": "Test execution disabled by --no-execution.",
            "duration_ms": 0,
            "execution_mode": "disabled",
        }

    # Safety gate: require explicit permission to run tests
    if not explicit_permission:
        return {
            "status": Status.SKIP,
            "command": command,
            "summary": "Test execution requires explicit permission (--explicit-permission). Tests were not run.",
            "duration_ms": 0,
            "execution_mode": "blocked_no_permission",
        }

    if timeout <= 0 or max_memory_mb <= 0 or max_cpu_seconds <= 0 or max_snapshot_mb <= 0 or max_write_mb < 2:
        return {
            "status": Status.SKIP,
            "command": command,
            "summary": "Timeout, memory, CPU and snapshot limits must be positive; writable storage must be at least 2 MB.",
            "duration_ms": 0,
            "execution_mode": "invalid_limits",
        }

    # Destructive terms that should never be run automatically
    destructive_terms = ("rm -rf", "rm -fr", "rm -r", "kubectl delete", "drop", "deploy", "serverless deploy", "sls deploy")

    if command:
        # Use shlex.split to properly handle shell-style quoting
        try:
            cmd = shlex.split(command)
        except ValueError as exc:
            return {
                "status": Status.SKIP,
                "command": command,
                "summary": f"Invalid command syntax: {exc}",
                "duration_ms": 0,
                "execution_mode": "error",
            }
        lowered = command.lower()
        if any(term in lowered for term in destructive_terms):
            return {
                "status": Status.SKIP,
                "command": command,
                "summary": f"Refusing to run potentially destructive command: {command}",
                "duration_ms": 0,
                "execution_mode": "blocked_destructive",
            }
    else:
        cmd = _detect_test_command(repo)
        if cmd is None:
            return {
                "status": Status.SKIP,
                "command": None,
                "summary": "No test runner detected.",
                "duration_ms": 0,
                "execution_mode": "no_runner",
            }

    env = _test_environment()
    env["CI"] = "true"
    env["NODE_ENV"] = "test"
    if timeout <= 0 or max_memory_mb <= 0 or max_cpu_seconds <= 0:
        return {
            "status": Status.SKIP,
            "command": command,
            "summary": "Timeout and resource limits must be positive values.",
            "duration_ms": 0,
            "execution_mode": "error",
        }

    command_str = redact_secrets(" ".join(shlex.quote(c) for c in cmd))
    if any(term in command_str.lower() for term in destructive_terms):
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": f"Refusing to run potentially destructive command: {command_str}",
            "duration_ms": 0,
            "execution_mode": "blocked_destructive",
        }

    try:
        image = _test_image(cmd, test_image)
    except ValueError as exc:
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": str(exc),
            "duration_ms": 0,
            "execution_mode": "error",
        }
    try:
        docker = shutil.which("docker")
        if not docker:
            raise FileNotFoundError("Docker CLI is not installed.")
        availability = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            check=False,
        )
        if availability.returncode != 0:
            return {
                "status": Status.SKIP,
                "command": command_str,
                "summary": "Isolated test execution requires an available Docker daemon; tests were not run.",
                "duration_ms": 0,
                "execution_mode": "sandbox_unavailable",
            }
        image_check = subprocess.run(
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            check=False,
        )
        if image_check.returncode != 0:
            return {
                "status": Status.SKIP,
                "command": command_str,
                "summary": f"Configured test image '{image}' is not available locally; no image was pulled and tests were not run.",
                "duration_ms": 0,
                "execution_mode": "sandbox_image_unavailable",
            }
    except (OSError, subprocess.TimeoutExpired):
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": "Could not verify an isolated Docker runtime; tests were not run.",
            "duration_ms": 0,
            "execution_mode": "sandbox_unavailable",
        }

    try:
        temporary_root, snapshot = _copy_test_snapshot(repo, max_bytes=max_snapshot_mb * 1024 * 1024)
    except (OSError, ValueError) as exc:
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": f"Could not prepare bounded test snapshot: {type(exc).__name__}.",
            "duration_ms": 0,
            "execution_mode": "snapshot_unavailable",
        }
    container_name = f"vcqa-test-{uuid.uuid4().hex[:12]}"
    resource_info = {
        "memory_mb": max_memory_mb,
        "cpu_seconds": max_cpu_seconds,
        "enforced": True,
        "environment_allowlisted": True,
        "isolation": "docker-network-disabled-read-only-rootfs",
        "snapshot_excludes_secrets": False,
        "snapshot_max_mb": max_snapshot_mb,
        "tmp_and_shm_max_mb": max_write_mb,
        "workspace": "tmpfs-read-write",
        "source_mount": "read-only",
        "workspace_max_mb": max_write_mb,
    }
    # The original repository is never mutated: a secret-filtered snapshot is
    # mounted read-only and copied into a size-bounded writable tmpfs workspace
    # before the test command runs, so the suite may create temp files and build
    # artifacts without touching the source or the read-only root filesystem.
    #
    # The copy must NOT preserve ownership. The container runs with --cap-drop ALL,
    # so it holds no CAP_CHOWN: ``cp -a``/``cp -p`` would try to chown the copies to
    # the snapshot owner and fail with EPERM, aborting under ``set -e``. ``cp -R``
    # copies contents and permissions without preserving ownership.
    inner_command = (
        "set -e; "
        "cp -R /vcqa-src/. /workspace/; "
        "cd /workspace; "
        "exec " + " ".join(shlex.quote(part) for part in cmd)
    )
    docker_command = [
        docker, "run", "--pull=never", "--rm", "--name", container_name,
        "--network", "none",
        "--memory", f"{max_memory_mb}m",
        "--cpus", "1",
        "--pids-limit", "128",
        "--ulimit", f"cpu={max_cpu_seconds}:{max_cpu_seconds + 1}",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,size={max_write_mb - 1}m",
        "--tmpfs", f"/workspace:rw,nosuid,nodev,size={max_write_mb}m",
        "--shm-size", "1m",
        "--mount", f"type=bind,source={snapshot},target=/vcqa-src,readonly",
        "--workdir", "/workspace",
        "--env", "CI=true",
        "--env", "NODE_ENV=test",
        "--env", "HOME=/tmp",
        image,
        "sh", "-c", inner_command,
    ]
    start = time.time()
    try:
        result, timed_out, output_exceeded = _run_bounded_process(
            docker_command,
            cwd=snapshot,
            timeout=timeout,
            env=env,
        )
        duration_ms = int((time.time() - start) * 1000)
        if timed_out:
            return {
                "status": Status.FAIL,
                "command": command_str,
                "summary": f"Test command timed out after {timeout}s.",
                "duration_ms": duration_ms,
                "execution_mode": "timeout",
                "resource_limits": resource_info,
            }
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        output = redact_secrets(output)
        summary = "Test output exceeded 1,000,000 bytes and was terminated." if output_exceeded else (output[-2000:] if len(output) > 2000 else output)

        missing_infrastructure = bool(re.search(
            r"No module named ['\"]?[\w.]+['\"]?|Cannot find module ['\"][^'\"]+['\"]|(?:pytest|vitest|jest): (?:not found|command not found)|executable file not found in \$PATH",
            output, re.IGNORECASE,
        )) or result.returncode == 127
        real_failures = bool(re.search(r"FAILED \(failures=|\b\d+ failed\b|\b\d+ failing\b", output, re.IGNORECASE))
        space_exceeded = bool(re.search(r"No space left on device|Disk quota exceeded", output, re.IGNORECASE))

        if output_exceeded:
            classification = {"status": Status.FAIL, "reason": "output_limit_exceeded", "runner": None, "counts": _empty_counts()}
            execution_mode = "docker_isolated"
        elif space_exceeded and not real_failures:
            classification = {"status": Status.FAIL, "reason": "workspace_size_exceeded", "runner": None, "counts": _empty_counts()}
            execution_mode = "workspace_size_exceeded"
            summary = "The bounded writable test workspace ran out of disk space. " + summary
        elif missing_infrastructure and not real_failures:
            classification = {"status": Status.SKIP, "reason": "test_infrastructure_unavailable", "runner": None, "counts": _empty_counts()}
            execution_mode = "test_infrastructure_unavailable"
            summary = "Test infrastructure appears unavailable. Use a locally prepared --test-image with the necessary dependencies. " + summary
        else:
            classification = classify_test_results(output, result.returncode)
            execution_mode = "docker_isolated"

        counts = classification["counts"]
        return {
            "status": classification["status"],
            "test_reason": classification["reason"],
            "test_runner": classification["runner"],
            "tests_discovered": counts["discovered"],
            "tests_executed": counts["executed"],
            "tests_passed": counts["passed"],
            "tests_failed": counts["failed"],
            "tests_skipped": counts["skipped"],
            "tests_errors": counts["errors"],
            "command": command_str,
            "returncode": result.returncode,
            "summary": summary,
            "stdout": redact_secrets(result.stdout),
            "stderr": redact_secrets(result.stderr),
            "duration_ms": duration_ms,
            "skipped": counts["skipped"],
            "output_truncated": output_exceeded,
            "execution_mode": execution_mode,
            "resource_limits": resource_info,
            "warning": "Tests ran in a restricted Docker container using a filtered snapshot. Redaction is pattern-based and cannot guarantee removal of all secrets; container isolation is not a proof against runtime vulnerabilities.",
        }
    except FileNotFoundError:
        return {
            "status": Status.SKIP,
            "command": command_str,
            "summary": "Docker CLI became unavailable; tests were not run.",
            "duration_ms": int((time.time() - start) * 1000),
            "execution_mode": "sandbox_unavailable",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": Status.FAIL,
            "command": command_str,
            "summary": f"Test command timed out after {timeout}s.",
            "duration_ms": int((time.time() - start) * 1000),
            "execution_mode": "timeout",
            "resource_limits": resource_info,
        }
    finally:
        try:
            subprocess.run(
                [docker, "rm", "--force", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        shutil.rmtree(temporary_root, ignore_errors=True)


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
        if "unittest" in profile.test_runners:
            test_dir = "tests" if (repo / "tests").is_dir() else "."
            return ["python", "-m", "unittest", "discover", "-s", test_dir]
    return None


def run_pipeline(
    source: str,
    *,
    output_dir: Path | str | None = None,
    run_tests_flag: bool = True,
    no_execution: bool = False,
    explicit_permission: bool = False,
    apply_fixes: bool = False,
    dry_run_fixes: bool = True,
    github_token: str | None = None,
    test_command: str | None = None,
    test_timeout: int = 300,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    test_image: str | None = None,
    max_snapshot_mb: int = 256,
    max_write_mb: int = 64,
    keep_clone: bool = False,
    progress: "ProgressCallback | None" = None,
    modules: list[str] | None = None,
    minimum_score: int | None = None,
    ai_review_enabled: bool | None = None,
) -> ScanResult:
    workdir: Path | None = None
    try:
        _emit(progress, "preparation", "running", "Loading repository")
        workdir = load_repository(source, token=github_token)
        _emit(progress, "preparation", "completed", "Repository ready")
        result = run_scan(
            workdir, metadata=True, progress=progress, modules=modules,
            minimum_score=minimum_score,
        )

        fix_engine: FixEngine | None = None
        if dry_run_fixes or apply_fixes:
            fix_engine = FixEngine(workdir, dry_run=not apply_fixes)
            fix_engine.apply(result.findings)
            if apply_fixes and fix_engine.applied:
                # Re-scan the modified repository; verification below compares this
                # fresh result against the pre-fix findings.
                _emit(progress, "fixes", "running", "Re-scanning after applying fixes")
                result = run_scan(
                    workdir, metadata=True, progress=progress, modules=modules,
                    minimum_score=minimum_score,
                )

        _emit(progress, "ai", "running", "AI review (optional)")
        ai_reviews = (
            review_findings(workdir, result.findings, provider=get_ai_provider())
            if ai_review_enabled is not False
            else []
        )
        if ai_reviews:
            result.tests["ai_reviews"] = ai_reviews
            _emit(progress, "ai", "completed", f"AI review produced {len(ai_reviews)} review(s)")
        else:
            _emit(progress, "ai", "skipped", "AI review not configured or not applicable")

        if run_tests_flag:
            _emit(progress, "tests", "running", "Running tests in the isolated sandbox")
            result.tests.update(run_tests(
                workdir,

                command=test_command,
                timeout=test_timeout,
                max_memory_mb=max_memory_mb,
                max_cpu_seconds=max_cpu_seconds,
                test_image=test_image,
                max_snapshot_mb=max_snapshot_mb,
                max_write_mb=max_write_mb,
                no_execution=no_execution,
                explicit_permission=explicit_permission,
            ))
            _emit(
                progress, "tests", "completed", "Test execution finished",
                {"status": str(result.tests.get("status", ""))},
            )

        if fix_engine is not None:
            result.tests["fixes"] = {
                "applied": fix_engine.applied,
                "skipped": fix_engine.skipped,
                "dry_run": fix_engine.dry_run,
                # Verification requires both an applied change and a post-fix scan.
                "verification": (
                    fix_engine.verify(result.findings, tests=result.tests)
                    if (apply_fixes and fix_engine.applied)
                    else None
                ),
            }

        # Re-assess after potential fixes/tests.
        _emit(progress, "gate", "running", "Assessing release gate")
        assessment = assess(result, minimum_score=minimum_score)
        result._assessment = assessment

        if output_dir:
            _emit(progress, "report", "running", "Writing reports")
            from .reporters import write_reports
            write_reports(result, Path(output_dir))

        _emit(progress, "gate", "completed", f"Release gate: {assessment.get('gate', 'unknown')}", {"gate": assessment.get("gate")})
        return result
    finally:
        if workdir and not keep_clone and str(workdir) != str(Path(source).resolve()):
            cleanup_repo(workdir)


def run_web_scan(
    target: str,
    *,
    progress: "ProgressCallback | None" = None,
    minimum_score: int | None = None,
    limits: Any = None,
) -> ScanResult:
    """Run the read-only web checks against a deployed website or app URL.

    The target is not a repository: nothing is cloned and no file is read, so the
    result carries a single ``web`` module. No test suite exists for a live site,
    so the test status is recorded as skipped rather than invented - which is why
    a clean web scan reports a gate of "not verified" instead of "pass".
    """
    from .scanners.web import WebSecurityScanner

    _emit(progress, "preparation", "running", "Connecting to the target")
    scanner = WebSecurityScanner(target, limits=limits)
    _emit(progress, "scanner", "running", "Running web analysis", {"module": "web"})
    findings = scanner.scan()
    _emit(
        progress, "scanner", "completed", "web analysis complete",
        {"module": "web", "findings": len(findings)},
    )

    module = ModuleResult(
        module="web", status=Status.PASS, score=100.0, findings=findings, notes=scanner.notes
    )
    result = ScanResult(repo=Path(urlsplit(target).netloc or target), modules=[module])
    result.tests = {
        "status": Status.SKIP,
        "execution_mode": "not_applicable",
        "test_reason": "web_target_no_test_suite",
        "target_kind": "web",
    }

    _emit(progress, "gate", "running", "Assessing release gate")
    assessment = assess(result, minimum_score=minimum_score)
    result._assessment = assessment
    _emit(
        progress, "gate", "completed",
        f"Release gate: {assessment.get('gate', 'unknown')}", {"gate": assessment.get("gate")},
    )
    return result


def critical_summary(result: ScanResult) -> str:
    parts = [
        f"Overall score: {result.overall_score}",
        f"Critical: {result.critical_count}",
        f"High: {result.high_count}",
        release_decision(result),
    ]
    return " | ".join(parts)
