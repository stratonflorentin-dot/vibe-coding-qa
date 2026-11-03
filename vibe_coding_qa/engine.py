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
            notes=getattr(scanner, "notes", []),
        ))
    result = ScanResult(repo=repo, modules=modules)
    assess(result)
    if metadata:
        result.tests["repo_metadata"] = repo_metadata(repo)
        result.tests["architecture"] = analyze_repo(repo).to_dict()
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


def _copy_test_snapshot(repo: Path) -> tuple[Path, Path]:
    source = repo.resolve()
    temporary_root = Path(tempfile.mkdtemp(prefix="vcqa-test-snapshot-"))
    snapshot = temporary_root / "repo"
    snapshot.mkdir()
    excluded_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".pytest_cache", ".aws", ".ssh", ".gnupg"}
    excluded_files = {".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "credentials.json", "service-account.json"}
    excluded_extensions = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer"}
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name for name in directories
            if name not in excluded_dirs and not (current_path / name).is_symlink()
        ]
        relative_dir = current_path.relative_to(source)
        target_dir = snapshot / relative_dir
        target_dir.mkdir(parents=True, exist_ok=True)
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
                content = source_file.read_bytes()
                try:
                    text = content.decode("utf-8")
                    target_file = target_dir / name
                    target_file.write_text(redact_secrets(text), encoding="utf-8")
                except UnicodeDecodeError:
                    shutil.copyfile(source_file, target_dir / name)
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


def run_tests(
    repo: Path,
    command: str | None = None,
    timeout: int = 300,
    no_execution: bool = False,
    explicit_permission: bool = False,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    test_image: str | None = None,
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

    if timeout <= 0 or max_memory_mb <= 0 or max_cpu_seconds <= 0:
        return {
            "status": Status.SKIP,
            "command": command,
            "summary": "Test timeout, memory limit, and CPU limit must all be positive values.",
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

    temporary_root, snapshot = _copy_test_snapshot(repo)
    container_name = f"vcqa-test-{uuid.uuid4().hex[:12]}"
    resource_info = {
        "memory_mb": max_memory_mb,
        "cpu_seconds": max_cpu_seconds,
        "enforced": True,
        "environment_allowlisted": True,
        "isolation": "docker-network-disabled-read-only-rootfs",
        "snapshot_excludes_secrets": True,
    }
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
        "--tmpfs", "/tmp:rw,nosuid,size=64m",
        "--mount", f"type=bind,source={snapshot},target=/workspace",
        "--workdir", "/workspace",
        "--env", "CI=true",
        "--env", "NODE_ENV=test",
        "--env", "HOME=/tmp",
        image,
        *cmd,
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
        skipped = _count_skipped(output)
        status = Status.FAIL if output_exceeded or result.returncode != 0 else Status.PASS
        return {
            "status": status,
            "command": command_str,
            "returncode": result.returncode,
            "summary": summary,
            "stdout": redact_secrets(result.stdout),
            "stderr": redact_secrets(result.stderr),
            "duration_ms": duration_ms,
            "skipped": skipped,
            "output_truncated": output_exceeded,
            "execution_mode": "docker_isolated",
            "resource_limits": resource_info,
            "warning": "Tests ran in a restricted Docker container using a secret-filtered snapshot, no network, explicit resource limits, and bounded output. Container isolation is not a proof against all kernel/runtime vulnerabilities.",
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
    explicit_permission: bool = False,
    apply_fixes: bool = False,
    dry_run_fixes: bool = True,
    github_token: str | None = None,
    test_command: str | None = None,
    test_timeout: int = 300,
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
    test_image: str | None = None,
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
            result.tests.update(run_tests(
                workdir,

                command=test_command,
                timeout=test_timeout,
                max_memory_mb=max_memory_mb,
                max_cpu_seconds=max_cpu_seconds,
                test_image=test_image,
                no_execution=no_execution,
                explicit_permission=explicit_permission,
            ))

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
