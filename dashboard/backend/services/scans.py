"""Bounded background scan runner.

Scans are long-running and must not block the request thread, so they run in a
bounded thread pool. Behaviour that the spec requires explicitly:

* **Bounded concurrency** — a fixed pool of ``max_concurrent_scans`` workers;
  extra scans queue instead of fanning out, and the queue itself is capped.
* **Persistent job state** — every transition is written to SQLite, so a scan
  interrupted by a restart is identifiable (see ``mark_interrupted_scans``).
* **Real events, never simulated progress** — the engine reports each stage
  through a callback that is persisted as a ``scan_events`` row and streamed
  over SSE. The dashboard never invents percentages.
* **No test execution without permission** — tests run only when the request
  opts in *and* the operator enabled ``VCQA_ALLOW_TEST_EXECUTION``.
* **The AI stage never gates a release** — AI review is recorded but the release
  gate is computed by the engine alone.
"""

from __future__ import annotations

import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from vibe_coding_qa.engine import run_pipeline, run_web_scan
from vibe_coding_qa.gates import coverage_gaps
from vibe_coding_qa.scanners.dependencies import reset_osv_enabled, set_osv_enabled

from .. import __version__
from ..config import Settings
from ..persistence.store import Store
from ..profiles import get_profile
from ..security import safe_error
from .paths import cached_clone_path
from .repositories import RepositoryService

_TERMINAL = ("completed", "failed", "cancelled")


def _git_head(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


class ScanRunner:
    def __init__(self, store: Store, settings: Settings, repositories: RepositoryService):
        self.store = store
        self.settings = settings
        self.repositories = repositories
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, settings.max_concurrent_scans), thread_name_prefix="vcqa-scan"
        )
        self._lock = threading.Lock()
        self._submitted: set[int] = set()

    # -------------------------------------------------------------- lifecycle
    @property
    def max_queue(self) -> int:
        return max(1, self.settings.max_concurrent_scans) * 4

    def active_scan_ids(self) -> set[int]:
        with self._lock:
            return set(self._submitted)

    def pending_count(self) -> int:
        _, total = self.store.list_scans(status="queued", limit=1)
        _, running = self.store.list_scans(status="running", limit=1)
        return total + running

    def scan_settings(self) -> dict:
        """Effective scan defaults (persisted operator settings, else env)."""
        from .settings import scan_settings

        return scan_settings(self.store, self.settings)

    def allow_test_execution(self) -> bool:
        """Tests never run unless the operator enabled the capability.

        Either the environment flag or the persisted setting enables it; both are
        deliberate operator actions.
        """
        return bool(self.scan_settings()["allow_test_execution"])

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def recover_interrupted(self) -> list[int]:
        """Mark scans a previous process left queued/running as failed."""
        return self.store.mark_interrupted_scans()

    # ----------------------------------------------------------------- create
    def create(self, *, repository: dict, profile_key: str, options: dict) -> dict:
        profile = get_profile(profile_key)
        if self.pending_count() >= self.max_queue:
            raise RuntimeError(
                "The scan queue is full. Wait for running scans to finish before starting more."
            )
        stored_options = dict(options)
        stored_options["profile"] = profile.key
        scan = self.store.create_scan(
            repository_id=repository["id"], profile=profile.key, options=stored_options
        )
        self.store.add_event(scan["id"], "queued", status="queued", message="Scan queued")
        self._submit(scan["id"])
        return scan

    def delete(self, scan_id: int) -> bool:
        """Remove a finished scan and its findings/events.

        A running or queued scan is refused: a worker is still writing to it, and
        deleting under the worker would leave it writing to a vanished row.
        """
        scan = self.store.get_scan(scan_id)
        if scan is None:
            return False
        if scan["status"] in ("queued", "running"):
            raise RuntimeError(
                "This scan is still running. Cancel it and wait for it to stop before deleting."
            )
        deleted = self.store.delete_scan(scan_id)
        if deleted:
            repository = self.store.get_repository(scan["repository_id"])
            if repository and repository.get("last_scan_id") == scan_id:
                remaining, _ = self.store.list_scans(repository_id=scan["repository_id"], limit=1)
                self.store.update_repository(
                    scan["repository_id"],
                    last_scan_id=remaining[0]["id"] if remaining else None,
                )
        return deleted

    def cancel(self, scan_id: int) -> dict | None:
        scan = self.store.get_scan(scan_id)
        if scan is None:
            return None
        if scan["status"] == "queued":
            updated = self.store.update_scan(
                scan_id,
                status="cancelled",
                completed_at=scan["created_at"],
                error="Cancelled before it started.",
            )
            self.store.add_event(scan_id, "cancelled", status="cancelled", message="Scan cancelled")
            return updated
        return scan

    def _submit(self, scan_id: int) -> None:
        with self._lock:
            if scan_id in self._submitted:
                return
            self._submitted.add(scan_id)
        try:
            self._pool.submit(self._run, scan_id)
        except RuntimeError:
            with self._lock:
                self._submitted.discard(scan_id)
            self._fail(scan_id, "The scan runner is shutting down.")

    # ---------------------------------------------------------------- execute
    def _run(self, scan_id: int) -> None:
        started = time.time()
        try:
            scan = self.store.get_scan(scan_id)
            if scan is None or scan["status"] not in ("queued", "running"):
                return
            repository = self.store.get_repository(scan["repository_id"])
            if repository is None:
                self._fail(scan_id, "The repository no longer exists.")
                return

            profile = get_profile(scan.get("profile"))
            options = scan.get("options") or {}
            defaults = self.scan_settings()

            self.store.update_scan(scan_id, status="running", started_at=_now())
            self.store.add_event(scan_id, "started", status="running", message="Scan started")

            def progress(stage: str, status: str, message: str = "", data: dict | None = None) -> None:
                self.store.add_event(scan_id, stage, status=status, message=message, data=data or {})

            if repository["source_type"] == "url":
                # A live target (website/app) is never cloned: run the read-only
                # web checks instead of the repository pipeline.
                result = run_web_scan(
                    repository["source"],
                    progress=progress,
                    minimum_score=profile.minimum_score,
                )
                self.store.add_event(
                    scan_id, "tests", status="skipped",
                    message="Test execution skipped: a live target has no test suite.",
                )
                if options.get("pentagi"):
                    from ..pentagi import probe as pentagi_probe

                    report = pentagi_probe()
                    if report.get("reachable"):
                        self.store.add_event(
                            scan_id, "pentagi", status="completed",
                            message="PentAGI is reachable (read-only status check; no flow was started).",
                            data={key: value for key, value in report.items() if key != "configured"},
                        )
                    else:
                        self.store.add_event(
                            scan_id, "pentagi", status="skipped",
                            message=f"PentAGI was not used: {report.get('detail', 'not configured')}",
                        )
                self._persist_result(scan_id, repository, result, profile, ai_requested=False)
                self._complete(scan_id, started, result)
                return

            source_path = self._prepare_source(repository, scan_id)
            if source_path is None:
                return

            static_only = bool(options.get("static_only"))
            run_tests_flag = bool(profile.run_tests) and not static_only
            explicit_permission = bool(options.get("explicit_permission")) and self.allow_test_execution()

            # ``None`` means "use the profile / operator default"; an explicit
            # value always wins.
            osv_option = options.get("osv")
            osv_enabled = bool(profile.osv) and (
                bool(defaults["osv_enabled"]) if osv_option is None else bool(osv_option)
            )
            ai_option = options.get("ai_review")
            ai_requested = bool(profile.ai_review) if ai_option is None else bool(ai_option)

            token = set_osv_enabled(osv_enabled)
            if osv_enabled:
                self.store.add_event(scan_id, "dependencies", status="running", message="OSV advisory lookups enabled")
            else:
                self.store.add_event(scan_id, "dependencies", status="skipped", message="OSV advisory lookups disabled")
            try:
                result = run_pipeline(
                    str(source_path),
                    run_tests_flag=run_tests_flag,
                    no_execution=static_only or not run_tests_flag,
                    explicit_permission=explicit_permission,
                    apply_fixes=False,
                    dry_run_fixes=False,
                    github_token=self.settings.github_token or None,
                    test_command=options.get("test_command") or None,
                    test_timeout=int(options.get("test_timeout") or defaults["test_timeout"]),
                    max_memory_mb=int(options.get("max_memory_mb") or defaults["max_memory_mb"]),
                    max_cpu_seconds=int(options.get("max_cpu_seconds") or defaults["max_cpu_seconds"]),
                    test_image=options.get("test_image") or defaults["test_image"],
                    max_snapshot_mb=int(options.get("max_snapshot_mb") or defaults["max_snapshot_mb"]),
                    max_write_mb=int(options.get("max_write_mb") or defaults["max_write_mb"]),
                    keep_clone=True,
                    progress=progress,
                    modules=list(profile.modules),
                    minimum_score=profile.minimum_score,
                    ai_review_enabled=ai_requested,
                )
            finally:
                reset_osv_enabled(token)

            if not run_tests_flag:
                reason = "static-only profile" if not profile.run_tests else "static-only requested"
                self.store.add_event(scan_id, "tests", status="skipped", message=f"Test execution skipped ({reason})")
            elif not explicit_permission:
                self.store.add_event(
                    scan_id, "tests", status="skipped",
                    message="Test execution skipped: explicit permission was not granted.",
                )

            self._persist_result(scan_id, repository, result, profile, ai_requested)

            self._complete(scan_id, started, result)
        except Exception as exc:  # noqa: BLE001 - never let a worker die silently
            self._fail(scan_id, safe_error(exc, "The scan failed while running."))
        finally:
            with self._lock:
                self._submitted.discard(scan_id)

    def _complete(self, scan_id: int, started: float, result) -> None:
        duration_ms = int((time.time() - started) * 1000)
        self.store.update_scan(scan_id, duration_ms=duration_ms)
        self.store.add_event(
            scan_id, "completed", status="completed",
            message=f"Scan complete: {result.gate}",
            data={"gate": result.gate, "score": result.overall_score},
        )

    # -------------------------------------------------------------- internals
    def _prepare_source(self, repository: dict, scan_id: int) -> Path | None:
        """Return a local directory to analyse, cloning remote repos on first use."""
        if repository["source_type"] == "local":
            path = Path(repository["source"])
            if not path.is_dir():
                self._fail(scan_id, "The local repository path is no longer available.")
                return None
            return path

        cache_dir = cached_clone_path(repository["source"])
        if cache_dir.is_dir() and (cache_dir / ".git").exists():
            self.store.add_event(scan_id, "preparation", status="running", message="Reusing the cached clone")
            return cache_dir
        self.store.add_event(scan_id, "preparation", status="running", message="Cloning the remote repository")
        try:
            from vibe_coding_qa.repo import clone_repo

            clone_repo(repository["source"], token=self.settings.github_token or None, workdir=cache_dir)
        except Exception as exc:  # noqa: BLE001
            self._fail(scan_id, safe_error(exc, "The remote repository could not be cloned."))
            return None
        return cache_dir

    def _persist_result(self, scan_id: int, repository: dict, result, profile, ai_requested: bool) -> None:
        tests = result.tests or {}
        findings = [f.to_dict() for f in result.findings]
        inserted = self.store.insert_findings(scan_id, repository["id"], findings)

        test_status = tests.get("status")
        test_status_value = getattr(test_status, "value", test_status)

        architecture = tests.get("architecture") or {}
        self.repositories.metadata_from_scan(repository["id"], architecture, True)
        # Persist the full profile so the Architecture/Dependencies pages render
        # instantly instead of re-walking the whole working tree on every request.
        if architecture:
            try:
                self.store.set_setting(f"profile:{repository['id']}", architecture)
            except Exception:  # noqa: BLE001
                pass

        # The release gate is decided by the engine alone. AI review is recorded
        # as advisory status and never influences the gate.
        if tests.get("ai_reviews"):
            ai_status = "completed"
        elif ai_requested:
            ai_status = "unavailable"
        else:
            ai_status = "not_requested"

        commit = _git_head(result.repo)
        self.store.update_scan(
            scan_id,
            status="completed",
            completed_at=_now(),
            commit_sha=commit,
            overall_score=result.overall_score,
            gate=result.gate,
            critical_count=result.critical_count,
            high_count=result.high_count,
            total_findings=inserted,
            test_status=test_status_value,
            tests_executed=tests.get("tests_executed"),
            tests_passed=tests.get("tests_passed"),
            tests_failed=tests.get("tests_failed"),
            tests_skipped=tests.get("tests_skipped"),
            scanner_versions={
                "dashboard_version": __version__,
                "profile": profile.key,
                "modules": [module.module for module in result.modules],
            },
            coverage_gaps=coverage_gaps(result),
            ai_review_status=ai_status,
        )
        self.store.update_repository(
            repository["id"], last_scan_id=scan_id, last_commit_sha=commit
        )

    def _fail(self, scan_id: int, message: str) -> None:
        self.store.update_scan(scan_id, status="failed", completed_at=_now(), error=message)
        self.store.add_event(scan_id, "failed", status="failed", message=message)


def _now() -> str:
    from ..persistence.database import utcnow

    return utcnow()
