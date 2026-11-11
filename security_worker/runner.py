"""Bounded, cancellable worker jobs; every executable comes from the registry."""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .adapters import parse_output
from .inventory import inventory_map
from .normalize import Finding
from .profiles import validate_job_tools
from .registry import ScanRequest, ToolArgumentError, build_command, get_tool, validate_http_url, validate_port, validate_rate, validate_target_host
from .targets import TargetRejected, validate_target


class JobRunnerError(RuntimeError):
    pass


class WorkerRunner:
    """In-memory worker queue with hard concurrency and output caps.

    Container-level CPU, memory and process limits are applied by Docker (see
    docker-compose.yml). This class adds per-job wall-clock, cancellation and
    combined stdout/stderr limits. Job state is retained in-process for polling;
    the dashboard persists the authoritative history and findings.
    """

    def __init__(
        self,
        *,
        token: str,
        allowed_cidrs: tuple[str, ...] = (),
        max_concurrency: int = 1,
        max_timeout: int = 900,
        max_output_bytes: int = 8_000_000,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        templates_path: str = "/opt/vcqa/nuclei-templates",
    ):
        self.token = token
        self.allowed_cidrs = allowed_cidrs
        self.max_timeout = max(1, min(int(max_timeout), 3600))
        self.max_output_bytes = max(64_000, min(int(max_output_bytes), 32_000_000))
        self.wordlist = wordlist
        self.templates_path = templates_path
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._pool = ThreadPoolExecutor(max_workers=max(1, min(int(max_concurrency), 4)), thread_name_prefix="security-worker")

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def submit(self, payload: dict) -> dict:
        request = self._validate_request(payload)
        job_id = uuid.uuid4().hex
        event = threading.Event()
        record = {
            "id": job_id,
            "status": "queued",
            "request": request.to_dict(),
            "created_at": time.time(),
            "started_at": None,
            "completed_at": None,
            "findings": [],
            "tools": {},
            "evidence": {},
            "error": None,
        }
        with self._lock:
            self._jobs[job_id] = record
            self._cancel[job_id] = event
        self._pool.submit(self._run, job_id, request, event)
        return self._public_job(record)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            record = self._jobs.get(job_id)
            return self._public_job(record) if record else None

    def list(self, limit: int = 50) -> list[dict]:
        with self._lock:
            records = sorted(self._jobs.values(), key=lambda row: row["created_at"], reverse=True)
            return [self._public_job(row) for row in records[:max(1, min(int(limit), 100))]]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            record = self._jobs.get(job_id)
            event = self._cancel.get(job_id)
            if record is None or event is None or record["status"] in {"completed", "failed", "cancelled"}:
                return False
            event.set()
            if record["status"] == "queued":
                record["status"] = "cancelled"
                record["completed_at"] = time.time()
            return True

    def _validate_request(self, payload: dict) -> ScanRequest:
        if not isinstance(payload, dict):
            raise JobRunnerError("Job body must be a JSON object.")
        if set(payload) - {"profile", "tools", "target", "port", "rate_limit", "intrusive", "authorized_cidrs"}:
            raise JobRunnerError("Job contains unsupported fields.")
        intrusive = payload.get("intrusive") is True
        profile_key = str(payload.get("profile") or "").lower()
        tools_value = payload.get("tools")
        if tools_value is not None and (
            not isinstance(tools_value, list)
            or any(not isinstance(item, str) for item in tools_value)
        ):
            raise JobRunnerError("Tools must be a list of registered tool names.")
        try:
            profile, tools = validate_job_tools(profile_key, tools_value, intrusive=intrusive)
            port = validate_port(payload.get("port"))
            rate = validate_rate(payload.get("rate_limit"), maximum=profile.max_rate)
        except ToolArgumentError as exc:
            raise JobRunnerError(str(exc)) from exc
        target = payload.get("target")
        if not isinstance(target, str):
            raise JobRunnerError("A target URL or IP address is required.")
        target_cidrs = payload.get("authorized_cidrs") or []
        if not isinstance(target_cidrs, list) or any(not isinstance(v, str) for v in target_cidrs):
            raise JobRunnerError("Authorized CIDRs must be a list of CIDR strings.")
        try:
            target, _ = validate_target(
                target,
                worker_cidrs=self.allowed_cidrs,
                requested_cidrs=target_cidrs,
            )
            if "://" in target:
                url = validate_http_url(target)
                from urllib.parse import urlsplit

                parsed = urlsplit(url)
                host = validate_target_host(parsed.hostname or "")
                effective_port = port or parsed.port or (443 if parsed.scheme == "https" else 80)
                return ScanRequest(
                    profile.key, tuple(tools), url, host, effective_port, rate,
                    intrusive, tuple(target_cidrs),
                )
            host = validate_target_host(target)
            if any(get_tool(key).requires_url for key in tools):
                raise JobRunnerError("The selected profile requires an HTTP(S) URL target.")
            return ScanRequest(
                profile.key, tuple(tools), None, host, port, rate, intrusive, tuple(target_cidrs),
            )
        except (ToolArgumentError, TargetRejected) as exc:
            raise JobRunnerError(str(exc)) from exc

    @staticmethod
    def _public_job(record: dict) -> dict:
        return {
            "id": record["id"],
            "status": record["status"],
            "request": record["request"],
            "created_at": record["created_at"],
            "started_at": record["started_at"],
            "completed_at": record["completed_at"],
            "findings": record["findings"],
            "tools": record["tools"],
            "evidence": record["evidence"],
            "error": record["error"],
        }

    def _set(self, job_id: str, **fields) -> None:
        with self._lock:
            self._jobs[job_id].update(fields)

    def _run(self, job_id: str, request: ScanRequest, cancelled: threading.Event) -> None:
        with self._lock:
            if cancelled.is_set():
                return
            self._jobs[job_id]["status"] = "running"
            self._jobs[job_id]["started_at"] = time.time()
        findings: list[Finding] = []
        tool_results: dict[str, dict] = {}
        evidence: dict[str, str] = {}
        inventory = inventory_map()
        try:
            for key in request.tools:
                if cancelled.is_set():
                    self._set(job_id, status="cancelled")
                    break
                spec = get_tool(key)
                tool_state = inventory.get(key, {})
                if not tool_state.get("installed"):
                    tool_results[key] = {"status": "unavailable", "detail": tool_state.get("detail")}
                    continue
                if key == "nuclei" and not self._approved_templates_available():
                    tool_results[key] = {
                        "status": "unavailable",
                        "detail": "No approved Nuclei templates are mounted on this worker.",
                        "version": tool_state.get("version"),
                    }
                    continue
                if spec.kind == "service":
                    if key == "zap" and request.url:
                        raw, status = self._run_zap(request.url, cancelled)
                        if status == "cancelled":
                            self._set(job_id, status="cancelled")
                            break
                        if status != "completed":
                            tool_results[key] = {"status": status, "detail": raw[:1000], "version": tool_state.get("version")}
                            continue
                        try:
                            parsed = parse_output(key, raw, target=request.url, tool_version=tool_state.get("version"))
                        except Exception as exc:
                            tool_results[key] = {"status": "malformed_output", "detail": str(exc)}
                            continue
                        findings.extend(parsed)
                        evidence[key] = raw[:self.max_output_bytes]
                        tool_results[key] = {
                            "status": "completed",
                            "version": tool_state.get("version"),
                            "finding_count": len(parsed),
                            "mode": "passive",
                        }
                    else:
                        tool_results[key] = {
                            "status": "unavailable",
                            "detail": "ZAP requires an HTTP(S) target.",
                            "version": tool_state.get("version"),
                        }
                    continue
                # Re-resolve and enforce the worker's fixed scope immediately
                # before each executable starts. The deployment firewall remains
                # mandatory because arbitrary CLI tools resolve DNS themselves.
                target = request.url or request.host or ""
                validate_target(
                    target,
                    worker_cidrs=self.allowed_cidrs,
                    requested_cidrs=request.authorized_cidrs,
                )
                raw, status = self._run_binary(spec, request, cancelled)
                if status == "cancelled":
                    self._set(job_id, status="cancelled")
                    break
                if status != "completed":
                    tool_results[key] = {"status": status, "detail": raw[:1000]}
                    continue
                try:
                    parsed = parse_output(key, raw, target=target, tool_version=tool_state.get("version"))
                except Exception as exc:
                    tool_results[key] = {"status": "malformed_output", "detail": str(exc)}
                    continue
                findings.extend(parsed)
                evidence[key] = raw[:self.max_output_bytes]
                tool_results[key] = {
                    "status": "completed",
                    "version": tool_state.get("version"),
                    "finding_count": len(parsed),
                }
            with self._lock:
                job = self._jobs[job_id]
                if job["status"] != "cancelled":
                    final_status = (
                        "completed"
                        if any(row.get("status") == "completed" for row in tool_results.values())
                        else "failed"
                    )
                    job.update(
                        status=final_status,
                        findings=[item.to_dict() for item in findings],
                        tools=tool_results,
                        evidence=evidence,
                        error=None if final_status == "completed" else "No selected tool completed a scan.",
                    )
        except Exception as exc:
            self._set(job_id, status="failed", error=str(exc)[:1000], tools=tool_results)
        finally:
            self._set(job_id, completed_at=time.time())

    def _run_binary(self, spec, request: ScanRequest, cancelled: threading.Event) -> tuple[str, str]:
        timeout = min(spec.default_timeout, self.max_timeout)
        with tempfile.TemporaryDirectory(prefix="vcqa-job-") as directory:
            output_path = str(Path(directory) / "tool-output.json")
            output_file = Path(output_path)
            argv = build_command(
                spec,
                request,
                output_path=output_path,
                wordlist=self.wordlist,
                templates_path=self.templates_path,
            )
            executable = self._resolve_executable(spec)
            argv[0] = executable
            env = {
                "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
                "HOME": directory,
                "TMPDIR": directory,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
            try:
                proc = subprocess.Popen(
                    argv,
                    cwd=directory,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                    bufsize=0,
                )
            except OSError:
                return "Tool could not be started.", "unavailable"

            selector = selectors.DefaultSelector()
            stdout = bytearray()
            stderr = bytearray()
            streams = {proc.stdout: stdout, proc.stderr: stderr}
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            started = time.monotonic()
            exceeded = False
            timed_out = False
            try:
                while selector.get_map():
                    if cancelled.is_set():
                        self._terminate(proc)
                        return "", "cancelled"
                    if time.monotonic() - started > timeout:
                        timed_out = True
                        self._terminate(proc)
                        break
                    try:
                        file_output_size = output_file.stat().st_size
                    except OSError:
                        file_output_size = 0
                    if len(stdout) + len(stderr) + file_output_size > self.max_output_bytes:
                        exceeded = True
                        self._terminate(proc)
                        break
                    for key, _ in selector.select(timeout=0.1):
                        try:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                        except OSError:
                            chunk = b""
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        bucket = streams[key.fileobj]
                        bucket.extend(chunk)
                        if len(stdout) + len(stderr) > self.max_output_bytes:
                            exceeded = True
                            self._terminate(proc)
                            break
                    if exceeded:
                        break
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._terminate(proc)
            finally:
                selector.close()
                for stream in streams:
                    if not stream.closed:
                        stream.close()

            if timed_out:
                return "Tool execution timed out.", "timeout"
            if exceeded:
                return "Tool output exceeded the configured limit.", "output_limit"
            if output_file.is_file():
                try:
                    remaining = max(0, self.max_output_bytes - len(stdout) - len(stderr))
                    with output_file.open("rb") as stream:
                        output_bytes = stream.read(remaining + 1)
                    if len(output_bytes) > remaining:
                        return "Tool output exceeded the configured limit.", "output_limit"
                    output = output_bytes.decode("utf-8", "replace")
                except OSError:
                    output = ""
            else:
                output = stdout.decode("utf-8", "replace")
            if proc.returncode:
                detail = stderr.decode("utf-8", "replace")[:1000]
                return detail or f"Tool exited with status {proc.returncode}.", "failed"
            return output, "completed"

    @staticmethod
    def _resolve_executable(spec) -> str:
        import shutil

        configured = os.environ.get(spec.env_binary, "").strip() if spec.env_binary else ""
        executable = configured or spec.binary
        path = executable if os.path.isabs(executable) else shutil.which(executable)
        if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
            raise JobRunnerError(f"{spec.name} is not available on this worker.")
        return path

    def _approved_templates_available(self) -> bool:
        root = Path(self.templates_path)
        try:
            resolved = root.resolve(strict=True)
        except OSError:
            return False
        if not resolved.is_dir():
            return False
        return any(path.is_file() and path.suffix.lower() in {".yaml", ".yml"} for path in resolved.rglob("*"))

    def _run_zap(self, target: str, cancelled: threading.Event) -> tuple[str, str]:
        """Run only the ZAP spider + passive scanner; active scan is never called."""
        base = os.environ.get("ZAP_BASE_URL", "").strip().rstrip("/")
        if not base:
            return "ZAP_BASE_URL is not configured.", "unavailable"
        started = time.monotonic()
        scan_id = None
        try:
            started_payload = self._zap_call(
                base,
                "spider/action/scan",
                {"url": target, "maxChildren": "20", "recurse": "false"},
            )
            scan_id = str(started_payload.get("scan", ""))
            if not scan_id.isdigit():
                return "ZAP did not return a valid passive spider job id.", "failed"
            while time.monotonic() - started < min(get_tool("zap").default_timeout, self.max_timeout):
                if cancelled.is_set():
                    self._zap_call(base, "spider/action/stop", {"scanId": scan_id})
                    return "", "cancelled"
                progress = self._zap_call(base, "spider/view/status", {"scanId": scan_id})
                if str(progress.get("status")) == "100":
                    break
                time.sleep(0.5)
            else:
                self._zap_call(base, "spider/action/stop", {"scanId": scan_id})
                return "ZAP passive spider timed out.", "timeout"

            while time.monotonic() - started < min(get_tool("zap").default_timeout, self.max_timeout):
                if cancelled.is_set():
                    return "", "cancelled"
                pending = self._zap_call(base, "pscan/view/recordsToScan", {})
                try:
                    remaining = int(pending.get("recordsToScan", 0))
                except (TypeError, ValueError):
                    remaining = 0
                if remaining <= 0:
                    break
                time.sleep(0.5)
            alerts = self._zap_call(base, "core/view/alerts", {"baseurl": target, "start": "0", "count": "500"})
            return json.dumps(alerts, ensure_ascii=False), "completed"
        except (OSError, URLError, HTTPError, ValueError, JobRunnerError):
            if cancelled.is_set():
                return "", "cancelled"
            return "ZAP passive scan request failed.", "failed"

    @staticmethod
    def _zap_call(base: str, endpoint: str, params: dict) -> dict:
        query = urlencode(params)
        url = f"{base}/JSON/{endpoint}/" + (f"?{query}" if query else "")
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("ZAP_API_KEY", "").strip()
        if api_key:
            headers["X-ZAP-API-Key"] = api_key
        request = Request(url, headers=headers, method="GET")
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, new_url):
                return None
        try:
            with build_opener(NoRedirect()).open(request, timeout=10) as response:
                body = response.read(2_000_001)
        except (HTTPError, URLError, OSError) as exc:
            raise JobRunnerError("ZAP API request failed.") from exc
        if len(body) > 2_000_000:
            raise JobRunnerError("ZAP API response exceeded the configured limit.")
        value = json.loads(body.decode("utf-8", "replace"))
        if not isinstance(value, dict):
            raise JobRunnerError("ZAP API returned malformed data.")
        return value

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


__all__ = ["JobRunnerError", "WorkerRunner"]
