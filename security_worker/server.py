"""Authenticated HTTP API for an independently deployed security worker.

The worker does not expose a Docker socket, accept command strings, or bind a
host port by default in the supplied compose file. The main dashboard makes
outbound HTTPS requests to these endpoints using a per-worker bearer token.
"""

from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from . import __version__
from .inventory import tool_inventory
from .profiles import PROFILES
from .runner import JobRunnerError, WorkerRunner

MAX_BODY_BYTES = 65_536


def _csv(name: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in os.environ.get(name, "").split(",") if part.strip())


def _config() -> dict:
    token = os.environ.get("VCQA_WORKER_TOKEN", "").strip()
    if len(token) < 32:
        raise RuntimeError("VCQA_WORKER_TOKEN must contain at least 32 characters.")
    return {
        "token": token,
        "host": os.environ.get("VCQA_WORKER_HOST", "0.0.0.0"),
        "port": int(os.environ.get("VCQA_WORKER_PORT", "8765")),
        "allowed_cidrs": _csv("VCQA_WORKER_ALLOWED_CIDRS"),
        "concurrency": int(os.environ.get("VCQA_WORKER_CONCURRENCY", "1")),
        "timeout": int(os.environ.get("VCQA_WORKER_MAX_TIMEOUT", "900")),
        "output_bytes": int(os.environ.get("VCQA_WORKER_MAX_OUTPUT_BYTES", "8000000")),
        "wordlist": os.environ.get("VCQA_WORKER_WORDLIST", "/usr/share/wordlists/dirb/common.txt"),
        "templates_path": os.environ.get("VCQA_NUCLEI_TEMPLATES", "/opt/vcqa/nuclei-templates"),
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "VCQA-Security-Worker"
    sys_version = ""

    def log_message(self, format: str, *args) -> None:
        # Do not log authorization headers, query strings, or target URLs.
        self.server.logger(f"{self.client_address[0]} {self.command} {urlsplit(self.path).path}")

    @property
    def runner(self) -> WorkerRunner:
        return self.server.runner

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            return False
        return hmac.compare_digest(supplied[7:].strip(), self.server.token)

    def _send(self, status: int, value: dict | list) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            raise JobRunnerError("A valid Content-Length is required.") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise JobRunnerError("Request body exceeds the worker limit.")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise JobRunnerError("Request body must be a JSON object.")
        return value

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        if not self._authorized():
            self._send(401, {"detail": "Worker authentication required."})
            return
        if path == "/health":
            self._send(200, {
                "status": "ok",
                "worker_version": __version__,
                "profiles": [profile.to_dict() for profile in PROFILES.values()],
            })
            return
        if path == "/tools":
            # Remove local executable paths; inventory only reports verified
            # availability and the actual version string.
            tools = []
            for item in tool_inventory():
                tools.append({key: value for key, value in item.items() if key != "executable"})
            self._send(200, {"items": tools})
            return
        if path == "/jobs":
            self._send(200, {"items": self.runner.list()})
            return
        if path.startswith("/jobs/"):
            job_id = path.split("/", 2)[2]
            job = self.runner.get(job_id)
            self._send(200, job) if job else self._send(404, {"detail": "Job not found."})
            return
        self._send(404, {"detail": "Endpoint not found."})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/")
        if not self._authorized():
            self._send(401, {"detail": "Worker authentication required."})
            return
        try:
            if path == "/jobs":
                self._send(202, self.runner.submit(self._read_json()))
                return
            if path.startswith("/jobs/") and path.endswith("/cancel"):
                job_id = path.split("/")[2]
                if not self.runner.cancel(job_id):
                    self._send(409, {"detail": "Job is missing or already terminal."})
                else:
                    self._send(202, {"id": job_id, "status": "cancellation_requested"})
                return
        except (JobRunnerError, UnicodeError, json.JSONDecodeError) as exc:
            self._send(400, {"detail": str(exc)[:500]})
            return
        self._send(404, {"detail": "Endpoint not found."})

    def do_PUT(self) -> None:  # noqa: N802
        self._send(405, {"detail": "Method not allowed."})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send(405, {"detail": "Method not allowed."})


class WorkerHTTPServer(HTTPServer):
    def __init__(self, address, *, runner: WorkerRunner, token: str, logger=print):
        super().__init__(address, _Handler)
        self.runner = runner
        self.token = token
        self.logger = logger


def main() -> None:
    config = _config()
    runner = WorkerRunner(
        token=config["token"],
        allowed_cidrs=config["allowed_cidrs"],
        max_concurrency=config["concurrency"],
        max_timeout=config["timeout"],
        max_output_bytes=config["output_bytes"],
        wordlist=config["wordlist"],
        templates_path=config["templates_path"],
    )
    server = WorkerHTTPServer(
        (config["host"], config["port"]),
        runner=runner,
        token=config["token"],
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        runner.shutdown()


if __name__ == "__main__":
    main()
