"""Security worker tests use fake executable output and controlled local targets only."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dashboard.backend.persistence.database import Database
from dashboard.backend.persistence.store import Store
from dashboard.backend.security import ValidationError
from dashboard.backend.services.security_lab import SecurityLabService
from security_worker.adapters import MalformedToolOutput, parse_output
from security_worker.inventory import _verify_binary
from security_worker.normalize import Finding
from security_worker.registry import (
    ScanRequest,
    ToolArgumentError,
    build_command,
    get_tool,
    validate_http_url,
    validate_target_host,
)
from security_worker.runner import JobRunnerError, WorkerRunner
from security_worker.server import WorkerHTTPServer
from security_worker.targets import TargetRejected, validate_target


def _dns_answers(*addresses: str):
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))
        for address in addresses
    ]


class WorkerTargetTests(unittest.TestCase):
    def test_public_target_dns_and_private_cidr_are_checked(self):
        url, resolved = validate_target(
            "https://example.invalid",
            resolver=lambda *_args, **_kwargs: _dns_answers("10.12.0.4"),
            worker_cidrs=("10.12.0.0/16",),
            requested_cidrs=("10.12.0.0/24",),
        )
        self.assertEqual(url, "https://example.invalid")
        self.assertEqual(resolved, ["10.12.0.4"])

    def test_rejects_unapproved_private_and_mixed_dns_answers(self):
        with self.assertRaises(TargetRejected):
            validate_target(
                "https://example.invalid",
                resolver=lambda *_args, **_kwargs: _dns_answers("10.0.0.7"),
            )
        with self.assertRaises(TargetRejected):
            validate_target(
                "https://example.invalid",
                resolver=lambda *_args, **_kwargs: _dns_answers("10.1.0.2", "8.8.8.8"),
                worker_cidrs=("10.0.0.0/8",),
                requested_cidrs=("10.0.0.0/8",),
            )

    def test_rejects_metadata_and_cidr_scope_expansion(self):
        with self.assertRaises(TargetRejected):
            validate_target("169.254.169.254", worker_cidrs=("169.254.0.0/16",))
        with self.assertRaises(TargetRejected):
            validate_target(
                "10.1.1.8",
                worker_cidrs=("10.1.0.0/16",),
                requested_cidrs=("10.0.0.0/8",),
            )

    def test_urls_and_hosts_reject_command_injection(self):
        for target in ("-oN", "example.com;id", "bad host", "a/b", "127.0.0.1\n"):
            with self.subTest(target=target), self.assertRaises(ToolArgumentError):
                validate_target_host(target)
        for target in ("file:///etc/passwd", "https://user:pass@example.com", "https://example.com/#fragment"):
            with self.subTest(target=target), self.assertRaises(ToolArgumentError):
                validate_http_url(target)

    def test_fixed_argv_has_no_shell_and_rejects_arbitrary_tool(self):
        spec = get_tool("nmap")
        request = ScanRequest("network", ("nmap",), host="example.invalid", port=443, rate_limit=20)
        argv = build_command(spec, request)
        self.assertEqual(argv[0], "nmap")
        self.assertIn("example.invalid", argv)
        self.assertNotIn(";", " ".join(argv))
        with self.assertRaises(ToolArgumentError):
            get_tool("custom-command")


class WorkerAdapterTests(unittest.TestCase):
    def test_nmap_and_nuclei_outputs_normalize(self):
        xml = (
            '<nmaprun><host><ports><port protocol="tcp" portid="443">'
            '<state state="open"/><service name="https" product="nginx" version="1.0"/>'
            "</port></ports></host></nmaprun>"
        )
        nmap = parse_output("nmap", xml, target="10.1.1.2", tool_version="Nmap 7.95")
        self.assertEqual(nmap[0].severity, "info")
        self.assertIn("nginx", nmap[0].description)
        row = {
            "template-id": "cve-2099-1234",
            "matched-at": "https://example.invalid/",
            "info": {"name": "Example CVE", "severity": "high", "reference": ["CVE-2099-1234"]},
        }
        nuclei = parse_output("nuclei", json.dumps(row), target="https://example.invalid", tool_version="3.0")
        self.assertEqual(nuclei[0].severity, "high")
        self.assertEqual(nuclei[0].references, ["CVE-2099-1234"])

    def test_zap_passive_alerts_and_malformed_output(self):
        raw = json.dumps({
            "alerts": [{
                "alert": "Missing header",
                "riskdesc": "Low (Medium)",
                "confidence": "Medium",
                "instances": [{"uri": "https://example.invalid/", "evidence": "header absent"}],
                "solution": "Set the header.",
            }]
        })
        result = parse_output("zap", raw, target="https://example.invalid", tool_version="2.16")
        self.assertEqual(result[0].severity, "low")
        self.assertEqual(result[0].evidence, "header absent")
        with self.assertRaises(MalformedToolOutput):
            parse_output("nuclei", "{bad-json", target="https://example.invalid")

    def test_finding_normalizes_limits_and_cross_tool_dedupe(self):
        first = Finding(tool="nuclei", target="https://x.test", endpoint="https://x.test/a",
                        title="Missing header", severity="WARN", category="misconfig")
        second = Finding(tool="zap", target="https://x.test", endpoint="https://x.test/a",
                         title="Missing header", severity="medium", category="passive")
        self.assertEqual(first.dedupe_key, second.dedupe_key)
        oversized = Finding(tool="zap", target="x", title="X", severity="critical", evidence="x" * 9000)
        self.assertLessEqual(len(oversized.evidence), 8020)

    def test_inventory_reports_missing_tools_instead_of_claiming_installed(self):
        with patch("security_worker.inventory._binary_path", return_value=None):
            result = _verify_binary(get_tool("nmap"))
        self.assertFalse(result["installed"])
        self.assertEqual(result["status"], "unavailable")

    def test_inventory_removes_terminal_formatting_from_tool_versions(self):
        completed = subprocess.CompletedProcess(
            args=["testssl"], returncode=0,
            stdout=b"\x1b[1m\n#####################################################################\n  testssl version 3.2.4 from https://testssl.sh/\n",
        )
        with patch("security_worker.inventory._binary_path", return_value="/usr/bin/testssl"), \
             patch("security_worker.inventory.subprocess.run", return_value=completed):
            result = _verify_binary(get_tool("testssl"))
        self.assertEqual(result["version"], "testssl version 3.2.4 from https://testssl.sh/")


class WorkerRunnerTests(unittest.TestCase):
    def test_job_rejects_unregistered_tools_and_bad_cidr(self):
        runner = WorkerRunner(token="x" * 40, allowed_cidrs=("10.0.0.0/8",))
        with self.assertRaises(JobRunnerError):
            runner._validate_request({
                "profile": "network", "tools": ["arbitrary"],
                "target": "10.1.2.3", "authorized_cidrs": ["10.0.0.0/8"],
            })
        with self.assertRaises(JobRunnerError):
            runner._validate_request({
                "profile": "network", "tools": ["nmap"],
                "target": "10.1.2.3", "authorized_cidrs": ["192.168.0.0/16"],
            })
        runner.shutdown()

    def test_intrusive_tools_need_explicit_authorization(self):
        runner = WorkerRunner(token="x" * 40)
        with self.assertRaises(JobRunnerError):
            runner._validate_request({
                "profile": "web", "tools": ["sqlmap"], "target": "https://example.invalid",
                "intrusive": False,
            })
        runner.shutdown()

    @unittest.skipIf(os.name == "nt", "The security worker runs in Linux; pipe polling is POSIX-specific.")
    def test_output_file_is_capped_without_reading_it_unbounded(self):
        runner = WorkerRunner(token="x" * 40, max_output_bytes=64_000)
        spec = get_tool("nikto")
        request = ScanRequest("web", ("nikto",), url="https://example.invalid")
        script = (
            "from pathlib import Path; import sys; "
            "Path(sys.argv[1]).write_bytes(b'x' * 1000000)"
        )
        with patch.object(runner, "_resolve_executable", return_value=sys.executable), \
             patch("security_worker.runner.build_command", side_effect=lambda _spec, _request, **kwargs: [
                 sys.executable, "-c", script, kwargs["output_path"],
             ]):
            _output, status = runner._run_binary(spec, request, threading.Event())
        self.assertEqual(status, "output_limit")
        runner.shutdown()

    @unittest.skipIf(os.name == "nt", "The security worker runs in Linux; pipe polling is POSIX-specific.")
    def test_timeout_and_cancellation_stop_local_child_processes(self):
        runner = WorkerRunner(token="x" * 40, max_timeout=1)
        spec = get_tool("nmap")
        request = ScanRequest("network", ("nmap",), host="127.0.0.1")
        with patch.object(runner, "_resolve_executable", return_value=sys.executable), \
             patch("security_worker.runner.build_command", return_value=[sys.executable, "-c", "import time; time.sleep(5)"]):
            output, status = runner._run_binary(spec, request, threading.Event())
        self.assertEqual(status, "timeout")

        event = threading.Event()
        result = []
        runner.max_timeout = 30
        with patch.object(runner, "_resolve_executable", return_value=sys.executable), \
             patch("security_worker.runner.build_command", return_value=[sys.executable, "-c", "import time; time.sleep(5)"]):
            thread = threading.Thread(target=lambda: result.append(runner._run_binary(spec, request, event)))
            thread.start()
            time.sleep(0.15)
            event.set()
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result[0][1], "cancelled")
        runner.shutdown()


class WorkerHTTPTests(unittest.TestCase):
    def test_authentication_required_and_revocation_disables_jobs(self):
        token = "worker-token-" + "a" * 40
        runner = WorkerRunner(token=token)
        server = WorkerHTTPServer(("127.0.0.1", 0), runner=runner, token=token, logger=lambda _line: None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(HTTPError) as caught:
                urlopen(base + "/health", timeout=2)
            self.assertEqual(caught.exception.code, 401)
            request = Request(base + "/health", headers={"Authorization": f"Bearer {token}"})
            with urlopen(request, timeout=2) as response:
                self.assertEqual(json.load(response)["status"], "ok")
            server.token = "revoked-token"
            with self.assertRaises(HTTPError) as revoked:
                urlopen(request, timeout=2)
            self.assertEqual(revoked.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            runner.shutdown()
            thread.join(timeout=2)


class SecurityStoreTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)

    def tearDown(self):
        self.db.close()

    def _job(self, target_id: int) -> dict:
        return self.store.create_security_job(
            target_id=target_id, worker_id=None, profile="basic", tools=["nuclei"]
        )

    def test_migration_and_cross_tool_dedup_keep_occurrences(self):
        target = self.store.create_security_target(
            value="https://example.invalid", ownership_confirmed=True
        )
        first_job = self._job(target["id"])
        second_job = self._job(target["id"])
        finding, created = self.store.upsert_security_finding(
            job_id=first_job["id"], target_id=target["id"],
            fingerprint="one", dedupe_key="endpoint|missing-header",
            tool="nuclei", tool_version="3.0", target=target["value"],
            endpoint=target["value"], title="Missing header", category="web",
            description=None, severity="medium", confidence="high", evidence=None,
            remediation=None, references=[], detected_at="2026-11-11T00:00:00+00:00",
        )
        self.assertTrue(created)
        duplicate, created = self.store.upsert_security_finding(
            job_id=second_job["id"], target_id=target["id"],
            fingerprint="two", dedupe_key="endpoint|missing-header",
            tool="zap", tool_version="2.16", target=target["value"],
            endpoint=target["value"], title="Missing header", category="configuration",
            description=None, severity="low", confidence="medium", evidence="raw",
            remediation=None, references=[], detected_at="2026-11-11T00:00:01+00:00",
        )
        self.assertFalse(created)
        self.assertEqual(finding["id"], duplicate["id"])
        self.assertEqual(set(duplicate["tools"]), {"nuclei", "zap"})
        rows, total = self.store.list_security_findings(job_id=second_job["id"])
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["id"], finding["id"])
        self.store.set_security_finding_verification(
            finding["id"], "pending", verification_job_id=second_job["id"]
        )
        self.assertEqual(self.store.get_security_finding(finding["id"])["verification_job_id"], second_job["id"])

    def test_worker_token_revocation(self):
        service = SecurityLabService(self.store)
        row = service.register_worker(
            name="local-worker",
            base_url="http://security-worker:8765",
            token="secret-" + "x" * 40,
            placement="same_vps",
            allowed_networks=[],
        )
        self.assertNotIn("token", row)
        service.revoke_worker(row["id"])
        revoked = self.store.get_security_worker(row["id"])
        self.assertFalse(revoked["enabled"])
        self.assertIsNone(revoked["token"])
        service.shutdown()

    def test_worker_dns_is_revalidated_before_each_request(self):
        service = SecurityLabService(self.store)
        with patch(
            "dashboard.backend.services.security_lab.socket.getaddrinfo",
            side_effect=[_dns_answers("8.8.8.8"), _dns_answers("8.8.8.8")],
        ):
            public = service.register_worker(
                name="remote-worker",
                base_url="https://worker.example.test",
                token="secret-" + "y" * 40,
                placement="remote_vps",
                allowed_networks=[],
            )
        worker = self.store.get_security_worker(public["id"])
        with patch(
            "dashboard.backend.services.security_lab.socket.getaddrinfo",
            return_value=_dns_answers("169.254.169.254"),
        ), patch("dashboard.backend.services.security_lab.httpx.Client") as client:
            with self.assertRaises(ValidationError):
                service._worker_request(worker, "GET", "/health")
        client.assert_not_called()
        service.shutdown()

    def test_follow_up_scan_marks_findings_by_deterministic_evidence(self):
        service = SecurityLabService(self.store)
        target = self.store.create_security_target(
            value="https://example.invalid", ownership_confirmed=True
        )

        def create_finding(title: str, dedupe_key: str) -> dict:
            original_job = self._job(target["id"])
            finding, _ = self.store.upsert_security_finding(
                job_id=original_job["id"], target_id=target["id"],
                fingerprint=dedupe_key, dedupe_key=dedupe_key,
                tool="nuclei", tool_version="3.0", target=target["value"],
                endpoint=target["value"], title=title, category="web",
                description=None, severity="medium", confidence="high",
                evidence=None, remediation=None, references=[],
                detected_at="2026-11-11T00:00:00+00:00",
            )
            return finding

        disappeared = create_finding("Disappeared", "endpoint|disappeared")
        absent_job = self._job(target["id"])
        self.store.set_security_finding_verification(
            disappeared["id"], "pending", verification_job_id=absent_job["id"]
        )
        service._finalize_verifications(absent_job["id"], "completed")
        self.assertEqual(
            self.store.get_security_finding(disappeared["id"])["verification_status"],
            "verified",
        )

        present = create_finding("Still present", "endpoint|still-present")
        present_job = self._job(target["id"])
        self.store.upsert_security_finding(
            job_id=present_job["id"], target_id=target["id"],
            fingerprint="present-again", dedupe_key="endpoint|still-present",
            tool="nuclei", tool_version="3.0", target=target["value"],
            endpoint=target["value"], title="Still present", category="web",
            description=None, severity="medium", confidence="high", evidence="matched",
            remediation=None, references=[], detected_at="2026-11-11T00:00:01+00:00",
        )
        self.store.set_security_finding_verification(
            present["id"], "pending", verification_job_id=present_job["id"]
        )
        service._finalize_verifications(present_job["id"], "completed")
        self.assertEqual(
            self.store.get_security_finding(present["id"])["verification_status"],
            "still_present",
        )

        inconclusive = create_finding("Incomplete verification", "endpoint|inconclusive")
        failed_job = self._job(target["id"])
        self.store.set_security_finding_verification(
            inconclusive["id"], "pending", verification_job_id=failed_job["id"]
        )
        service._finalize_verifications(failed_job["id"], "failed")
        self.assertEqual(
            self.store.get_security_finding(inconclusive["id"])["verification_status"],
            "inconclusive",
        )
        service.shutdown()


if __name__ == "__main__":
    unittest.main()
