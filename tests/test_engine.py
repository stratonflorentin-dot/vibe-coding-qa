import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa.engine import run_pipeline, run_scan, run_tests
from vibe_coding_qa.fixes import FixEngine
from vibe_coding_qa.gates import assess, coverage_gaps, release_decision
from vibe_coding_qa.repo import load_repository
from vibe_coding_qa.scanners.security import SecurityScanner
from vibe_coding_qa.scanners.web import WebResponse, WebSecurityScanner


# Synthetic credentials assembled at runtime so no secret literal is committed
# (identical runtime value; see tests/test_regression.py for the rationale).
def _assemble(*parts: str) -> str:
    return "".join(parts)


_OPENAI_KEY = _assemble("sk-", "123456789012345678901234")
_OPENAI_KEY_ALT = _assemble("sk-", "abc123def456ghi789012")


class EngineTests(TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="vcqa-sample-"))
        (self.repo / "src").mkdir()
        (self.repo / "package.json").write_text('{"name":"sample","scripts":{"test":"exit 0"}}')
        (self.repo / "src" / "client.ts").write_text(
            "\n"
            'const API_KEY = "' + _OPENAI_KEY + '";\n'
            'console.log("debug");\n'
            "function submit() { eval(userInput); }\n"
        )
        (self.repo / "src" / "db.sql").write_text("""
CREATE TABLE users (id uuid primary key);
CREATE TABLE orders (id uuid primary key);
""")
        (self.repo / ".env").write_text("SECRET=password123\n")

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_scan_detects_client_secret_and_missing_rls(self):
        result = run_scan(self.repo)
        rules = {f.rule for f in result.findings}
        # Real-looking credential should be detected
        self.assertIn("security:openai-key", rules)
        self.assertIn("database:table-without-rls", rules)
        self.assertTrue(result.release_blocked)

    def test_scan_detects_critical_client_secret(self):
        # Critical patterns (OpenAI/Stripe/AWS/Supabase) in client files trigger client-side-secret.
        (self.repo / "src" / "client-critical.ts").write_text('const OPENAI_KEY = "' + _OPENAI_KEY_ALT + '";\n')
        result = run_scan(self.repo)
        rules = {f.rule for f in result.findings}
        self.assertIn("security:client-side-secret", rules)
        self.assertTrue(result.release_blocked)

    def test_gate_blocks_release_for_critical_findings(self):
        result = run_scan(self.repo)
        assess(result)
        self.assertIn("BLOCKED", release_decision(result))

    def test_fix_engine_can_remove_console_log_in_dry_run(self):
        result = run_scan(self.repo)
        engine = FixEngine(self.repo, dry_run=True)
        engine.apply(result.findings)
        applied_rules = {a["finding"]["rule"] for a in engine.applied}
        self.assertIn("quality:console-log-in-production", applied_rules)
        # File should be unchanged in dry-run.
        self.assertIn("console.log", (self.repo / "src" / "client.ts").read_text())

    def test_run_tests_uses_package_json_script_in_sandbox(self):
        def fake_docker_run(command, **kwargs):
            if command[1:2] == ["info"]:
                return subprocess.CompletedProcess(command, 0, "27.0.0", "")
            if command[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(command, 0, "[]", "")
            if command[1:2] == ["run"]:
                return subprocess.CompletedProcess(command, 0, "Tests:       1 passed, 1 total", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
            "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run
        ), patch(
            "vibe_coding_qa.engine._run_bounded_process",
            return_value=(subprocess.CompletedProcess(["docker", "run"], 0, "Tests:       1 passed, 1 total", ""), False, False),
        ):
            result = run_tests(self.repo, explicit_permission=True)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["execution_mode"], "docker_isolated")
        self.assertEqual(result["command"], "npm run test")

    def test_clean_repo_has_open_gate(self):
        clean = Path(tempfile.mkdtemp(prefix="vcqa-clean-"))
        (clean / "README.md").write_text(
            "# clean\n\nData Protection Officer: privacy@example.com\n"
            "Registered with the Personal Data Protection Commission.\n"
            "Unsubscribe: POST /unsubscribe returns 200 immediately.\n"
        )
        try:
            result = run_scan(clean)
            assess(result)
            self.assertGreaterEqual(result.overall_score, 95.0)
            self.assertIn("NOT VERIFIED", release_decision(result))
            self.assertFalse(result.release_blocked)
        finally:
            shutil.rmtree(clean, ignore_errors=True)


class RepoLoaderTests(TestCase):
    def test_load_local_path(self):
        path = load_repository(str(Path(__file__).resolve().parent.parent))
        self.assertTrue(path.exists())


class _FakeFetcher:
    """Deterministic fetcher so the web scanner is tested without any network."""

    def __init__(self, base: WebResponse, routes: dict | None = None):
        self.base = base
        self.routes = routes or {}
        self.requests = 0

    def get(self, url, *, follow=True, headers=None):
        self.requests += 1
        if url == self.base.url:
            return self.base
        if url in self.routes:
            return self.routes[url]
        return WebResponse(url=url, status=404, headers={"content-type": "text/plain"}, body=b"not found")

    def options(self, url):
        self.requests += 1
        return WebResponse(url=url, status=204, headers={})


class WebScannerTests(TestCase):
    def _scanner(self, base: WebResponse, routes: dict | None = None) -> WebSecurityScanner:
        fetcher = _FakeFetcher(base, routes)
        return WebSecurityScanner(base.url, fetcher=fetcher)

    def test_flags_plain_http_and_exposed_env_file(self):
        base = WebResponse(
            url="http://example.test",
            status=200,
            headers={"content-type": "text/html"},
            body=b"<!doctype html><html><body>hello</body></html>",
        )
        routes = {
            "http://example.test/.env": WebResponse(
                url="http://example.test/.env",
                status=200,
                headers={"content-type": "text/plain"},
                body=b"SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n",
            ),
        }
        findings = self._scanner(base, routes).scan()
        rules = {f.rule for f in findings}
        self.assertIn("web:insecure-transport", rules)
        self.assertIn("web:exposed-env-file", rules)

        env = next(f for f in findings if f.rule == "web:exposed-env-file")
        self.assertEqual(env.severity.value, "critical")
        self.assertEqual(str(env.file), "/.env")
        # A URL path is the location, so there is no fake source line number.
        self.assertEqual(env.line, 0)

    def test_catchall_routing_does_not_produce_false_positives(self):
        body = b"<!doctype html><html><body>single page app</body></html>"
        base = WebResponse(
            url="http://example.test",
            status=200,
            headers={"content-type": "text/html"},
            body=body,
        )
        # Every unknown path answers 200 with the app shell: that is routing, not exposure.
        routes = {
            "http://example.test/.DS_Store": WebResponse(
                url="http://example.test/.DS_Store",
                status=200,
                headers={"content-type": "application/octet-stream"},
                body=body,
            ),
            "http://example.test/backup.zip": WebResponse(
                url="http://example.test/backup.zip",
                status=200,
                headers={"content-type": "application/zip"},
                body=body,
            ),
        }
        rules = {f.rule for f in self._scanner(base, routes).scan()}
        self.assertNotIn("web:exposed-ds-store", rules)
        self.assertNotIn("web:exposed-backup", rules)

    def test_missing_security_headers_are_reported(self):
        base = WebResponse(
            url="http://example.test",
            status=200,
            headers={"content-type": "text/html"},
            body=b"<html><body>hi</body></html>",
        )
        rules = {f.rule for f in self._scanner(base).scan()}
        self.assertIn("web:missing-csp", rules)
        self.assertIn("web:clickjacking", rules)

    def test_web_target_gaps_are_web_specific(self):
        from vibe_coding_qa import ModuleResult, ScanResult, Status

        result = ScanResult(repo=Path("example.test"), modules=[ModuleResult(module="web", status=Status.PASS, score=100.0)])
        result.tests = {"status": Status.SKIP, "execution_mode": "not_applicable", "target_kind": "web"}
        gaps = coverage_gaps(result)
        self.assertTrue(any("black-box" in gap for gap in gaps))
        # Repository-oriented gaps (lockfiles, CI, .gitignore) must not appear.
        self.assertFalse(any("lockfile" in gap for gap in gaps))


if __name__ == "__main__":
    import unittest
    unittest.main()
