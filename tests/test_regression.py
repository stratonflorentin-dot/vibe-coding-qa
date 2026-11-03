import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa import Finding, ModuleResult, ScanResult, Severity, Status
from vibe_coding_qa.ai_review import OpenRouterAIProvider, get_ai_provider
from vibe_coding_qa.engine import _run_bounded_process, run_scan, run_tests
from vibe_coding_qa.fixes import FixEngine
from vibe_coding_qa.gates import assess, release_decision
from vibe_coding_qa.reporters import html_report, json_report, markdown_report
from vibe_coding_qa.scanners.dependencies import DependencyScanner
from vibe_coding_qa.repo import clone_repo
from vibe_coding_qa.cli import main as cli_main


SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def fake_docker_run(run_returncode=0, run_stdout="", run_stderr=""):
    def run(command, **kwargs):
        if command[1:2] == ["info"]:
            return subprocess.CompletedProcess(command, 0, "27.0.0", "")
        if command[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "[]", "")
        return subprocess.CompletedProcess(command, 0, "", "")
    return run


def fake_sandbox_run(run_returncode=0, run_stdout="", run_stderr=""):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, run_returncode, run_stdout, run_stderr), False, False
    return run


class SampleRepoTests(TestCase):
    def test_vulnerable_repo_detects_expanded_security_issues(self):
        repo = SAMPLES / "vulnerable_repo"
        result = run_scan(repo)
        rules = {f.rule for f in result.findings}
        self.assertIn("security:generic-api-key", rules)
        self.assertIn("security:client-side-secret", rules)
        self.assertIn("security:unsafe-shell-execution", rules)
        self.assertIn("security:path-traversal-risk", rules)
        self.assertIn("security:ssrf-risk", rules)
        self.assertIn("security:exposed-debug-endpoint", rules)
        self.assertIn("security:firebase-insecure-rules", rules)
        self.assertIn("database:table-without-rls", rules)
        self.assertIn("dependencies:missing-lockfile", rules)
        self.assertIn("dependencies:vulnerable-dependency", rules)
        self.assertTrue(result.release_blocked)

    def test_clean_repo_has_open_gate(self):
        repo = SAMPLES / "clean_repo"
        result = run_scan(repo)
        assess(result)
        self.assertFalse(result.release_blocked)
        self.assertGreaterEqual(result.overall_score, 95.0)
        self.assertIn("NOT VERIFIED", release_decision(result))

    def test_rls_schema_qualified_tables(self):
        """Test that schema-qualified table names are handled correctly."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-schema-"))
        try:
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001_schema.sql").write_text("""
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE auth.users (id uuid primary key, email text);
CREATE TABLE public.posts (id uuid primary key, user_id uuid references auth.users(id));
ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_own ON auth.users FOR ALL USING (auth.uid() = id);
-- public.posts has no RLS
""")
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            # auth.users has RLS and policy - should be OK
            # public.posts has no RLS - should be flagged
            self.assertIn("database:table-without-rls", rules)
            # Check that the finding references public.posts
            table_findings = [f for f in result.findings if f.rule == "database:table-without-rls"]
            self.assertTrue(any("public.posts" in str(f.file) or "public.posts" in f.message for f in table_findings))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_state_is_tracked_across_migrations(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-migrations-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_table.sql").write_text("CREATE TABLE app.posts (id integer);\n", encoding="utf-8")
            (migrations / "002_rls.sql").write_text("ALTER TABLE app.posts ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
            (migrations / "003_policy.sql").write_text(
                "CREATE POLICY post_owner ON app.posts FOR SELECT TO authenticated USING (auth.uid() = owner_id);\n",
                encoding="utf-8",
            )
            result = run_scan(repo)
            rules = {finding.rule for finding in result.findings}
            self.assertNotIn("database:table-without-rls", rules)
            self.assertNotIn("database:policy-without-rls-enabled", rules)
            self.assertNotIn("security:missing-rls", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_policy_without_rls_across_migrations_uses_policy_location(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-policy-location-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_table.sql").write_text("CREATE TABLE app.records (id integer);\n", encoding="utf-8")
            policy_file = migrations / "002_policy.sql"
            policy_file.write_text("CREATE POLICY open_records ON app.records FOR SELECT USING (true);\n", encoding="utf-8")
            result = run_scan(repo)
            finding = next(f for f in result.findings if f.rule == "database:policy-without-rls-enabled")
            self.assertEqual(finding.file.as_posix(), "migrations/002_policy.sql")
            self.assertEqual(finding.line, 1)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_enabled_without_policy_is_reported(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-no-policy-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_schema.sql").write_text(
                "CREATE TABLE app.audit_log (id integer);\nALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;\n",
                encoding="utf-8",
            )
            result = run_scan(repo)
            self.assertIn("database:rls-enabled-without-policy", {f.rule for f in result.findings})
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_disabled_in_later_migration_is_not_treated_as_enabled(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-disabled-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_enable.sql").write_text(
                "CREATE TABLE app.audit_log (id integer);\nALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;\n",
                encoding="utf-8",
            )
            (migrations / "002_disable.sql").write_text(
                "ALTER TABLE app.audit_log DISABLE ROW LEVEL SECURITY;\n",
                encoding="utf-8",
            )
            result = run_scan(repo)
            self.assertIn("database:table-without-rls", {f.rule for f in result.findings})
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_dropped_rls_policy_is_not_counted_as_active(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-drop-policy-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_schema.sql").write_text(
                "CREATE TABLE app.records (id integer);\nALTER TABLE app.records ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY records_read ON app.records FOR SELECT TO authenticated USING (auth.uid() = id);\n",
                encoding="utf-8",
            )
            (migrations / "002_remove_policy.sql").write_text(
                "DROP POLICY records_read ON app.records;\n",
                encoding="utf-8",
            )
            result = run_scan(repo)
            rules = {finding.rule for finding in result.findings}
            self.assertIn("database:rls-enabled-without-policy", rules)
            self.assertNotIn("database:rls-policy-missing-condition", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_dropped_table_is_not_reported_for_missing_rls(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-drop-table-"))
        try:
            migrations = repo / "migrations"
            migrations.mkdir()
            (migrations / "001_create.sql").write_text(
                "CREATE TABLE app.retired (id integer);\n",
                encoding="utf-8",
            )
            (migrations / "002_drop.sql").write_text(
                "DROP TABLE app.retired;\n",
                encoding="utf-8",
            )
            result = run_scan(repo)
            self.assertNotIn("database:table-without-rls", {finding.rule for finding in result.findings})
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_overly_permissive_policy(self):
        """Test detection of overly permissive policies (USING true)."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-permissive-"))
        try:
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001_permissive.sql").write_text("""
CREATE TABLE users (id uuid primary key, email text);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY bad_policy ON users FOR ALL USING (true);
""")
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertIn("database:rls-policy-overly-permissive", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_missing_role_restriction(self):
        """Test detection of policies without role restrictions."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-role-"))
        try:
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001_no_role.sql").write_text("""
CREATE TABLE users (id uuid primary key, email text);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY no_role ON users FOR ALL USING (auth.uid() = id);
""")
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertIn("database:rls-policy-missing-role-restriction", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_rls_policy_with_role_restriction_ok(self):
        """Test that policies with role restrictions don't trigger false positives."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-role-ok-"))
        try:
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001_with_role.sql").write_text("""
CREATE TABLE users (id uuid primary key, email text);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY with_role ON users FOR ALL TO authenticated USING (auth.uid() = id);
""")
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertNotIn("database:rls-policy-missing-role-restriction", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class FixSafetyTests(TestCase):
    def test_fix_engine_rejects_path_traversal(self):
        repo = Path(tempfile.mkdtemp())
        try:
            (repo / "safe.txt").write_text("keep\n")
            engine = FixEngine(repo, dry_run=False)
            bad = Finding(
                rule="quality:console-log-in-production",
                module="quality",
                severity=Severity.LOW,
                file=Path("../../../etc/passwd"),
                line=1,
                fixable=True,
            )
            engine.apply([bad])
            self.assertEqual(len(engine.applied), 0)
            self.assertTrue(any("escapes" in s["reason"] for s in engine.skipped))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_fix_engine_creates_backup_and_rollback(self):
        repo = Path(tempfile.mkdtemp())
        try:
            target = repo / "app.js"
            target.write_text("console.log('debug');\n", encoding="utf-8")
            engine = FixEngine(repo, dry_run=False)
            finding = Finding(
                rule="quality:console-log-in-production",
                module="quality",
                severity=Severity.LOW,
                file=Path("app.js"),
                line=1,
                fixable=True,
            )
            engine.apply([finding])
            self.assertEqual(len(engine.applied), 1)
            self.assertEqual(target.read_text(encoding="utf-8").strip(), "")
            self.assertEqual(len(engine.backups), 1)
            engine.rollback()
            self.assertEqual(target.read_text(encoding="utf-8"), "console.log('debug');\n")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class TestRunnerTests(TestCase):
    def test_run_tests_refuses_destructive_command(self):
        repo = Path(tempfile.mkdtemp())
        try:
            result = run_tests(repo, command="rm -rf /", explicit_permission=True)
            self.assertEqual(result["status"], "skip")
            self.assertIn("destructive", result["summary"].lower())
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_no_execution_mode(self):
        repo = Path(tempfile.mkdtemp())
        try:
            result = run_tests(repo, no_execution=True)
            self.assertEqual(result["status"], "skip")
            self.assertIn("disabled", result["summary"].lower())
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_detects_missing_runner(self):
        repo = Path(tempfile.mkdtemp())
        try:
            result = run_tests(repo, explicit_permission=True)
            self.assertEqual(result["status"], "skip")
            self.assertIn("No test runner", result["summary"])
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_detects_and_runs_stdlib_unittest(self):
        repo = Path(tempfile.mkdtemp())
        try:
            tests_dir = repo / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_basic.py").write_text(
                "import unittest\n\nclass BasicTests(unittest.TestCase):\n    def test_success(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="OK")) as sandbox_run:
                result = run_tests(repo, explicit_permission=True)
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["execution_mode"], "docker_isolated")
            self.assertIn("unittest", result["command"])
            run_command = sandbox_run.call_args.args[0]
            self.assertIn("none", run_command)
            self.assertIn("--memory", run_command)
            self.assertIn("--pids-limit", run_command)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_skips_when_docker_daemon_is_unavailable(self):
        repo = Path(tempfile.mkdtemp())
        try:
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run",
                return_value=subprocess.CompletedProcess(["docker", "info"], 1, "", "daemon unavailable"),
            ):
                result = run_tests(repo, command='python -c "pass"', explicit_permission=True)
            self.assertEqual(result["status"], "skip")
            self.assertEqual(result["execution_mode"], "sandbox_unavailable")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_uses_secret_filtered_snapshot_and_redacts_output(self):
        repo = Path(tempfile.mkdtemp())
        captured = {}
        try:
            (repo / ".env").write_text("TOKEN=developer-secret\n", encoding="utf-8")
            (repo / "source.py").write_text('password = "embedded-secret-password"\n', encoding="utf-8")
            (repo / "app.py").write_text("print('test')\n", encoding="utf-8")

            def capture(command, **kwargs):
                captured["command"] = command
                snapshot = kwargs["cwd"]
                captured["files"] = [path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()]
                captured["source"] = (snapshot / "source.py").read_text(encoding="utf-8")
                captured["environment"] = kwargs["env"]
                return subprocess.CompletedProcess(command, 0, 'password="embedded-secret-password"\n', ""), False, False

            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=capture), patch.dict(
                os.environ, {"VCQA_TEST_SECRET": "host-secret-value"}
            ):
                result = run_tests(repo, command="python app.py", explicit_permission=True)

            self.assertNotIn(".env", captured["files"])
            self.assertNotIn("embedded-secret-password", captured["source"])
            self.assertNotIn("VCQA_TEST_SECRET", captured["environment"])
            self.assertNotIn("host-secret-value", str(captured["environment"]))
            self.assertNotIn("embedded-secret-password", result["stdout"])
            self.assertIn("[REDACTED]", result["stdout"])
            self.assertIn("--network", captured["command"])
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_uses_allowlisted_environment_and_reports_limits(self):
        repo = Path(tempfile.mkdtemp())
        try:
            probe = repo / "env_probe.py"
            probe.write_text("import json, os\\nprint(json.dumps({'leaked': 'VCQA_TEST_SECRET' in os.environ, 'path': bool(os.environ.get('PATH'))}))\\n", encoding="utf-8")
            with patch.dict(os.environ, {"VCQA_TEST_SECRET": "must-not-leak", "DATABASE_URL": "postgres://private"}), patch(
                "vibe_coding_qa.engine.shutil.which", return_value="docker"
            ), patch("vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()), patch(
                "vibe_coding_qa.engine._run_bounded_process",
                side_effect=fake_sandbox_run(run_stdout='{"leaked": false, "path": false}'),
            ):
                result = run_tests(repo, command="python env_probe.py", explicit_permission=True)
            self.assertEqual(result["status"], "pass")
            self.assertNotIn("VCQA_TEST_SECRET", result["stdout"])
            self.assertTrue(result["resource_limits"]["enforced"])
            self.assertEqual(result["resource_limits"]["isolation"], "docker-network-disabled-read-only-rootfs")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_bounded_runner_enforces_wall_clock_timeout(self):
        repo = Path(tempfile.mkdtemp())
        try:
            result, timed_out, output_exceeded = _run_bounded_process(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=repo,
                env={"PATH": os.environ.get("PATH", "")},
                timeout=0.1,
            )
            self.assertTrue(timed_out)
            self.assertFalse(output_exceeded)
            self.assertNotEqual(result.returncode, 0)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_bounded_runner_terminates_and_caps_excessive_output(self):
        repo = Path(tempfile.mkdtemp())
        try:
            result, timed_out, output_exceeded = _run_bounded_process(
                [sys.executable, "-c", "print('x' * 5000000)"],
                cwd=repo,
                env={"PATH": os.environ.get("PATH", "")},
                timeout=5,
                max_output_bytes=1024,
            )
            self.assertFalse(timed_out)
            self.assertTrue(output_exceeded)
            self.assertLessEqual(len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")), 1024)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_blocked_without_permission(self):
        """Test that tests are blocked without explicit permission."""
        repo = Path(tempfile.mkdtemp())
        try:
            result = run_tests(repo, command="python -c \"print(1)\"")
            self.assertEqual(result["status"], "skip")
            self.assertIn("explicit permission", result["summary"].lower())
            self.assertEqual(result["execution_mode"], "blocked_no_permission")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_run_tests_with_permission_passes(self):
        """Test that tests run when explicit permission is given."""
        repo = Path(tempfile.mkdtemp())
        try:
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="1")):
                result = run_tests(repo, command="python -c \"print(1)\"", explicit_permission=True)
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["execution_mode"], "docker_isolated")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class ModuleEntryPointTests(TestCase):
    def test_not_verified_release_gate_has_nonzero_module_exit_code(self):
        root = Path(__file__).resolve().parent.parent
        temp = Path(tempfile.mkdtemp(prefix="vcqa-module-entrypoint-"))
        try:
            repo = temp / "repo"
            repo.mkdir()
            (repo / ".gitignore").write_text(".env\\n", encoding="utf-8")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_basic.py").write_text("def test_ok():\\n    assert True\\n", encoding="utf-8")
            output = temp / "reports"
            completed = subprocess.run(
                [
                    sys.executable, "-m", "vibe_coding_qa", "gate", "--repo", str(repo),
                    "--no-execution", "--output", str(output),
                ],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 3, completed.stdout + completed.stderr)
            self.assertIn("NOT VERIFIED", completed.stdout)
            report = (output / "vcqa-report.json").read_text(encoding="utf-8")
            self.assertIn('"gate": "not_verified"', report)
        finally:
            shutil.rmtree(temp, ignore_errors=True)


class ReportTests(TestCase):
    def test_report_normalizes_skipped_test_status(self):
        result = ScanResult(
            repo=Path("fixture"),
            modules=[ModuleResult(module="quality", status=Status.PASS, score=100.0)],
            tests={"status": Status.SKIP, "execution_mode": "disabled"},
        )
        assess(result)
        self.assertIn("Status: `skip`", markdown_report(result))
        self.assertIn("Status: skip", html_report(result))

    def test_html_report_escapes_untrusted_content(self):
        module = ModuleResult(
            module="security",
            status=Status.PASS,
            score=100.0,
            findings=[
                Finding(
                    rule="xss:test",
                    module="security",
                    severity=Severity.HIGH,
                    file=Path("app.js"),
                    line=1,
                    message="<script>alert(1)</script>",
                    suggestion="Use safe DOM methods.",
                )
            ],
        )
        result = ScanResult(repo=Path("/tmp/test"), modules=[module], tests={})
        html = html_report(result)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)


class AIProviderTests(TestCase):
    def test_ai_request_payload_redacts_complete_pem_and_finding_fields(self):
        provider = OpenRouterAIProvider(api_key="fake", base_url="https://example.invalid")
        finding = Finding(
            rule="security:generic-api-key",
            module="security",
            severity=Severity.HIGH,
            file=Path("source.ts"),
            line=1,
            message='Found password="payload-password-123"',
            suggestion="Remove token ghp_12345678901234567890123456789012345678",
        )
        pem_block = "-----BEGIN RSA PRIVATE KEY-----\nPRIVATEKEYMATERIAL123\n-----END RSA PRIVATE KEY-----"
        response = io.BytesIO(b'{"choices":[{"message":{"content":"review"}}]}')
        with patch("vibe_coding_qa.ai_review.urllib.request.urlopen", return_value=response) as urlopen:
            provider.review(finding, [pem_block, 'const token = "sk-123456789012345678901234";'])
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        content = payload["messages"][0]["content"]
        for secret in ("PRIVATEKEYMATERIAL123", "payload-password-123", "ghp_12345678901234567890123456789012345678", "sk-123456789012345678901234"):
            self.assertNotIn(secret, content)
        self.assertGreaterEqual(content.count("[REDACTED]"), 4)

    def test_core_works_without_ai_credentials(self):
        provider = get_ai_provider()
        review = provider.review(Finding(rule="test", module="security", severity=Severity.HIGH, file=Path("x"), line=1))
        self.assertFalse(review["enabled"])

    def test_openrouter_provider_reports_sanitized_http_errors(self):
        provider = OpenRouterAIProvider(api_key="fake", base_url="https://example.invalid", timeout=2)
        finding = Finding(rule="test", module="security", severity=Severity.HIGH, file=Path("x"), line=1)
        http_error = urllib.error.HTTPError("https://example.invalid", 500, "password=secret-from-provider", {}, None)
        with patch("vibe_coding_qa.ai_review.urllib.request.urlopen", side_effect=http_error):
            http_review = provider.review(finding)
        self.assertTrue(http_review["enabled"])
        self.assertEqual(http_review["error"], "HTTP 500")
        self.assertNotIn("secret-from-provider", str(http_review))
        with patch(
            "vibe_coding_qa.ai_review.urllib.request.urlopen",
            side_effect=OSError("Authorization: Bearer leak-this-error"),
        ):
            request_review = provider.review(finding)
        self.assertEqual(request_review["error"], "AI review request failed: OSError")
        self.assertNotIn("leak-this-error", str(request_review))

    def test_ai_redacts_secrets_in_payload(self):
        """Test that AI provider redacts secrets from all payload fields."""
        provider = OpenRouterAIProvider(api_key="fake", base_url="https://invalid.invalid", timeout=2)
        # Create a finding with context containing various secret types
        finding = Finding(
            rule="security:test",
            module="security",
            severity=Severity.HIGH,
            file=Path("test.ts"),
            line=1,
            message="Test finding",
            suggestion="Fix it"
        )
        context_lines = [
            'const API_KEY = "sk-123456789012345678901234";',
            'const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";',
            'const DB_URL = "postgres://user:pass@localhost:5432/db";',
            'const BEARER = "Bearer abcdefghijklmnopqrstuvwxyz123456";',
            'const GH_TOKEN = "ghp_12345678901234567890123456789012345678";',
        ]
        response = io.BytesIO(b'{"choices":[{"message":{"content":"review"}}]}')
        with patch("vibe_coding_qa.ai_review.urllib.request.urlopen", return_value=response) as urlopen:
            review = provider.review(finding, context_lines)
        self.assertTrue(review["enabled"])
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        transmitted = payload["messages"][0]["content"]
        for secret in (
            "sk-123456789012345678901234",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "postgres://user:pass@localhost:5432/db",
            "Bearer abcdefghijklmnopqrstuvwxyz123456",
            "ghp_12345678901234567890123456789012345678",
        ):
            self.assertNotIn(secret, transmitted)
        self.assertIn("[REDACTED]", transmitted)


class GitCredentialTests(TestCase):
    def test_clone_never_passes_token_in_args_or_environment_and_cleans_files(self):
        token = "ghp_super-secret-token-value"
        captured = {}

        def fake_git(command, **kwargs):
            captured["command"] = command
            captured["env"] = kwargs["env"]
            config_path = Path(kwargs["env"]["GIT_CONFIG_GLOBAL"])
            captured["config"] = config_path.read_text(encoding="utf-8")
            helper_path = captured["config"].split("--file=", 1)[1].strip().strip("'\"")
            captured["credential_path"] = Path(helper_path)
            captured["credential"] = captured["credential_path"].read_text(encoding="utf-8")
            return subprocess.CompletedProcess(command, 1, "", f"fatal: authentication failed: {token}")

        with patch.dict(os.environ, {
            "VCQA_GITHUB_TOKEN": token,
            "GITHUB_TOKEN": token,
            "VCQA_AI_API_KEY": "ai-secret-value",
            "DATABASE_URL": "postgres://db-secret@host/app",
        }), patch("vibe_coding_qa.repo.subprocess.run", side_effect=fake_git):
            with self.assertRaises(RuntimeError) as error:
                clone_repo("example/private-repo", token=token)
        self.assertNotIn(token, " ".join(captured["command"]))
        self.assertNotIn(token, str(captured["env"]))
        self.assertNotIn("VCQA_AI_API_KEY", captured["env"])
        self.assertNotIn("DATABASE_URL", captured["env"])
        self.assertEqual(captured["env"]["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertNotIn(token, captured["config"])
        self.assertIn(token, captured["credential"])
        self.assertNotIn(token, str(error.exception))
        self.assertFalse(Path(captured["env"]["GIT_CONFIG_GLOBAL"]).exists())
        self.assertFalse(captured["credential_path"].exists())

    def test_cli_reads_private_repo_token_from_environment(self):
        token = "ghp_cli-auth-token-value"
        result = ScanResult(
            repo=Path("fixture"),
            modules=[ModuleResult(module="quality", status=Status.PASS, score=100.0)],
            tests={"status": Status.SKIP, "execution_mode": "disabled"},
        )
        assess(result)
        with patch.dict(os.environ, {"VCQA_GITHUB_TOKEN": token}, clear=False), patch(
            "vibe_coding_qa.cli.run_pipeline", return_value=result
        ) as pipeline:
            cli_main(["gate", "--repo", "owner/private-repo", "--no-execution"])
        self.assertEqual(pipeline.call_args.kwargs["github_token"], token)


class DependencyOSVTests(TestCase):
    def test_osv_checks_resolved_transitive_lockfile_dependencies(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-osv-"))
        try:
            lockfile = repo / "package-lock.json"
            lockfile.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/parent/node_modules/transitive": {"version": "2.0.0"},
                },
            }), encoding="utf-8")
            response = io.BytesIO(b'{"vulns":[{"id":"GHSA-test","aliases":["CVE-2026-0001"]}]}')
            with patch.dict(os.environ, {"VCQA_OSV_ENABLED": "1"}), patch(
                "vibe_coding_qa.scanners.dependencies.urllib.request.urlopen",
                return_value=response,
            ) as urlopen:
                scanner = DependencyScanner(repo)
                findings = scanner.scan()
            self.assertEqual(urlopen.call_count, 1)
            package = json.loads(urlopen.call_args.args[0].data)
            self.assertEqual(package["package"], {"name": "transitive", "ecosystem": "npm"})
            self.assertEqual(package["version"], "2.0.0")
            self.assertEqual(sum(f.rule == "dependencies:osv-verified-vulnerability" for f in findings), 1)
            self.assertTrue(all(f.confidence == "high" for f in findings if f.rule.endswith("osv-verified-vulnerability")))
            self.assertTrue(any("OSV checked 1" in note for note in scanner.notes))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_osv_parses_major_npm_and_python_lockfile_formats(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-lockfiles-"))
        try:
            (repo / "yarn.lock").write_text(
                '"@scope/yarn-pkg@^4.0.0":\n  version "4.5.6"\n',
                encoding="utf-8",
            )
            (repo / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '9.0'\npackages:\n  /@scope/pnpm-pkg@5.6.7:\n    resolution: {}\n",
                encoding="utf-8",
            )
            (repo / "poetry.lock").write_text(
                '[[package]]\nname = "poetry-pkg"\nversion = "1.2.3"\n',
                encoding="utf-8",
            )
            (repo / "uv.lock").write_text(
                '[[package]]\nname = "uv-pkg"\nversion = "2.3.4"\n',
                encoding="utf-8",
            )
            (repo / "Pipfile.lock").write_text(json.dumps({"default": {"pipfile-pkg": {"version": "==3.4.5"}}, "develop": {}}), encoding="utf-8")
            (repo / "requirements.txt").write_text("req-pkg==6.7.8\n", encoding="utf-8")
            resolved = set(DependencyScanner(repo)._resolved_dependencies())
            found = {(ecosystem, name, version) for ecosystem, name, version, _ in resolved}
            self.assertEqual(found, {
                ("npm", "@scope/yarn-pkg", "4.5.6"),
                ("npm", "@scope/pnpm-pkg", "5.6.7"),
                ("PyPI", "poetry-pkg", "1.2.3"),
                ("PyPI", "uv-pkg", "2.3.4"),
                ("PyPI", "pipfile-pkg", "3.4.5"),
                ("PyPI", "req-pkg", "6.7.8"),
            })
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_osv_is_offline_by_default(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-osv-offline-"))
        try:
            with patch.dict(os.environ, {}, clear=True), patch(
                "vibe_coding_qa.scanners.dependencies.urllib.request.urlopen"
            ) as urlopen:
                scanner = DependencyScanner(repo)
                scanner.scan()
            urlopen.assert_not_called()
            self.assertTrue(any("disabled" in note for note in scanner.notes))
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class GateDecisionTests(TestCase):
    def test_gate_not_verified_when_tests_skipped(self):
        """Test that gate returns 'not_verified' when tests are skipped due to no permission."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-"))
        try:
            (repo / "README.md").write_text(
                "# clean\n\nData Protection Officer: privacy@example.com\n"
                "Registered with the Personal Data Protection Commission.\n"
                "Unsubscribe: POST /unsubscribe returns 200 immediately.\n"
            )
            result = run_scan(repo)
            # Don't run tests - they'll be skipped
            from vibe_coding_qa.gates import assess
            assess(result)
            self.assertEqual(result.gate, "not_verified")
            self.assertIn("NOT VERIFIED", release_decision(result))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_gate_not_verified_when_execution_is_refused(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-refused-"))
        try:
            result = run_scan(repo)
            result.tests.update(run_tests(repo, command="rm -rf /", explicit_permission=True))
            assess(result)
            self.assertEqual(result.tests["status"], "skip")
            self.assertEqual(result.gate, "not_verified")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_gate_pass_when_tests_pass(self):
        """Test that gate returns 'pass' when tests pass."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-pass-"))
        try:
            (repo / "README.md").write_text(
                "# clean\n\nData Protection Officer: privacy@example.com\n"
                "Registered with the Personal Data Protection Commission.\n"
                "Unsubscribe: POST /unsubscribe returns 200 immediately.\n"
            )
            result = run_scan(repo)
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run()):
                result.tests.update(run_tests(repo, command='python -c "pass"', explicit_permission=True))
            from vibe_coding_qa.gates import assess
            assess(result)
            self.assertEqual(result.gate, "pass")
            self.assertIn("PASS", release_decision(result))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_gate_fail_when_tests_fail(self):
        """Test that gate returns 'fail' when tests fail."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-fail-"))
        try:
            (repo / "README.md").write_text(
                "# clean\n\nData Protection Officer: privacy@example.com\n"
                "Registered with the Personal Data Protection Commission.\n"
                "Unsubscribe: POST /unsubscribe returns 200 immediately.\n"
            )
            # No package.json with test script - use explicit command
            result = run_scan(repo)
            # Run tests with explicit permission using a command that will fail
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_returncode=1)):
                result.tests.update(run_tests(repo, command="python -c \"import sys; sys.exit(1)\"", explicit_permission=True))
            from vibe_coding_qa.gates import assess
            assess(result)
            self.assertEqual(result.gate, "fail")
            self.assertIn("FAIL", release_decision(result))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_gate_blocked_on_critical(self):
        """Test that gate returns 'block' on critical findings."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-block-"))
        try:
            (repo / "src").mkdir()
            (repo / "src" / "secret.ts").write_text('const API_KEY = "sk-123456789012345678901234";\n')
            result = run_scan(repo)
            from vibe_coding_qa.gates import assess
            assess(result)
            self.assertEqual(result.gate, "block")
            self.assertIn("BLOCKED", release_decision(result))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_reports_share_authoritative_release_decision(self):
        result = ScanResult(
            repo=Path("fixture"),
            modules=[ModuleResult(module="quality", status=Status.PASS, score=100.0)],
            tests={"status": Status.PASS, "execution_mode": "executed"},
        )
        assess(result, minimum_score=101)
        markdown = markdown_report(result)
        structured = json_report(result)
        html = html_report(result)
        self.assertEqual(result.gate, "fail")
        self.assertIn("Release Gate:** FAIL", markdown)
        self.assertIn("FAIL", markdown)
        self.assertEqual(json.loads(structured)["assessment"]["gate"], "fail")
        self.assertEqual(json.loads(structured)["release_gate"], "FAIL")
        self.assertIn("Release Gate:</strong> FAIL", html)

    def test_gate_cli_allows_test_execution_only_through_pipeline_permission(self):
        result = ScanResult(
            repo=Path("fixture"),
            modules=[ModuleResult(module="quality", status=Status.PASS, score=100.0)],
            tests={"status": Status.PASS, "execution_mode": "executed"},
        )
        assess(result)
        with patch("vibe_coding_qa.cli.run_pipeline", return_value=result) as pipeline:
            self.assertEqual(cli_main(["gate", "--repo", "fixture", "--explicit-permission", "--test-command", "python -c pass", "--test-image", "python:3.12-slim"]), 0)
        self.assertTrue(pipeline.call_args.kwargs["run_tests_flag"])
        self.assertTrue(pipeline.call_args.kwargs["explicit_permission"])
        self.assertEqual(pipeline.call_args.kwargs["test_command"], "python -c pass")
        self.assertEqual(pipeline.call_args.kwargs["test_image"], "python:3.12-slim")

    def test_minimum_score_threshold(self):
        """Test that minimum score threshold affects gate decision."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-gate-score-"))
        try:
            (repo / "README.md").write_text(
                "# clean\n\nData Protection Officer: privacy@example.com\n"
                "Registered with the Personal Data Protection Commission.\n"
                "Unsubscribe: POST /unsubscribe returns 200 immediately.\n"
            )
            (repo / "src").mkdir()
            # Add some medium findings to lower score but not block
            (repo / "src" / "code.ts").write_text("console.log('debug');\n" * 20)
            result = run_scan(repo)
            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run()):
                result.tests.update(run_tests(repo, command='python -c "pass"', explicit_permission=True))
            from vibe_coding_qa.gates import assess
            # Default minimum score is 60
            assess(result)
            # With many console.log findings, score might be below 60
            if result.overall_score < 60:
                self.assertEqual(result.gate, "fail")
            else:
                self.assertEqual(result.gate, "pass")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    import unittest
    unittest.main()
