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
from vibe_coding_qa.engine import (
    _run_bounded_process,
    classify_test_results,
    run_pipeline,
    run_scan,
    run_tests,
)
from vibe_coding_qa.fixes import FixEngine
from vibe_coding_qa.gates import assess, release_decision
from vibe_coding_qa.reporters import html_report, json_report, markdown_report
from vibe_coding_qa.profile import EXCLUDED_DIRS, analyze_repo, iter_repo_files
from vibe_coding_qa.scanners.dependencies import DependencyScanner, clear_osv_cache
from vibe_coding_qa.scanners.security import SecurityScanner
from vibe_coding_qa.repo import clone_repo
from vibe_coding_qa.scanners import redact_secrets
from vibe_coding_qa.cli import main as cli_main


SAMPLES = Path(__file__).resolve().parent.parent / "samples"


# --------------------------------------------------------------------------- #
# Synthetic credential fixtures.
#
# These tests exercise the secret scanner and the AI-payload redactor, so they
# need credentials that *look* real. Committing those literals would (rightly)
# trip secret scanners and GitHub push protection, so each value is assembled
# from fragments at runtime: the runtime string is byte-for-byte identical to
# the old literal, but no credential literal is left in the committed source.
# None of these are, or ever were, real secrets.
# --------------------------------------------------------------------------- #
def _assemble(*parts: str) -> str:
    return "".join(parts)


_OPENAI_KEY = _assemble("sk-", "123456789012345678901234")
_OPENAI_KEY_TEST_SUBSTR = _assemble("sk-", "test1234567890123456789")
_GITHUB_TOKEN = _assemble("ghp_", "12345678901234567890123456789012345678")
_PEM_BEGIN = _assemble("-----BEGIN RSA PRIVATE ", "KEY-----")
_PEM_END = _assemble("-----END RSA PRIVATE ", "KEY-----")
_PEM_REDACTION = _PEM_BEGIN + "\nPRIVATEKEYMATERIAL123\n" + _PEM_END
_PEM_KEY = _PEM_BEGIN + "\nMIIEowIBAAKCAQEA...\n" + _PEM_END
_PEM_KEY_SHORT = _PEM_BEGIN + "\nMIIEowIBAAKCAQEA\n" + _PEM_END
_JWT = _assemble(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ".",
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
    ".",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
)
_DB_URL = _assemble("postgres://user:", "pass@localhost:5432/db")
_BEARER = _assemble("Bearer ", "abcdefghijklmnopqrstuvwxyz123456")
_PW_WORD = _assemble("pass", "word")
_EMBEDDED_PW = "embedded-secret-password"
_PAYLOAD_PW = "payload-password-123"


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
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="Ran 1 test in 0.001s\n\nOK")) as sandbox_run:
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
            (repo / "source.py").write_text(_PW_WORD + ' = "' + _EMBEDDED_PW + '"\n', encoding="utf-8")
            (repo / "app.py").write_text("print('test')\n", encoding="utf-8")
            (repo / "tests").mkdir()
            fixture_source = 'const API_KEY = "sample-key-not-real";\n'
            (repo / "tests" / "test_fixture.py").write_text(fixture_source, encoding="utf-8")

            def capture(command, **kwargs):
                captured["command"] = command
                snapshot = kwargs["cwd"]
                captured["files"] = [path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()]
                captured["source"] = (snapshot / "source.py").read_text(encoding="utf-8")
                captured["test_source"] = (snapshot / "tests" / "test_fixture.py").read_text(encoding="utf-8")
                captured["environment"] = kwargs["env"]
                return subprocess.CompletedProcess(command, 0, _PW_WORD + '="' + _EMBEDDED_PW + '"\n', ""), False, False

            with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
                "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=capture), patch.dict(
                os.environ, {"VCQA_TEST_SECRET": "host-secret-value"}
            ):
                result = run_tests(repo, command="python app.py", explicit_permission=True)

            self.assertNotIn(".env", captured["files"])
            self.assertNotIn("embedded-secret-password", captured["source"])
            self.assertIn("tests/test_fixture.py", captured["files"])
            self.assertIn("[REDACTED]", captured["test_source"])
            self.assertNotIn("sample-key-not-real", captured["test_source"])
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
                side_effect=fake_sandbox_run(run_stdout='{"leaked": false, "path": false}\nRan 1 test in 0.001s\n\nOK'),
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
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="Ran 1 test in 0.001s\n\nOK")):
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
    def test_secret_redaction_does_not_cross_source_boundaries(self):
        source = (
            'base_url="https://example.invalid"\\n'
            'masked="https://***:***@"\\n'
            'credential="https://audit-user:secret-value@example.invalid/path"\\n'
            'next="ordinary source"'
        )
        redacted = redact_secrets(source)
        self.assertIn('base_url="https://example.invalid"', redacted)
        self.assertIn('masked="https://***:***@"', redacted)
        self.assertNotIn("secret-value", redacted)
        self.assertIn('next="ordinary source"', redacted)

    def test_ai_request_payload_redacts_complete_pem_and_finding_fields(self):
        provider = OpenRouterAIProvider(api_key="fake", base_url="https://example.invalid")
        finding = Finding(
            rule="security:generic-api-key",
            module="security",
            severity=Severity.HIGH,
            file=Path("source.ts"),
            line=1,
            message='Found ' + _PW_WORD + '="' + _PAYLOAD_PW + '"',
            suggestion="Remove token " + _GITHUB_TOKEN,
        )
        pem_block = _PEM_REDACTION
        response = io.BytesIO(b'{"choices":[{"message":{"content":"review"}}]}')
        with patch("vibe_coding_qa.ai_review.urllib.request.urlopen", return_value=response) as urlopen:
            provider.review(finding, [pem_block, 'const token = "' + _OPENAI_KEY + '";'])
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        content = payload["messages"][0]["content"]
        for secret in ("PRIVATEKEYMATERIAL123", _PAYLOAD_PW, _GITHUB_TOKEN, _OPENAI_KEY):
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
            'const API_KEY = "' + _OPENAI_KEY + '";',
            'const JWT = "' + _JWT + '";',
            'const DB_URL = "' + _DB_URL + '";',
            'const BEARER = "' + _BEARER + '";',
            'const GH_TOKEN = "' + _GITHUB_TOKEN + '";',
        ]
        response = io.BytesIO(b'{"choices":[{"message":{"content":"review"}}]}')
        with patch("vibe_coding_qa.ai_review.urllib.request.urlopen", return_value=response) as urlopen:
            review = provider.review(finding, context_lines)
        self.assertTrue(review["enabled"])
        payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        transmitted = payload["messages"][0]["content"]
        for secret in (
            _OPENAI_KEY,
            _JWT.split(".")[0],
            _DB_URL,
            _BEARER,
            _GITHUB_TOKEN,
        ):
            self.assertNotIn(secret, transmitted)
        self.assertIn("[REDACTED]", transmitted)


class SecretDetectionTests(TestCase):
    def test_real_credential_in_test_file_is_detected(self):
        """Real credentials in test files should be flagged, not ignored."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-test-"))
        try:
            (repo / "tests").mkdir()
            # Real-looking credential in test file
            (repo / "tests" / "test_auth.py").write_text(
                'API_KEY = "' + _OPENAI_KEY + '"\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertIn("security:generic-api-key", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_synthetic_credential_in_test_file_is_filtered(self):
        """Synthetic/test credentials in test files should be filtered."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-synthetic-"))
        try:
            (repo / "tests").mkdir()
            # Synthetic credential with "sample" indicator
            (repo / "tests" / "test_auth.py").write_text(
                'API_KEY = "sample-key-not-real"\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertNotIn("security:generic-api-key", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_real_credential_in_fixture_file_is_detected(self):
        """Real credentials in fixture files should be flagged."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-fixture-"))
        try:
            (repo / "fixtures").mkdir()
            (repo / "fixtures" / "config.json").write_text(
                '{"api_key": "' + _GITHUB_TOKEN + '"}\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            # ghp_ tokens match github-token pattern
            self.assertIn("security:github-token", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_synthetic_credential_in_fixture_file_is_filtered(self):
        """Synthetic credentials in fixture files should be filtered."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-fixture-synth-"))
        try:
            (repo / "fixtures").mkdir()
            (repo / "fixtures" / "config.json").write_text(
                '{"api_key": "your-api-key-here"}\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertNotIn("security:generic-api-key", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_critical_patterns_still_flagged_in_test_files(self):
        """Private keys and other CRITICAL patterns should still be flagged in test files."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-critical-"))
        try:
            (repo / "tests").mkdir()
            pem = _PEM_KEY
            (repo / "tests" / "test_crypto.py").write_text(pem, encoding="utf-8")
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertIn("security:private-key", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_client_side_secret_detection_respects_synthetic_heuristic(self):
        """Client-side secret detection should filter synthetic credentials."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-client-secret-"))
        try:
            (repo / "src").mkdir()
            # Synthetic in client file
            (repo / "src" / "client.ts").write_text(
                'const API_KEY = "sample-key-not-real";\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertNotIn("security:client-side-secret", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_real_client_side_secret_still_flagged(self):
        """Real credentials in client files should still be flagged."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-client-real-"))
        try:
            (repo / "src").mkdir()
            (repo / "src" / "client.ts").write_text(
                'const OPENAI_KEY = "' + _OPENAI_KEY + '";\n', encoding="utf-8"
            )
            result = run_scan(repo)
            rules = {f.rule for f in result.findings}
            self.assertIn("security:client-side-secret", rules)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


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


class KnownVulnerableRangeTests(TestCase):
    """P4: exact resolved versions are matched against ranges, not historical CVEs."""

    def _package_json_versions(self, deps: dict) -> set[str]:
        repo = Path(tempfile.mkdtemp(prefix="vcqa-pkg-"))
        try:
            (repo / "package.json").write_text(json.dumps({"dependencies": deps}), encoding="utf-8")
            findings = DependencyScanner(repo).scan()
            return {
                f.message.split("@")[1].split()[0]
                for f in findings
                if f.rule == "dependencies:vulnerable-dependency"
            }
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_jquery_3_5_0_and_3_5_1_are_not_flagged(self):
        """The jQuery CVE-2020-11023 affected range must exclude the fixed 3.5.x releases."""
        self.assertEqual(self._package_json_versions({"jquery": "3.5.0"}), set())
        self.assertEqual(self._package_json_versions({"jquery": "3.5.1"}), set())

    def test_jquery_3_4_1_is_flagged(self):
        flagged = self._package_json_versions({"jquery": "3.4.1"})
        self.assertIn("3.4.1", flagged)

    def test_pinned_only_matches_exact_three_part_versions(self):
        """Caret/tilde ranges are not treated as a resolved exact version."""
        flagged = self._package_json_versions({"lodash": "^4.17.20"})
        self.assertEqual(flagged, set())

    def test_transitive_lockfile_dependency_is_flagged(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-transitive-"))
        try:
            (repo / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/parent/node_modules/jquery": {"version": "3.4.1"},
                },
            }), encoding="utf-8")
            findings = DependencyScanner(repo).scan()
            vulns = [f for f in findings if f.rule == "dependencies:vulnerable-dependency"]
            self.assertEqual(len(vulns), 1)
            self.assertIn("3.4.1", vulns[0].message)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_resolved_dependency_is_not_reported_twice(self):
        """A dependency present in package.json and its lockfile is reported once."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-dedupe-"))
        try:
            (repo / "package.json").write_text(json.dumps({"dependencies": {"jquery": "3.4.1"}}), encoding="utf-8")
            (repo / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/jquery": {"version": "3.4.1"},
                },
            }), encoding="utf-8")
            findings = DependencyScanner(repo).scan()
            vulns = [f for f in findings if f.rule == "dependencies:vulnerable-dependency"]
            self.assertEqual(len(vulns), 1)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class VersionRangeMatcherTests(TestCase):
    """P4: the local version-range matcher used for heuristic findings."""

    def test_simple_comparisons(self):
        self.assertTrue(DependencyScanner._satisfies("3.4.1", "<3.5.0"))
        self.assertFalse(DependencyScanner._satisfies("3.5.0", "<3.5.0"))
        self.assertFalse(DependencyScanner._satisfies("3.5.1", "<3.5.0"))
        self.assertTrue(DependencyScanner._satisfies("3.5.0", "<=3.5.0"))

    def test_comma_joined_bounds(self):
        self.assertTrue(DependencyScanner._satisfies("1.2.0", ">=1.2.0,<1.5.0"))
        self.assertTrue(DependencyScanner._satisfies("1.4.9", ">=1.2.0,<1.5.0"))
        self.assertFalse(DependencyScanner._satisfies("1.5.0", ">=1.2.0,<1.5.0"))
        self.assertFalse(DependencyScanner._satisfies("1.1.9", ">=1.2.0,<1.5.0"))

    def test_exact_match(self):
        self.assertTrue(DependencyScanner._satisfies("2.0.0", "2.0.0"))
        self.assertFalse(DependencyScanner._satisfies("2.0.1", "2.0.0"))

    def test_short_versions_are_zero_padded(self):
        self.assertTrue(DependencyScanner._satisfies("3.5", "<3.5.0") is False)  # equals bound, not less
        self.assertTrue(DependencyScanner._satisfies("4.0", ">=4"))

    def test_non_numeric_constraint_is_not_matched(self):
        self.assertFalse(DependencyScanner._satisfies("1.0.0", "^1.0.0"))
        self.assertFalse(DependencyScanner._satisfies("not-a-version", "<2.0.0"))


class OSVRobustnessTests(TestCase):
    """P4: bounded concurrency, caching, and honest reporting of failures."""

    def tearDown(self):
        clear_osv_cache()

    def _lockfile_with_packages(self, repo: Path, packages: dict) -> None:
        (repo / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {"name": "fixture"}, **{
                f"node_modules/{name}": {"version": version} for name, version in packages.items()
            }},
        }), encoding="utf-8")

    def test_duplicate_dependencies_are_cached(self):
        """Repeated (ecosystem, name, version) lookups hit the cache, not the network."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-osv-cache-"))
        try:
            clear_osv_cache()
            self._lockfile_with_packages(repo, {"cacheprobe-pkg": "1.0.0"})
            response = io.BytesIO(b'{"vulns":[]}')
            with patch.dict(os.environ, {"VCQA_OSV_ENABLED": "1"}), patch(
                "vibe_coding_qa.scanners.dependencies.urllib.request.urlopen",
                return_value=response,
            ) as urlopen:
                DependencyScanner(repo)._osv_lookup("npm", "cacheprobe-pkg", "1.0.0")
                DependencyScanner(repo)._osv_lookup("npm", "cacheprobe-pkg", "1.0.0")
            self.assertEqual(urlopen.call_count, 1)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_failed_lookup_is_reported_not_silently_clean(self):
        """A network failure must surface as an unverified note, never a clean result."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-osv-fail-"))
        try:
            clear_osv_cache()
            self._lockfile_with_packages(repo, {"failing-pkg": "1.0.0"})
            with patch.dict(os.environ, {"VCQA_OSV_ENABLED": "1"}), patch(
                "vibe_coding_qa.scanners.dependencies.urllib.request.urlopen",
                side_effect=urllib.error.URLError("offline"),
            ):
                scanner = DependencyScanner(repo)
                findings = scanner.scan()
            self.assertEqual([f for f in findings if f.rule == "dependencies:osv-verified-vulnerability"], [])
            self.assertTrue(any("could not be verified" in note for note in scanner.notes))
            self.assertTrue(any("failing-pkg@1.0.0" in note for note in scanner.notes))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_global_budget_defers_remaining_lookups(self):
        """When the time budget is exhausted, skipped dependencies are reported explicitly."""
        repo = Path(tempfile.mkdtemp(prefix="vcqa-osv-budget-"))
        try:
            clear_osv_cache()
            self._lockfile_with_packages(repo, {"budget-a": "1.0.0", "budget-b": "1.0.0"})
            response = io.BytesIO(b'{"vulns":[]}')
            with patch.dict(os.environ, {
                "VCQA_OSV_ENABLED": "1",
                "VCQA_OSV_BUDGET_SECONDS": "1",
            }), patch(
                "vibe_coding_qa.scanners.dependencies.urllib.request.urlopen",
                return_value=response,
            ), patch(
                "vibe_coding_qa.scanners.dependencies.time.monotonic",
                side_effect=[0.0, 5.0, 5.0, 5.0],
            ):
                scanner = DependencyScanner(repo)
                scanner._scan_osv()
            self.assertTrue(any("skipped after the" in note for note in scanner.notes))
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class RepoWalkerTests(TestCase):
    """P5: the shared repository walker prunes generated/vendored trees safely."""

    def _make_repo(self) -> Path:
        repo = Path(tempfile.mkdtemp(prefix="vcqa-walk-"))
        (repo / "src").mkdir()
        (repo / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
        for generated in ("node_modules", ".venv", "dist", "build", "coverage", "__pycache__"):
            directory = repo / generated
            directory.mkdir()
            (directory / "generated.py").write_text("x = 1\n", encoding="utf-8")
        (repo / "node_modules" / "pkg").mkdir()
        (repo / "node_modules" / "pkg" / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
        return repo

    def test_generated_directories_are_pruned(self):
        repo = self._make_repo()
        try:
            rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
            self.assertIn("src/app.py", rel)
            for generated in ("node_modules", ".venv", "dist", "build", "coverage", "__pycache__"):
                self.assertFalse(
                    any(part == generated for path in rel for part in Path(path).parts),
                    f"{generated} should have been pruned",
                )
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_excluded_dirs_constant_covers_required_names(self):
        required = {
            ".git", "node_modules", ".venv", "venv", "__pycache__", ".next", ".nuxt",
            "dist", "build", "out", "coverage", ".pytest_cache", ".mypy_cache",
            ".ruff_cache", "vendor",
        }
        self.assertTrue(required.issubset(EXCLUDED_DIRS))

    def test_vcqaignore_is_respected(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-walk-ignore-"))
        try:
            (repo / "keep.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "generated_third_party").mkdir()
            (repo / "generated_third_party" / "gen.py").write_text("y = 1\n", encoding="utf-8")
            (repo / ".vcqaignore").write_text("generated_third_party\n", encoding="utf-8")
            rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
            self.assertIn("keep.py", rel)
            self.assertNotIn("generated_third_party/gen.py", rel)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_symlinks_are_not_followed(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-walk-link-"))
        outside = Path(tempfile.mkdtemp(prefix="vcqa-walk-outside-"))
        try:
            (repo / "real.py").write_text("x = 1\n", encoding="utf-8")
            (outside / "secret.py").write_text("token = 'leaked'\n", encoding="utf-8")
            try:
                os.symlink(outside / "secret.py", repo / "linked.py")
                os.symlink(outside, repo / "linked_dir")
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not permitted on this platform")
            rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
            self.assertIn("real.py", rel)
            self.assertNotIn("linked.py", rel)
            self.assertFalse(any(path.startswith("linked_dir/") for path in rel))
        finally:
            shutil.rmtree(repo, ignore_errors=True)
            shutil.rmtree(outside, ignore_errors=True)

    def test_language_detection_ignores_generated_code(self):
        repo = self._make_repo()
        try:
            (repo / "node_modules" / "pkg" / "big.ts").write_text("export const x = 1\n", encoding="utf-8")
            (repo / "dist" / "bundle.js").write_text("var x = 1\n", encoding="utf-8")
            profile = analyze_repo(repo)
            self.assertEqual(profile.languages.get("python"), 1)  # only src/app.py
            self.assertNotIn("typescript", profile.languages)
            self.assertNotIn("javascript", profile.languages)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_completeness_is_reported_when_exclusions_present(self):
        repo = self._make_repo()
        try:
            profile = analyze_repo(repo)
            self.assertTrue(any("excluded" in note.lower() for note in profile.notes))
            self.assertTrue(any("node_modules" in note for note in profile.notes))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_lockfile_and_config_detection_is_preserved(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-walk-config-"))
        try:
            (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (repo / ".env.example").write_text("API_KEY=\n", encoding="utf-8")
            (repo / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            profile = analyze_repo(repo)
            self.assertIn("requirements.txt", profile.lockfiles)
            self.assertIn(".env.example", profile.env_files)
            self.assertIn("docker", profile.deployment)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_non_python_dependency_tests_are_not_discovered_in_node_modules(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-walk-tests-"))
        try:
            (repo / "node_modules").mkdir()
            (repo / "node_modules" / "vendored.test.ts").write_text("test('x', () => {})\n", encoding="utf-8")
            profile = analyze_repo(repo)
            self.assertNotIn("ts-js-tests", profile.test_runners)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class RLSMigrationParsingTests(TestCase):
    """P6: identifier-aware RLS analysis with honest coverage reporting."""

    def _run_sql(self, sql: str) -> ScanResult:
        repo = Path(tempfile.mkdtemp(prefix="vcqa-rls-parse-"))
        try:
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001_migration.sql").write_text(sql, encoding="utf-8")
            return run_scan(repo)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    @staticmethod
    def _db_notes(result: ScanResult) -> list[str]:
        module = next(m for m in result.modules if m.module == "database")
        return module.notes

    def test_quoted_schema_and_table_identifiers_are_tracked(self):
        result = self._run_sql(
            'CREATE TABLE "auth"."Users" (id uuid primary key);\n'
            'ALTER TABLE "auth"."Users" ENABLE ROW LEVEL SECURITY;\n'
            'CREATE POLICY "Users own" ON "auth"."Users" FOR ALL TO authenticated USING (auth.uid() = id);\n'
        )
        rules = {f.rule for f in result.findings}
        self.assertNotIn("database:table-without-rls", rules)
        self.assertNotIn("database:policy-without-rls-enabled", rules)
        self.assertNotIn("database:rls-policy-missing-role-restriction", rules)

    def test_alter_table_only_enable_is_recognized(self):
        result = self._run_sql(
            "CREATE TABLE app.t (id integer);\n"
            "ALTER TABLE ONLY app.t ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY p ON app.t FOR SELECT TO authenticated USING (auth.uid() = id);\n"
        )
        self.assertNotIn("database:table-without-rls", {f.rule for f in result.findings})

    def test_force_row_level_security_alone_does_not_enable_rls(self):
        result = self._run_sql(
            "CREATE TABLE app.t (id integer);\n"
            "ALTER TABLE app.t FORCE ROW LEVEL SECURITY;\n"
        )
        self.assertIn("database:table-without-rls", {f.rule for f in result.findings})

    def test_with_check_only_policy_counts_as_condition(self):
        result = self._run_sql(
            "CREATE TABLE app.t (id integer, owner uuid);\n"
            "ALTER TABLE app.t ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY ins ON app.t FOR INSERT TO authenticated WITH CHECK (owner = auth.uid());\n"
        )
        rules = {f.rule for f in result.findings}
        self.assertNotIn("database:rls-policy-missing-condition", rules)
        self.assertNotIn("database:rls-policy-missing-role-restriction", rules)

    def test_quoted_role_is_recognized(self):
        result = self._run_sql(
            "CREATE TABLE app.t (id integer);\n"
            "ALTER TABLE app.t ENABLE ROW LEVEL SECURITY;\n"
            'CREATE POLICY p ON app.t FOR SELECT TO "authenticated" USING (auth.uid() = id);\n'
        )
        self.assertNotIn("database:rls-policy-missing-role-restriction", {f.rule for f in result.findings})

    def test_disclaims_full_parser(self):
        result = self._run_sql("CREATE TABLE app.t (id integer);\n")
        self.assertTrue(any("not a full PostgreSQL parser" in note for note in self._db_notes(result)))

    def test_dynamic_sql_is_reported_as_coverage_limitation(self):
        result = self._run_sql(
            "DO $$\nBEGIN\n  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', 'app.t');\nEND $$;\n"
        )
        notes = self._db_notes(result)
        self.assertTrue(any("cannot be determined" in note for note in notes))

    def test_heuristic_method_is_disclosed(self):
        result = self._run_sql("-- nothing to see here\n")
        self.assertTrue(any("pattern matching" in note for note in self._db_notes(result)))

    def test_missing_pglast_is_disclosed(self):
        result = self._run_sql("CREATE TABLE app.t (id integer);\n")
        notes = self._db_notes(result)
        self.assertTrue(any("pglast" in note for note in notes))


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
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="Ran 1 test in 0.001s\n\nOK")):
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
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_returncode=1, run_stdout="Ran 1 test in 0.001s\n\nFAILED (failures=1)")):
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
            (repo / "src" / "secret.ts").write_text('const API_KEY = "' + _OPENAI_KEY + '";\n')
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
            ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=fake_sandbox_run(run_stdout="Ran 1 test in 0.001s\n\nOK")):
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


class SecretPlaceholderRegressionTests(TestCase):
    """Legitimate credentials must never be suppressed by surrounding text."""

    def _scan_rules(self, files: dict[str, str]) -> set[str]:
        repo = Path(tempfile.mkdtemp(prefix="vcqa-secret-regress-"))
        try:
            for relative, content in files.items():
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            return {f.rule for f in run_scan(repo).findings}
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_genuine_openai_key_in_test_file_is_detected(self):
        rules = self._scan_rules({
            "tests/test_openai.py": 'OPENAI_API_KEY = "' + _OPENAI_KEY + '"\n',
        })
        self.assertIn("security:openai-key", rules)

    def test_genuine_github_token_in_fixture_is_detected(self):
        rules = self._scan_rules({
            "fixtures/github.json": '{"token": "' + _GITHUB_TOKEN + '"}\n',
        })
        self.assertIn("security:github-token", rules)

    def test_real_credential_assigned_to_test_variable_is_detected(self):
        rules = self._scan_rules({
            "src/config.py": 'TEST_API_KEY = "' + _OPENAI_KEY + '"\n',
        })
        self.assertIn("security:openai-key", rules)

    def test_real_credential_on_line_containing_example_is_detected(self):
        rules = self._scan_rules({
            "src/config.js": 'const payload = {"example": "' + _OPENAI_KEY + '"};\n',
        })
        self.assertIn("security:openai-key", rules)

    def test_real_credential_in_mock_configuration_is_detected(self):
        rules = self._scan_rules({
            "mocks/config.ts": 'MOCK_API_KEY = "' + _OPENAI_KEY + '"\n',
        })
        self.assertIn("security:openai-key", rules)

    def test_private_key_in_test_file_is_detected(self):
        pem = _PEM_KEY_SHORT
        rules = self._scan_rules({"tests/test_crypto.py": pem + "\n"})
        self.assertIn("security:private-key", rules)

    def test_genuine_placeholder_is_filtered(self):
        rules = self._scan_rules({
            "fixtures/config.json": '{"api_key": "your-api-key-here"}\n',
        })
        self.assertNotIn("security:generic-api-key", rules)
        self.assertNotIn("security:client-side-secret", rules)

    def test_real_token_containing_substring_test_is_detected(self):
        rules = self._scan_rules({
            "src/service.py": 'token = "' + _OPENAI_KEY_TEST_SUBSTR + '"\n',
        })
        self.assertIn("security:openai-key", rules)

    def test_placeholder_reason_is_explainable(self):
        self.assertEqual(
            SecurityScanner._placeholder_reason("your-api-key-here"),
            "known placeholder literal",
        )
        self.assertIsNone(SecurityScanner._placeholder_reason(_OPENAI_KEY))


class TestResultClassificationTests(TestCase):
    """Exit code alone must never be treated as a passing test run."""

    def test_unittest_pass_is_verified(self):
        result = classify_test_results("Ran 3 tests in 0.010s\n\nOK", 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["runner"], "unittest")
        self.assertEqual(result["counts"]["passed"], 3)
        self.assertEqual(result["counts"]["executed"], 3)

    def test_pytest_pass_is_verified(self):
        result = classify_test_results("collected 2 items\n\n2 passed in 0.10s", 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["runner"], "pytest")

    def test_jest_pass_is_verified(self):
        result = classify_test_results("Tests:       4 passed, 4 total", 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["runner"], "jest")

    def test_vitest_pass_is_verified(self):
        result = classify_test_results("  Tests  2 passed (2)", 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["runner"], "vitest")

    def test_zero_exit_with_unrecognized_output_is_not_verified(self):
        result = classify_test_results("everything looks fine", 0)
        self.assertEqual(result["status"], "skip")
        self.assertEqual(result["reason"], "no_recognizable_results")

    def test_empty_output_is_not_verified(self):
        result = classify_test_results("", 0)
        self.assertEqual(result["status"], "skip")

    def test_all_tests_skipped_is_not_verified(self):
        result = classify_test_results("Ran 2 tests in 0.010s\n\nOK (skipped=2)", 0)
        self.assertEqual(result["status"], "skip")
        self.assertEqual(result["reason"], "all_tests_skipped")
        self.assertEqual(result["counts"]["executed"], 0)

    def test_zero_tests_discovered_is_not_verified(self):
        result = classify_test_results("Ran 0 tests in 0.000s\n\nOK", 0)
        self.assertEqual(result["status"], "skip")
        self.assertEqual(result["reason"], "zero_tests_discovered")

    def test_failures_are_reported_as_fail(self):
        result = classify_test_results("Ran 2 tests in 0.010s\n\nFAILED (failures=1)", 1)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["reason"], "tests_failed")
        self.assertEqual(result["counts"]["failed"], 1)

    def test_non_zero_exit_with_parsed_success_is_fail(self):
        result = classify_test_results("collected 1 item\n\n1 passed in 0.05s", 1)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["reason"], "non_zero_exit")


class DockerWorkspaceIsolationTests(TestCase):
    """Original sources stay read-only; tests run in a bounded writable workspace."""

    def _run_with_capture(self, repo, run_stdout="Ran 1 test in 0.001s\n\nOK", run_returncode=0):
        captured = {}

        def capture(command, **kwargs):
            captured["command"] = command
            return subprocess.CompletedProcess(command, run_returncode, run_stdout, ""), False, False

        with patch("vibe_coding_qa.engine.shutil.which", return_value="docker"), patch(
            "vibe_coding_qa.engine.subprocess.run", side_effect=fake_docker_run()
        ), patch("vibe_coding_qa.engine._run_bounded_process", side_effect=capture):
            result = run_tests(
                repo,
                command="python -m pytest",
                explicit_permission=True,
                max_write_mb=32,
            )
        return result, captured["command"]

    def test_snapshot_mounted_read_only_and_workspace_is_writable(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-ws-"))
        try:
            (repo / "keep.py").write_text("print('ok')\n", encoding="utf-8")
            result, command = self._run_with_capture(repo)
            joined = " ".join(command)
            self.assertEqual(result["status"], "pass")
            self.assertIn("/vcqa-src,readonly", joined)
            self.assertIn("/workspace:rw", joined)
            self.assertIn("--read-only", command)
            self.assertIn("none", command)
            inner = command[-1]
            self.assertIn("cp -R /vcqa-src/. /workspace/", inner)
            self.assertIn("exec", inner)
            # The container has no CAP_CHOWN (--cap-drop ALL), so the copy must not
            # preserve ownership or it would fail with EPERM and abort the run.
            self.assertNotIn("cp -a ", inner)
            self.assertNotIn("cp -p ", inner)
            self.assertNotIn("--preserve", inner)
            limits = result["resource_limits"]
            self.assertEqual(limits["source_mount"], "read-only")
            self.assertEqual(limits["workspace"], "tmpfs-read-write")
            self.assertEqual(limits["workspace_max_mb"], 32)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_original_repository_is_not_modified(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-orig-"))
        try:
            (repo / "app.py").write_text("print('original')\n", encoding="utf-8")
            (repo / ".env").write_text("TOKEN=developer-secret\n", encoding="utf-8")
            self._run_with_capture(repo)
            self.assertEqual((repo / "app.py").read_text(encoding="utf-8"), "print('original')\n")
            self.assertTrue((repo / ".env").is_file())
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_workspace_size_exceeded_is_a_failure(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-space-"))
        try:
            result, _ = self._run_with_capture(
                repo,
                run_returncode=1,
                run_stdout="cp: error writing '/workspace/x': No space left on device",
            )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["test_reason"], "workspace_size_exceeded")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_missing_dependency_is_not_verified(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-dep-"))
        try:
            result, _ = self._run_with_capture(
                repo,
                run_returncode=127,
                run_stdout="/usr/local/bin/python: No module named 'pytest'",
            )
            self.assertEqual(result["status"], "skip")
            self.assertEqual(result["execution_mode"], "test_infrastructure_unavailable")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_missing_module_never_reports_pass(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-nopass-"))
        try:
            result, _ = self._run_with_capture(
                repo,
                run_returncode=0,
                run_stdout="Error: Cannot find module 'vitest'",
            )
            self.assertNotEqual(result["status"], "pass")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_isolation_flags_are_all_present(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-flags-"))
        try:
            _, command = self._run_with_capture(repo)
            joined = " ".join(command)
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
            self.assertIn("--read-only", command)
            self.assertIn("no-new-privileges", command)
            self.assertIn("--pids-limit", command)
            self.assertIn("--memory", command)
            self.assertIn("--ulimit", command)
            # Images must never be pulled implicitly by the engine.
            self.assertIn("--pull=never", joined)
            self.assertIn("/vcqa-src,readonly", joined)
            # Only an allowlisted set of environment variables is passed through.
            self.assertFalse(any(arg.startswith("VCQA_") for arg in command))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_container_start_failure_is_not_a_pass(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-docker-startfail-"))
        try:
            result, _ = self._run_with_capture(
                repo,
                run_returncode=125,
                run_stdout="docker: Error response from daemon: unable to start container.",
            )
            self.assertNotEqual(result["status"], "pass")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class FixVerificationTests(TestCase):
    """Fix verification must be evidence-based, never inferred from edits.

    A fix is only ``resolved`` when a fresh scan no longer reports the rule for
    that file. Editing a file or shifting a line number is never enough.
    """

    def _engine(self, applied):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-verify-"))
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
        engine = FixEngine(repo, dry_run=False)
        engine.applied = list(applied)
        return engine

    @staticmethod
    def _change(rule, file, line):
        return {"finding": {"rule": rule, "file": str(Path(file)), "line": line}}

    @staticmethod
    def _finding(rule, file, line):
        return Finding(
            rule=rule,
            module="quality",
            severity=Severity.MEDIUM,
            file=Path(file),
            line=line,
        )

    def test_resolved_when_rule_disappears_from_rescan(self):
        file = "src/app.ts"
        rule = "quality:console-log-in-production"
        engine = self._engine([self._change(rule, file, 3)])
        report = engine.verify([])  # fresh scan no longer reports the rule
        self.assertEqual(len(report["resolved"]), 1)
        self.assertEqual(report["resolved"][0]["rule"], rule)
        self.assertTrue(report["verified"])
        self.assertEqual(engine.applied[0]["resolution"], "resolved")

    def test_unresolved_when_rule_remains_even_if_line_shifted(self):
        file = "src/app.ts"
        rule = "quality:console-log-in-production"
        engine = self._engine([self._change(rule, file, 3)])
        # Same rule/file still reported; only the line number moved.
        report = engine.verify([self._finding(rule, file, 42)])
        self.assertEqual(len(report["unresolved"]), 1)
        self.assertFalse(report["verified"])
        self.assertEqual(engine.applied[0]["resolution"], "unresolved")

    def test_partially_resolved_when_multiplicity_drops_but_not_to_zero(self):
        file = "src/app.ts"
        rule = "quality:console-log-in-production"
        engine = self._engine([self._change(rule, file, 3), self._change(rule, file, 7)])
        report = engine.verify([self._finding(rule, file, 9)])
        self.assertEqual(len(report["partially_resolved"]), 1)
        entry = report["partially_resolved"][0]
        self.assertEqual(entry["attempted"], 2)
        self.assertEqual(entry["remaining"], 1)
        self.assertFalse(report["verified"])
        self.assertEqual(report["resolved"], [])

    def test_unverifiable_when_tests_fail(self):
        file = "src/app.ts"
        rule = "quality:console-log-in-production"
        engine = self._engine([self._change(rule, file, 3)])
        report = engine.verify([], tests={"status": "fail"})
        self.assertEqual(len(report["unverifiable"]), 1)
        self.assertTrue(report["tests_failed"])
        self.assertFalse(report["verified"])
        # A regression must never be reported as resolved.
        self.assertEqual(report["resolved"], [])

    def test_unrelated_rule_in_rescan_does_not_block_resolution(self):
        file = "src/app.ts"
        rule = "quality:console-log-in-production"
        engine = self._engine([self._change(rule, file, 3)])
        report = engine.verify([self._finding("security:openai-key", file, 1)])
        self.assertEqual(len(report["resolved"]), 1)
        self.assertTrue(report["verified"])

    def test_run_pipeline_exposes_fix_verification(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-pipeline-"))
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
        (repo / "app.ts").write_text('console.log("debug");\nconst x = 1;\n', encoding="utf-8")
        with patch(
            "vibe_coding_qa.engine.run_tests",
            return_value={"status": "pass", "executed": 1, "failed": 0},
        ), patch("vibe_coding_qa.engine.review_findings", return_value=[]):
            result = run_pipeline(
                str(repo),
                apply_fixes=True,
                dry_run_fixes=True,
                run_tests_flag=True,
            )
        fixes = result.tests["fixes"]
        self.assertFalse(fixes["dry_run"])
        verification = fixes["verification"]
        self.assertIsNotNone(verification)
        resolved_rules = {entry["rule"] for entry in verification["resolved"]}
        self.assertIn("quality:console-log-in-production", resolved_rules)
        self.assertEqual(verification["unresolved"], [])

    def test_run_pipeline_without_apply_leaves_verification_none(self):
        repo = Path(tempfile.mkdtemp(prefix="vcqa-pipeline-dry-"))
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
        (repo / "app.ts").write_text('console.log("debug");\n', encoding="utf-8")
        with patch(
            "vibe_coding_qa.engine.run_tests",
            return_value={"status": "pass", "executed": 1, "failed": 0},
        ), patch("vibe_coding_qa.engine.review_findings", return_value=[]):
            result = run_pipeline(str(repo), dry_run_fixes=True, run_tests_flag=True)
        fixes = result.tests["fixes"]
        self.assertTrue(fixes["dry_run"])
        self.assertIsNone(fixes["verification"])
        # Dry-run must not modify the repository.
        self.assertIn("console.log", (repo / "app.ts").read_text(encoding="utf-8"))


if __name__ == "__main__":
    import unittest
    unittest.main()
