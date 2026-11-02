import shutil
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa import Finding, ModuleResult, ScanResult, Severity, Status
from vibe_coding_qa.ai_review import OpenRouterAIProvider, get_ai_provider
from vibe_coding_qa.engine import run_scan, run_tests
from vibe_coding_qa.fixes import FixEngine
from vibe_coding_qa.gates import assess, release_decision
from vibe_coding_qa.reporters import html_report


SAMPLES = Path(__file__).resolve().parent.parent / "samples"


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
        self.assertIn("PASS", release_decision(result))


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
            result = run_tests(repo, command="rm -rf /")
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
            result = run_tests(repo)
            self.assertEqual(result["status"], "skip")
            self.assertIn("No test runner", result["summary"])
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class ReportTests(TestCase):
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
    def test_core_works_without_ai_credentials(self):
        provider = get_ai_provider()
        review = provider.review(Finding(rule="test", module="security", severity=Severity.HIGH, file=Path("x"), line=1))
        self.assertFalse(review["enabled"])

    def test_openrouter_provider_reports_http_errors(self):
        provider = OpenRouterAIProvider(api_key="fake", base_url="https://invalid.invalid", timeout=2)
        review = provider.review(Finding(rule="test", module="security", severity=Severity.HIGH, file=Path("x"), line=1))
        self.assertTrue(review["enabled"])
        self.assertIn("error", review)


if __name__ == "__main__":
    import unittest
    unittest.main()
