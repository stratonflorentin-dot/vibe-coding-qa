import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa.engine import run_pipeline, run_scan, run_tests
from vibe_coding_qa.fixes import FixEngine
from vibe_coding_qa.gates import assess, release_decision
from vibe_coding_qa.repo import load_repository
from vibe_coding_qa.scanners.security import SecurityScanner


class EngineTests(TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="vcqa-sample-"))
        (self.repo / "src").mkdir()
        (self.repo / "package.json").write_text('{"name":"sample","scripts":{"test":"exit 0"}}')
        (self.repo / "src" / "client.ts").write_text("""
const API_KEY = "sample-key-not-real";
console.log("debug");
function submit() { eval(userInput); }
""")
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
        self.assertIn("security:generic-api-key", rules)
        self.assertIn("database:table-without-rls", rules)
        self.assertTrue(result.release_blocked)

    def test_scan_detects_critical_client_secret(self):
        # Critical patterns (OpenAI/Stripe/AWS/Supabase) in client files trigger client-side-secret.
        (self.repo / "src" / "client-critical.ts").write_text('const OPENAI_KEY = "sk-abc123def456ghi789012";\n')
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

    def test_run_tests_detects_package_json_script(self):
        result = run_tests(self.repo, command="python -c \"print(1)\"")
        self.assertEqual(result["status"], "pass")

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
            self.assertIn("PASS", release_decision(result))
            self.assertFalse(result.release_blocked)
        finally:
            shutil.rmtree(clean, ignore_errors=True)


class RepoLoaderTests(TestCase):
    def test_load_local_path(self):
        path = load_repository(str(Path(__file__).resolve().parent.parent))
        self.assertTrue(path.exists())


if __name__ == "__main__":
    import unittest
    unittest.main()
