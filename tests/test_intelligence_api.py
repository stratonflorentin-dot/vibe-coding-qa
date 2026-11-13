"""API tests for the Vibe Intelligence routes (auth, no-secret health, tasks)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:  # pragma: no cover - optional web stack
    from fastapi.testclient import TestClient

    from dashboard.backend.config import reset_settings
    from dashboard.backend.main import create_app

    WEB_STACK = True
except Exception:  # noqa: BLE001
    WEB_STACK = False


@unittest.skipUnless(WEB_STACK, "FastAPI/httpx are not installed")
class IntelligenceApiTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VCQA_DASHBOARD_DB"] = str(Path(self._tmp.name) / "vcqa.sqlite3")
        os.environ.pop("VCQA_BASIC_AUTH", None)   # open mode: no login needed
        os.environ.pop("VCQA_AI_API_KEY", None)
        os.environ.pop("VCQA_AI_PROVIDER", None)
        self.app = create_app(reset_settings())
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.store = self.app.state.services.store
        self.repo = self.store.create_repository(name="demo", source="/x", source_type="local")
        self.scan = self.store.create_scan(repository_id=self.repo["id"], profile="deep", options={})
        self.store.update_scan(self.scan["id"], status="completed", gate="block", test_status="skip",
                               overall_score=68.2, critical_count=1, total_findings=1)
        self.store.insert_findings(self.scan["id"], self.repo["id"], [
            {"rule": "security:jwt-token", "module": "security", "severity": "critical",
             "file": "app/x.py", "line": 10, "message": "token leaked"},
        ])

    def tearDown(self):
        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self._env)
        reset_settings()
        self._tmp.cleanup()

    def test_health_exposes_no_secrets(self):
        res = self.client.get("/api/intelligence/health")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["configured"], False)
        self.assertEqual(len(body["operations"]), 8)
        text = res.text.lower()
        for leak in ("api_key", "bearer", "authorization", "secret"):
            self.assertNotIn(leak, text)

    def test_providers_and_models(self):
        self.assertEqual(self.client.get("/api/intelligence/providers").status_code, 200)
        self.assertNotIn("api_key", self.client.get("/api/intelligence/models").text)

    def test_run_deterministic_task(self):
        res = self.client.post("/api/intelligence/tasks", json={
            "operation": "summarize_verification", "scan_id": self.scan["id"],
        })
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["operation"], "summarize_verification")
        self.assertEqual(body["status"], "completed")
        self.assertTrue(body["data"]["not_executed"])
        task_id = body["task_id"]
        self.assertEqual(self.client.get(f"/api/intelligence/tasks/{task_id}").status_code, 200)

    def test_unknown_operation_is_rejected(self):
        res = self.client.post("/api/intelligence/tasks", json={"operation": "take_over_the_world"})
        self.assertEqual(res.status_code, 422)

    def test_missing_required_field(self):
        res = self.client.post("/api/intelligence/tasks", json={"operation": "summarize_verification"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["code"], "invalid_task")

    def test_unknown_project(self):
        res = self.client.post("/api/intelligence/tasks", json={
            "operation": "analyze_project", "repository_id": 99999,
        })
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()["code"], "project_not_found")


if __name__ == "__main__":
    unittest.main()
