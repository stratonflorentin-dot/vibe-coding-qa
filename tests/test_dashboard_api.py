"""Backend API tests for the v0.5.0 dashboard.

These tests exercise the real FastAPI app against a temporary SQLite database
and a real (small) repository, so they verify behaviour rather than mocks:
a scan must actually run, produce findings, persist events and be visible
through every read endpoint.

The dashboard's HTTP dependencies (FastAPI/httpx) are optional, so the whole
module is skipped when they are not installed.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_REPO = PROJECT_ROOT / "samples" / "vulnerable_repo"

try:  # pragma: no cover - import guard for the optional web stack
    from fastapi.testclient import TestClient

    from dashboard.backend.config import reset_settings
    from dashboard.backend.main import create_app

    WEB_STACK = True
except Exception:  # noqa: BLE001
    WEB_STACK = False


def _wait_for_scan(client, scan_id, timeout=120.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        if response.status_code != 200:
            raise AssertionError(f"scan lookup failed: {response.status_code} {response.text}")
        scan = response.json()
        if scan["status"] in ("completed", "failed", "cancelled"):
            return scan
        time.sleep(0.2)
    raise AssertionError("scan did not reach a terminal state in time")


@unittest.skipUnless(WEB_STACK, "FastAPI/httpx are not installed")
class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        import os

        self._env = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VCQA_DASHBOARD_DB"] = str(Path(self._tmp.name) / "vcqa.sqlite3")
        os.environ.pop("VCQA_AI_API_KEY", None)
        os.environ.pop("VCQA_AI_PROVIDER", None)
        os.environ["VCQA_MAX_CONCURRENT_SCANS"] = "2"
        self.app = create_app(reset_settings())
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self):
        import os

        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self._env)
        reset_settings()
        self._tmp.cleanup()

    # ------------------------------------------------------------------ helpers
    def _register_sample_repo(self) -> int:
        response = self.client.post(
            "/api/repositories",
            json={"source": str(SAMPLE_REPO), "source_type": "local", "name": "vulnerable_repo"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def _run_quick_scan(self, repository_id: int) -> dict:
        response = self.client.post(
            "/api/scans",
            json={"repository_id": repository_id, "profile": "quick", "options": {"static_only": True}},
        )
        self.assertEqual(response.status_code, 202, response.text)
        return _wait_for_scan(self.client, response.json()["id"])

    # -------------------------------------------------------------------- system
    def test_health_and_profiles(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        body = health.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["version"], "0.5.0")
        self.assertFalse(body["ai_configured"])

        profiles = self.client.get("/api/profiles").json()
        keys = {profile["key"] for profile in profiles}
        self.assertIn("quick", keys)
        self.assertIn("production_readiness", keys)
        # A profile is real configuration, not a label: it selects modules.
        quick = next(p for p in profiles if p["key"] == "quick")
        self.assertEqual(quick["modules"], ["security", "dependencies"])
        self.assertFalse(quick["run_tests"])

    def test_scan_settings_round_trip(self):
        current = self.client.get("/api/settings/scan").json()
        self.assertEqual(current["default_scan_profile"], "standard")
        self.assertFalse(current["allow_test_execution"])

        updated = dict(current, default_scan_profile="quick", test_timeout=120, allow_test_execution=False)
        response = self.client.put("/api/settings/scan", json=updated)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["default_scan_profile"], "quick")
        self.assertEqual(self.client.get("/api/settings/scan").json()["test_timeout"], 120)

        bad = self.client.put("/api/settings/scan", json=dict(updated, default_scan_profile="nope"))
        self.assertEqual(bad.status_code, 400)

    def test_ai_settings_never_expose_the_key(self):
        import os

        os.environ["VCQA_AI_PROVIDER"] = "openrouter"
        os.environ["VCQA_AI_API_KEY"] = "sk-super-secret-value"
        settings = reset_settings()
        app = create_app(settings)
        with TestClient(app) as client:
            response = client.get("/api/settings/ai")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertTrue(payload["api_key_configured"])
            self.assertNotIn("sk-super-secret-value", json.dumps(payload))
            self.assertEqual(payload["source"], "environment")

            health = client.get("/api/health").json()
            self.assertTrue(health["ai_configured"])

    def test_ai_key_from_settings_is_used_for_connection_test_without_persistence(self):
        from unittest.mock import patch

        api_key = "sk-runtime-secret"
        response = self.client.put(
            "/api/settings/ai",
            json={
                "enabled": True,
                "provider": "openrouter",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "nvidia/nemotron-3-ultra-550b-a5b:free",
                "timeout": 30,
                "max_output_tokens": 1000,
                "share_source_context": False,
                "api_key": api_key,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["api_key_configured"])
        self.assertNotIn(api_key, response.text)
        self.assertNotIn(api_key, json.dumps(self.app.state.services.store.all_settings()))
        self.assertEqual(self.app.state.services.ai.config().api_key, api_key)

        with patch("dashboard.backend.ai.service.ChatProvider.check", return_value="ready"):
            result = self.client.post("/api/settings/ai/test")
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["configured"])
        self.assertTrue(result.json()["ok"])
        self.assertNotIn(api_key, result.text)

    # -------------------------------------------------------------- repositories
    def test_repository_registration_is_validated(self):
        outside = self.client.post(
            "/api/repositories",
            json={"source": str(Path(tempfile.gettempdir()) / "definitely-not-a-repo"), "source_type": "local"},
        )
        self.assertEqual(outside.status_code, 400)

        embedded = self.client.post(
            "/api/repositories",
            json={"source": "https://user:pass@github.com/acme/app.git", "source_type": "github"},
        )
        self.assertEqual(embedded.status_code, 400)
        self.assertIn("credentials", embedded.json()["detail"].lower())

        repository_id = self._register_sample_repo()
        self.assertEqual(len(self.client.get("/api/repositories").json()), 1)

        duplicate = self.client.post(
            "/api/repositories", json={"source": str(SAMPLE_REPO), "source_type": "local"}
        )
        self.assertEqual(duplicate.status_code, 400)

        detail = self.client.get(f"/api/repositories/{repository_id}").json()
        self.assertEqual(detail["name"], "vulnerable_repo")
        self.assertTrue(detail["main_language"])

        missing = self.client.get("/api/repositories/424242")
        self.assertEqual(missing.status_code, 404)

    # --------------------------------------------------------------------- scans
    def test_scan_runs_and_persists_real_findings(self):
        repository_id = self._register_sample_repo()
        scan = self._run_quick_scan(repository_id)

        self.assertEqual(scan["status"], "completed")
        self.assertIsNotNone(scan["overall_score"])
        self.assertIsNotNone(scan["gate"])
        self.assertGreater(scan["total_findings"], 0)
        self.assertEqual(scan["scanner_versions"]["profile"], "quick")
        self.assertEqual(sorted(scan["scanner_versions"]["modules"]), ["dependencies", "security"])
        # The quick profile is static-only: no tests may have been executed.
        self.assertIn(scan["test_status"], ("skip", None))

        findings = self.client.get("/api/findings", params={"repository_id": repository_id}).json()
        self.assertGreater(findings["total"], 0)
        first = findings["items"][0]
        self.assertEqual(first["repository_id"], repository_id)

        detail = self.client.get(f"/api/findings/{first['id']}").json()
        self.assertIn("evidence", detail)
        self.assertTrue(detail["history"])

        triaged = self.client.patch(f"/api/findings/{first['id']}", json={"status": "dismissed"})
        self.assertEqual(triaged.status_code, 200)
        self.assertEqual(triaged.json()["status"], "dismissed")

    def test_scan_events_are_persisted_and_streamed(self):
        repository_id = self._register_sample_repo()
        scan = self._run_quick_scan(repository_id)

        events = self.client.get(f"/api/scans/{scan['id']}/events.json").json()
        stages = [event["stage"] for event in events]
        self.assertIn("queued", stages)
        self.assertIn("started", stages)
        self.assertIn("completed", stages)
        self.assertEqual(events[-1]["status"], "completed")

        with self.client.stream("GET", f"/api/scans/{scan['id']}/events") as response:
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
            received = []
            for chunk in response.iter_lines():
                if chunk:
                    received.append(chunk)
                if len(received) > 200:
                    break
        text = "\n".join(received)
        self.assertIn("event: open", text)
        self.assertIn("event: scan-event", text)
        self.assertIn("event: end", text)

    def test_comparing_two_scans(self):
        repository_id = self._register_sample_repo()
        first = self._run_quick_scan(repository_id)
        second = self._run_quick_scan(repository_id)

        response = self.client.get("/api/scans/compare", params={"base": first["id"], "head": second["id"]})
        self.assertEqual(response.status_code, 200, response.text)
        diff = response.json()
        self.assertEqual(diff["base_scan_id"], first["id"])
        self.assertEqual(diff["head_scan_id"], second["id"])
        self.assertIn("added", diff)
        self.assertIn("resolved", diff)

        current_findings = self.client.get("/api/findings").json()
        self.assertEqual(current_findings["total"], second["total_findings"])

        same = self.client.get("/api/scans/compare", params={"base": first["id"], "head": first["id"]})
        self.assertEqual(same.status_code, 400)

    def test_unknown_scan_profile_is_rejected(self):
        repository_id = self._register_sample_repo()
        response = self.client.post(
            "/api/scans", json={"repository_id": repository_id, "profile": "does-not-exist"}
        )
        self.assertEqual(response.status_code, 400)

    # ---------------------------------------------------------------- dashboard
    def test_overview_reports_no_data_until_a_scan_completes(self):
        empty = self.client.get("/api/dashboard/overview").json()
        self.assertFalse(empty["has_data"])
        self.assertEqual(empty["score_history"], [])
        self.assertIsNone(empty["summary"]["overall_score"])

        repository_id = self._register_sample_repo()
        self._run_quick_scan(repository_id)

        populated = self.client.get("/api/dashboard/overview").json()
        self.assertTrue(populated["has_data"])
        self.assertIsNotNone(populated["summary"]["overall_score"])
        self.assertTrue(populated["score_history"])
        self.assertTrue(populated["repository_health"])

        activity = self.client.get("/api/dashboard/activity").json()
        self.assertTrue(activity["items"])

    # ------------------------------------------------------------- intelligence
    def test_architecture_and_dependencies(self):
        repository_id = self._register_sample_repo()
        scan = self._run_quick_scan(repository_id)

        extra_findings = [
            {
                "rule": "quality:repeated-test-finding",
                "module": "quality",
                "severity": "medium",
                "file": f"src/repeated/finding-{index}.ts",
                "line": 1,
                "message": "Repeated finding used to verify complete architecture results.",
            }
            for index in range(205)
        ]
        self.app.state.services.store.insert_findings(scan["id"], repository_id, extra_findings)

        architecture = self.client.get(f"/api/architecture/{repository_id}").json()
        node_ids = {node["id"] for node in architecture["nodes"]}
        self.assertIn("app", node_ids)
        self.assertTrue(architecture["notes"])
        attached_findings = [
            finding
            for node_findings in architecture["findings_by_node"].values()
            for finding in node_findings
        ]
        self.assertEqual(len(attached_findings), scan["total_findings"] + len(extra_findings))
        self.assertTrue(any(finding["module"] == "quality" for finding in attached_findings))

        dependencies = self.client.get(f"/api/dependencies/{repository_id}").json()
        self.assertFalse(dependencies["osv_checked"])
        names = {dep["name"] for dep in dependencies["dependencies"]}
        self.assertTrue(names)

    # ------------------------------------------------------------------------ AI
    def test_ai_endpoints_degrade_honestly_without_a_provider(self):
        repository_id = self._register_sample_repo()
        scan = self._run_quick_scan(repository_id)
        finding_id = self.client.get(
            "/api/findings", params={"scan_id": scan["id"]}
        ).json()["items"][0]["id"]
        finding = self.app.state.services.store.get_finding(finding_id)
        repository = self.app.state.services.store.get_repository(repository_id)
        self.assertEqual(
            self.app.state.services.ai._finding_evidence(finding, repository),
            "",
        )

        chat = self.client.post("/api/ai/chat", json={"message": "What is the riskiest issue?"})
        self.assertEqual(chat.status_code, 200, chat.text)
        chat_body = chat.json()
        self.assertFalse(chat_body["configured"])
        self.assertIn("not configured", chat_body["message"]["content"].lower())
        conversation_id = chat_body["conversation_id"]

        history = self.client.get(f"/api/ai/conversations/{conversation_id}").json()
        self.assertEqual(len(history["messages"]), 2)
        self.assertGreaterEqual(
            self.client.get("/api/ai/conversations").json()[0]["message_count"], 2
        )

        review = self.client.post(f"/api/ai/findings/{finding_id}/review", json={"kind": "analyst"})
        self.assertEqual(review.status_code, 200)
        self.assertFalse(review.json()["configured"])

        test_draft = self.client.post(f"/api/ai/findings/{finding_id}/test")
        self.assertEqual(test_draft.status_code, 200)
        self.assertFalse(test_draft.json()["configured"])

        proposal = self.client.post("/api/ai/remediations", json={"finding_id": finding_id})
        self.assertEqual(proposal.status_code, 400)
        self.assertEqual(proposal.json()["code"], "ai_error")

        summary = self.client.post("/api/ai/summary", json={"scan_id": scan["id"]})
        self.assertEqual(summary.status_code, 200)
        summary_body = summary.json()
        self.assertFalse(summary_body["configured"])
        # A local factual fallback is still produced from real scan data.
        self.assertIn("Overall score", summary_body["text"])

        threat = self.client.post("/api/ai/threat-model", json={"repository_id": repository_id})
        self.assertEqual(threat.status_code, 400)

    def test_remediation_requires_confirmation(self):
        repository_id = self._register_sample_repo()
        scan = self._run_quick_scan(repository_id)
        finding_id = self.client.get(
            "/api/findings", params={"scan_id": scan["id"]}
        ).json()["items"][0]["id"]

        # Insert a proposal directly: generating one needs an AI provider.
        store = self.app.state.services.store
        proposal = store.create_proposal(
            finding_id=finding_id,
            repository_id=repository_id,
            provider="test",
            model="test",
            file="src/server.ts",
            original="SOMETHING_THAT_IS_NOT_IN_THE_FILE",
            proposed="REPLACEMENT",
            diff="",
            rationale="unit test fixture",
        )

        blocked = self.client.post(f"/api/ai/remediations/{proposal['id']}/approve", json={"confirm": False})
        self.assertEqual(blocked.status_code, 400)

        stale = self.client.post(f"/api/ai/remediations/{proposal['id']}/approve", json={"confirm": True})
        self.assertEqual(stale.status_code, 400)

        stored = self.client.get(f"/api/ai/remediations/{proposal['id']}").json()
        self.assertEqual(stored["status"], "stale")

    def test_tests_never_run_without_permission(self):
        """Even when the operator enables tests, a scan must opt in explicitly."""
        current = self.client.get("/api/settings/scan").json()
        enabled = dict(
            current,
            allow_test_execution=True,
            test_timeout=5,
            max_memory_mb=128,
            max_cpu_seconds=5,
            max_snapshot_mb=16,
            max_write_mb=8,
        )
        self.assertEqual(self.client.put("/api/settings/scan", json=enabled).status_code, 200)

        repository_id = self._register_sample_repo()
        response = self.client.post(
            "/api/scans",
            json={"repository_id": repository_id, "profile": "quick", "options": {}},
        )
        self.assertEqual(response.status_code, 202)
        scan = _wait_for_scan(self.client, response.json()["id"])
        # The quick profile is static-only, so nothing was executed and the
        # scan still completed with real results.
        self.assertEqual(scan["status"], "completed")
        self.assertIsNone(scan["tests_executed"])


if __name__ == "__main__":
    unittest.main()
