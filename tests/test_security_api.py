"""Security Lab API auth, worker revocation and authorized-target tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from fastapi.testclient import TestClient

    from dashboard.backend.config import reset_settings
    from dashboard.backend.main import create_app

    WEB_STACK = True
except Exception:  # pragma: no cover - optional web stack
    WEB_STACK = False


@unittest.skipUnless(WEB_STACK, "FastAPI/httpx are not installed")
class SecurityApiTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VCQA_DASHBOARD_DB"] = str(Path(self._tmp.name) / "security.sqlite3")
        os.environ.pop("VCQA_BASIC_AUTH", None)
        self.app = create_app(reset_settings())
        self.client = TestClient(self.app)
        self.client.__enter__()
        self._setup_owner()
        self.analyst = self._login_as("analyst")
        self.viewer = self._login_as("viewer")

    def tearDown(self):
        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self._env)
        reset_settings()
        self._tmp.cleanup()

    def _setup_owner(self):
        response = self.client.post(
            "/api/auth/setup", json={"username": "owner", "password": "ownerpass123"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        for username, role in (("analyst", "security_analyst"), ("viewer", "viewer")):
            response = self.client.post(
                "/api/auth/users",
                json={"username": username, "password": "password12345", "role": role},
            )
            self.assertEqual(response.status_code, 201, response.text)

    def _login_as(self, username: str):
        client = TestClient(self.app)
        client.__enter__()
        self.addCleanup(lambda: client.__exit__(None, None, None))
        response = client.post("/api/auth/login", json={"username": username, "password": "password12345"})
        self.assertEqual(response.status_code, 200, response.text)
        return client

    def test_security_routes_enforce_admin_and_analyst_roles(self):
        create_body = {
            "name": "private-worker",
            "base_url": "http://security-worker:8765",
            "token": "worker-secret-" + "a" * 40,
            "placement": "private_network",
            "allowed_networks": ["10.20.0.0/16"],
        }
        denied = self.analyst.post("/api/security/workers", json=create_body)
        self.assertEqual(denied.status_code, 403)
        viewer_create = self.viewer.post("/api/security/targets", json={
            "value": "https://example.invalid",
            "ownership_confirmed": True,
            "verify_method": "http",
        })
        self.assertEqual(viewer_create.status_code, 403)
        permitted_analyst = self.analyst.post("/api/security/scans", json={
            "target_id": 999, "profile": "basic",
        })
        self.assertNotEqual(permitted_analyst.status_code, 403)
        self.assertEqual(self.viewer.get("/api/security/profiles").status_code, 200)
        summary = self.viewer.get("/api/security/summary")
        self.assertEqual(summary.status_code, 200, summary.text)
        self.assertEqual(
            set(summary.json()),
            {"critical", "high", "medium", "low", "info"},
        )

    def test_worker_secret_is_not_returned_and_revocation_clears_it(self):
        token = "worker-secret-" + "b" * 40
        response = self.client.post("/api/security/workers", json={
            "name": "local-worker",
            "base_url": "http://security-worker:8765",
            "token": token,
            "placement": "same_vps",
        })
        self.assertEqual(response.status_code, 201, response.text)
        worker = response.json()
        self.assertNotIn("token", worker)
        worker_id = worker["id"]
        listing = self.client.get("/api/security/workers")
        self.assertNotIn("token", str(listing.json()))
        revoked = self.client.post(f"/api/security/workers/{worker_id}/revoke")
        self.assertEqual(revoked.status_code, 200, revoked.text)
        stored = self.app.state.services.store.get_security_worker(worker_id)
        self.assertIsNone(stored["token"])
        self.assertFalse(stored["enabled"])

    def test_private_targets_need_admin_and_worker_cidr_approval(self):
        worker_response = self.client.post("/api/security/workers", json={
            "name": "private-worker",
            "base_url": "http://security-worker:8765",
            "token": "worker-secret-" + "c" * 40,
            "placement": "private_network",
            "allowed_networks": ["10.20.0.0/16"],
        })
        self.assertEqual(worker_response.status_code, 201, worker_response.text)
        worker_id = worker_response.json()["id"]
        target = {
            "value": "http://10.20.1.10",
            "environment": "staging",
            "ownership_confirmed": True,
            "profile": "basic",
            "worker_id": worker_id,
            "allowed_cidrs": ["10.20.1.0/24"],
        }
        with patch("dashboard.backend.services.security_lab.socket.getaddrinfo"):
            denied = self.analyst.post("/api/security/targets", json=target)
            self.assertEqual(denied.status_code, 400)
            approved = self.client.post("/api/security/targets", json=target)
        self.assertEqual(approved.status_code, 201, approved.text)
        target_data = approved.json()["target"]
        self.assertEqual(target_data["verify_status"], "verified")
        self.assertNotIn("verify_token", target_data)
        self.assertIsNone(approved.json()["verification_token"])


if __name__ == "__main__":
    unittest.main()
