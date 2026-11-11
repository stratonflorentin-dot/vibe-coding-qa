"""End-to-end auth API tests: setup, login/logout, middleware gating, RBAC."""

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

OWNER_PW = "ownerpass123"
VIEWER_PW = "viewerpass123"


@unittest.skipUnless(WEB_STACK, "FastAPI/httpx are not installed")
class AuthApiTests(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VCQA_DASHBOARD_DB"] = str(Path(self._tmp.name) / "vcqa.sqlite3")
        os.environ.pop("VCQA_BASIC_AUTH", None)  # start in open mode
        os.environ.pop("VCQA_AI_API_KEY", None)
        self.app = create_app(reset_settings())
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        os.environ.clear()
        os.environ.update(self._env)
        reset_settings()
        self._tmp.cleanup()

    def _anon(self) -> "TestClient":
        client = TestClient(self.app)
        client.__enter__()
        self.addCleanup(lambda: client.__exit__(None, None, None))
        return client

    def _setup_owner(self):
        return self.client.post("/api/auth/setup", json={"username": "owner", "password": OWNER_PW})

    def test_open_mode_then_setup_switches_to_accounts(self):
        status = self.client.get("/api/auth/status").json()
        self.assertEqual(status["mode"], "open")
        self.assertTrue(status["needs_setup"])
        # Gated data API is open on a localhost install with no users.
        self.assertEqual(self.client.get("/api/repositories").status_code, 200)

        setup = self._setup_owner()
        self.assertEqual(setup.status_code, 200, setup.text)
        body = setup.json()
        self.assertEqual(body["mode"], "accounts")
        self.assertEqual(body["user"]["role"], "owner")

        # The setup client holds a session cookie, so it still reaches the API.
        self.assertEqual(self.client.get("/api/repositories").status_code, 200)
        # A fresh client without a session is now blocked (401, no popup header).
        anon = self._anon()
        blocked = anon.get("/api/repositories")
        self.assertEqual(blocked.status_code, 401)
        self.assertNotIn("www-authenticate", {k.lower() for k in blocked.headers})
        self.assertFalse(anon.get("/api/auth/status").json()["authenticated"])

    def test_login_logout_lifecycle(self):
        self._setup_owner()
        anon = self._anon()
        self.assertEqual(
            anon.post("/api/auth/login", json={"username": "owner", "password": "wrongpassword"}).status_code,
            401,
        )
        ok = anon.post("/api/auth/login", json={"username": "owner", "password": OWNER_PW})
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["authenticated"])
        self.assertEqual(anon.get("/api/repositories").status_code, 200)
        anon.post("/api/auth/logout")
        self.assertEqual(anon.get("/api/repositories").status_code, 401)

    def test_rbac_viewer_cannot_manage_users(self):
        self._setup_owner()
        created = self.client.post(
            "/api/auth/users", json={"username": "viewer1", "password": VIEWER_PW, "role": "viewer"}
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(self.client.get("/api/auth/users").status_code, 200)

        viewer = self._anon()
        viewer.post("/api/auth/login", json={"username": "viewer1", "password": VIEWER_PW})
        # The viewer is authenticated for data, but not for user administration.
        self.assertEqual(viewer.get("/api/repositories").status_code, 200)
        self.assertEqual(viewer.get("/api/auth/users").status_code, 403)
        self.assertEqual(
            viewer.post("/api/auth/users", json={"username": "x", "password": "xpassword123", "role": "viewer"}).status_code,
            403,
        )

    def test_setup_is_blocked_after_completion(self):
        self._setup_owner()
        again = self._anon().post("/api/auth/setup", json={"username": "evil", "password": "evilpass1234"})
        self.assertEqual(again.status_code, 409)

    def test_weak_password_rejected_at_setup(self):
        weak = self.client.post("/api/auth/setup", json={"username": "owner", "password": "short"})
        self.assertEqual(weak.status_code, 400)


if __name__ == "__main__":
    unittest.main()
