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
ANALYST_PW = "analystpass0123"
ADMIN_PW = "adminpass1234"

#: Mutating routes only an administrator (or owner) may call.
ADMIN_ONLY_ROUTES = [
    ("POST", "/api/repositories", {}),
    ("DELETE", "/api/repositories/1", None),
    ("DELETE", "/api/scans/1", None),
    ("PUT", "/api/settings/scan", {}),
    ("PUT", "/api/settings/ai", {}),
    ("POST", "/api/ai/remediations/1/approve", {"confirm": True}),
    ("POST", "/api/ai/remediations/1/rollback", None),
]

#: Mutating routes a security analyst (and above) may call.
ANALYST_ROUTES = [
    ("POST", "/api/scans", {}),
    ("POST", "/api/scans/1/cancel", None),
    ("PATCH", "/api/findings/1", {"status": "open"}),
    ("POST", "/api/repositories/1/refresh", None),
    ("POST", "/api/settings/ai/test", None),
    ("POST", "/api/ai/chat", {"message": "hello"}),
    ("POST", "/api/ai/summary", {}),
    ("POST", "/api/ai/threat-model", {"repository_id": 1}),
    ("POST", "/api/ai/findings/1/review", {"kind": "analyst"}),
    ("POST", "/api/ai/findings/1/test", {}),
    ("POST", "/api/ai/remediations", {"finding_id": 1}),
    ("DELETE", "/api/ai/conversations/1", None),
]


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

    def _create_user(self, username: str, password: str, role: str) -> None:
        response = self.client.post(
            "/api/auth/users", json={"username": username, "password": password, "role": role}
        )
        self.assertEqual(response.status_code, 201, response.text)

    def _login(self, username: str, password: str) -> "TestClient":
        client = self._anon()
        response = client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["authenticated"])
        return client

    @staticmethod
    def _call(client: "TestClient", method: str, path: str, body):
        return client.request(method, path) if body is None else client.request(method, path, json=body)

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

    def test_rbac_viewer_is_read_only(self):
        self._setup_owner()
        self._create_user("viewer2", VIEWER_PW, "viewer")
        viewer = self._login("viewer2", VIEWER_PW)
        # Reads are fine; every mutation is refused at the role gate.
        self.assertEqual(viewer.get("/api/repositories").status_code, 200)
        for method, path, body in ADMIN_ONLY_ROUTES + ANALYST_ROUTES:
            with self.subTest(method=method, path=path):
                response = self._call(viewer, method, path, body)
                self.assertEqual(response.status_code, 403, f"{method} {path} -> {response.status_code}")

    def test_rbac_analyst_can_scan_but_not_administer(self):
        self._setup_owner()
        self._create_user("analyst1", ANALYST_PW, "security_analyst")
        analyst = self._login("analyst1", ANALYST_PW)
        # Reaching the handler (any non-403) proves the analyst gate let it through.
        for method, path, body in ANALYST_ROUTES:
            with self.subTest(method=method, path=path):
                response = self._call(analyst, method, path, body)
                self.assertNotEqual(response.status_code, 403, f"{method} {path} was blocked")
        for method, path, body in ADMIN_ONLY_ROUTES:
            with self.subTest(method=method, path=path):
                response = self._call(analyst, method, path, body)
                self.assertEqual(response.status_code, 403, f"{method} {path} -> {response.status_code}")

    def test_rbac_admin_can_administer(self):
        self._setup_owner()
        self._create_user("admin1", ADMIN_PW, "administrator")
        admin = self._login("admin1", ADMIN_PW)
        for method, path, body in ADMIN_ONLY_ROUTES:
            with self.subTest(method=method, path=path):
                response = self._call(admin, method, path, body)
                self.assertNotEqual(response.status_code, 403, f"{method} {path} was blocked")

    def test_csrf_rejects_cross_site_mutation(self):
        self._setup_owner()
        payload = {"message": "hello"}
        blocked = self.client.post("/api/ai/chat", json=payload, headers={"Origin": "https://evil.example"})
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json().get("code"), "csrf_rejected")
        referer = self.client.post("/api/ai/chat", json=payload, headers={"Referer": "https://evil.example/page"})
        self.assertEqual(referer.status_code, 403)
        # An opaque origin ("null") is never trusted.
        self.assertEqual(
            self.client.post("/api/ai/chat", json=payload, headers={"Origin": "null"}).status_code, 403
        )

    def test_csrf_allows_same_origin_and_non_browser_clients(self):
        self._setup_owner()
        payload = {"message": "hello"}
        # The dashboard's own origin (TestClient host) is same-origin.
        same = self.client.post("/api/ai/chat", json=payload, headers={"Origin": "http://testserver"})
        self.assertNotEqual(same.status_code, 403)
        # A configured dev origin is accepted too.
        dev = self.client.post("/api/ai/chat", json=payload, headers={"Origin": "http://localhost:5173"})
        self.assertNotEqual(dev.status_code, 403)
        # No Origin/Referer: a CLI/curl caller holds no ambient cookie to abuse.
        self.assertNotEqual(self.client.post("/api/ai/chat", json=payload).status_code, 403)
        # Reads are never affected by the guard.
        self.assertEqual(
            self.client.get("/api/repositories", headers={"Origin": "https://evil.example"}).status_code, 200
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
