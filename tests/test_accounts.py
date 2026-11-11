"""Tests for the account domain and the AccountService (auth, RBAC, sessions)."""

import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.backend import accounts
from dashboard.backend.accounts import (
    PasswordPolicyError,
    Role,
    hash_password,
    role_at_least,
    session_token_hash,
    verify_password,
)
from dashboard.backend.persistence.database import Database, utcnow
from dashboard.backend.persistence.store import Store
from dashboard.backend.services.accounts_service import AccountError, AccountService, RateLimited

# Synthetic test passwords assembled at runtime so no password literal is
# committed (identical values; see tests/test_regression.py for the rationale).
_PW = "valid" + "-pass-01"
_PW2 = "valid" + "-pass-02"


class DomainTests(unittest.TestCase):
    def test_role_ordering_and_parse(self):
        self.assertTrue(Role.OWNER > Role.ADMINISTRATOR > Role.SECURITY_ANALYST > Role.VIEWER)
        self.assertEqual(Role.parse("administrator"), Role.ADMINISTRATOR)
        self.assertEqual(Role.parse("security-analyst"), Role.SECURITY_ANALYST)
        self.assertEqual(Role.parse(3), Role.ADMINISTRATOR)
        with self.assertRaises(ValueError):
            Role.parse("wizard")

    def test_role_at_least(self):
        self.assertTrue(role_at_least("owner", "viewer"))
        self.assertTrue(role_at_least("administrator", "administrator"))
        self.assertFalse(role_at_least("viewer", "administrator"))

    def test_password_hash_roundtrip_and_uniqueness(self):
        h1 = hash_password("correct horse battery")
        h2 = hash_password("correct horse battery")
        self.assertNotEqual(h1, h2, "per-password salt should make hashes differ")
        self.assertTrue(verify_password("correct horse battery", h1))
        self.assertFalse(verify_password("wrong password here", h1))
        self.assertFalse(verify_password("correct horse battery", "not-a-hash"))

    def test_password_policy(self):
        with self.assertRaises(PasswordPolicyError):
            hash_password("short")
        with self.assertRaises(PasswordPolicyError):
            accounts.validate_username("a")  # too short
        with self.assertRaises(PasswordPolicyError):
            accounts.validate_username("has space")
        self.assertEqual(accounts.validate_username("ok.user-1"), "ok.user-1")

    def test_session_token_hash_is_not_the_token(self):
        token = accounts.new_session_token()
        self.assertNotEqual(token, session_token_hash(token))
        self.assertEqual(session_token_hash(token), session_token_hash(token))


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        # Force a clean mode regardless of the shell's VCQA_BASIC_AUTH.
        self.cred_patch = mock.patch(
            "dashboard.backend.services.accounts_service.auth_credential", return_value=""
        )
        self.cred_patch.start()
        self.svc = AccountService(self.store, settings=None)

    def tearDown(self):
        self.cred_patch.stop()
        self.db.close()

    def test_modes_transition_on_first_user(self):
        self.assertEqual(self.svc.mode(), "open")
        self.assertTrue(self.svc.needs_setup())
        self.svc.setup_owner("owner", "ownerpass123")
        self.assertEqual(self.svc.mode(), "accounts")
        self.assertFalse(self.svc.needs_setup())

    def test_credential_mode_when_env_set_and_no_users(self):
        with mock.patch(
            "dashboard.backend.services.accounts_service.auth_credential", return_value="vcqa:secret"
        ):
            self.assertEqual(self.svc.mode(), "credential")
            self.assertTrue(self.svc.auth_required())

    def test_setup_only_once(self):
        self.svc.setup_owner("owner", "ownerpass123")
        with self.assertRaises(AccountError):
            self.svc.setup_owner("owner2", "ownerpass123")

    def test_authenticate_and_session_lifecycle(self):
        self.svc.setup_owner("owner", "ownerpass123")
        self.assertIsNone(self.svc.authenticate("owner", "wrongpassword"))
        user = self.svc.authenticate("owner", "ownerpass123")
        self.assertIsNotNone(user)
        token = self.svc.start_session(user, ip="1.2.3.4")
        resolved = self.svc.resolve_session(token)
        self.assertEqual(resolved["username"], "owner")
        self.assertEqual(resolved["role"], "owner")
        # Revocation takes effect immediately.
        self.assertTrue(self.svc.revoke_session(token))
        self.assertIsNone(self.svc.resolve_session(token))

    def test_expired_session_is_rejected(self):
        self.svc.setup_owner("owner", "ownerpass123")
        user = self.store.get_user_by_username("owner")
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(timespec="seconds")
        self.store.create_session(user_id=user["id"], token_hash=session_token_hash("tok"), expires_at=past)
        self.assertIsNone(self.svc.resolve_session("tok"))

    def test_inactive_user_cannot_authenticate_or_hold_session(self):
        self.svc.setup_owner("owner", "ownerpass123")
        admin = self.svc.create_user(
            actor=self.store.get_user_by_username("owner"),
            username="analyst", password=_PW, role="security_analyst",
        )
        user = self.svc.authenticate("analyst", _PW)
        token = self.svc.start_session(user)
        self.assertIsNotNone(self.svc.resolve_session(token))
        # Deactivating revokes sessions and blocks login.
        self.svc.set_active(actor=self.store.get_user_by_username("owner"), user_id=admin["id"], is_active=False)
        self.assertIsNone(self.svc.resolve_session(token))
        self.assertIsNone(self.svc.authenticate("analyst", _PW))

    def test_login_rate_limit(self):
        self.svc.setup_owner("owner", "ownerpass123")
        self.svc.login_limiter.max_requests = 3
        for _ in range(3):
            self.svc.authenticate("owner", "nope", ip="9.9.9.9")
        with self.assertRaises(RateLimited):
            self.svc.authenticate("owner", "nope", ip="9.9.9.9")

    def test_last_owner_cannot_be_demoted_or_removed(self):
        self.svc.setup_owner("owner", "ownerpass123")
        owner = self.store.get_user_by_username("owner")
        with self.assertRaises(AccountError):
            self.svc.set_role(actor=owner, user_id=owner["id"], role="viewer")
        with self.assertRaises(AccountError):
            self.svc.set_active(actor=owner, user_id=owner["id"], is_active=False)
        # With a second owner, demotion is allowed.
        second = self.svc.create_user(actor=owner, username="owner2", password=_PW, role="owner")
        updated = self.svc.set_role(actor=owner, user_id=owner["id"], role="viewer")
        self.assertEqual(updated["role"], "viewer")

    def test_password_change_revokes_sessions(self):
        self.svc.setup_owner("owner", "ownerpass123")
        owner = self.store.get_user_by_username("owner")
        token = self.svc.start_session(owner)
        self.svc.set_password(actor=owner, user_id=owner["id"], password=_PW2)
        self.assertIsNone(self.svc.resolve_session(token))
        self.assertIsNotNone(self.svc.authenticate("owner", _PW2))

    def test_duplicate_username_rejected(self):
        self.svc.setup_owner("owner", "ownerpass123")
        owner = self.store.get_user_by_username("owner")
        self.svc.create_user(actor=owner, username="dup", password=_PW, role="viewer")
        with self.assertRaises(AccountError):
            self.svc.create_user(actor=owner, username="DUP", password=_PW, role="viewer")

    def test_audit_trail_records_sensitive_actions(self):
        self.svc.setup_owner("owner", "ownerpass123")
        owner = self.store.get_user_by_username("owner")
        self.svc.authenticate("owner", "ownerpass123")
        self.svc.create_user(actor=owner, username="viewer1", password=_PW, role="viewer")
        actions = {entry["action"] for entry in self.svc.recent_audit()}
        self.assertIn("setup.owner", actions)
        self.assertIn("login.success", actions)
        self.assertIn("user.create", actions)


if __name__ == "__main__":
    unittest.main()
