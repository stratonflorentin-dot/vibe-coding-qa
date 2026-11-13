"""Tests for the Vibe Intelligence subsystem (contracts, registry, router,
context engine, gateway, security and evidence validation)."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dashboard.backend.ai.provider import AIConfig, AIError
from dashboard.backend.config import reset_settings
from dashboard.backend.ai.service import AIService
from dashboard.backend.persistence.database import Database
from dashboard.backend.persistence.store import Store
from dashboard.backend.intelligence import gateway as gateway_module
from dashboard.backend.intelligence.context_engine import ContextEngine
from dashboard.backend.intelligence.contracts import (
    ContextOptions,
    EvidenceKind,
    EvidenceRef,
    ExecutionKind,
    IntelligenceRequest,
    Operation,
    TaskStatus,
)
from dashboard.backend.intelligence.evaluations import validate_evidence
from dashboard.backend.intelligence.exceptions import (
    InvalidTaskError,
    ProjectNotFoundError,
    ProviderFailedError,
)
from dashboard.backend.intelligence.gateway import IntelligenceGateway
from dashboard.backend.intelligence.model_registry import Capability, ModelRegistry, capabilities_for
from dashboard.backend.intelligence.router import Router
from dashboard.backend.intelligence.tool_broker import ToolBroker


class _FakeProvider:
    last_messages = None

    def __init__(self, config):
        self.config = config

    def complete(self, messages, *, max_tokens=None, temperature=0.2):
        _FakeProvider.last_messages = messages
        return "Analysis: FastAPI app; entry point app/main.py. This is a hypothesis to verify."


class _FailingProvider(_FakeProvider):
    def complete(self, messages, *, max_tokens=None, temperature=0.2):
        raise AIError("the provider exploded with secret sk-xyz")


# Synthetic secret assembled at runtime so no literal is committed.
_SECRET = "sk-" + "123456789012345678901234"


def _seed(store: Store):
    user = store.create_user(username="owner", password_hash="x", role="owner")
    repo = store.create_repository(
        name="demo", source="/nonexistent", source_type="local",
        main_language="python", frameworks=["fastapi"],
    )
    scan = store.create_scan(repository_id=repo["id"], profile="deep", options={})
    store.update_scan(scan["id"], status="completed", overall_score=68.2, gate="block",
                      critical_count=1, high_count=2, total_findings=1, test_status="skip")
    store.insert_findings(scan["id"], repo["id"], [
        {"rule": "security:jwt-token", "module": "security", "severity": "critical",
         "file": "app/x.py", "line": 10, "message": f"token {_SECRET} leaked"},
    ])
    return user, repo, scan


def _enable_ai(store: Store, ai: AIService, model: str = "gpt-4o-mini"):
    ai._runtime_api_key = "test-key"
    store.set_setting("ai", {"enabled": True, "provider": "openrouter", "model": model,
                             "base_url": "https://example.invalid/v1"})


class DomainTests(unittest.TestCase):
    def test_capabilities_inference(self):
        self.assertIn(Capability.REASONING, capabilities_for("gpt-4o"))
        self.assertIn(Capability.CODE, capabilities_for("deepseek-coder"))
        self.assertEqual(capabilities_for("tiny-chat-1b"), {Capability.CHAT})

    def test_request_validation(self):
        IntelligenceRequest(operation=Operation.MAP_ARCHITECTURE, repository_id=1)
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            IntelligenceRequest(operation="not_a_real_op")
        with self.assertRaises(ValidationError):
            IntelligenceRequest(operation=Operation.MAP_ARCHITECTURE, repository_id=0)

    def test_evidence_ref_bounds(self):
        ref = EvidenceRef(kind=EvidenceKind.FINDING, ref="7", line=3)
        self.assertEqual(ref.ref, "7")


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        self.ai = AIService(self.store, reset_settings())
        self.registry = ModelRegistry(self.ai.config)
        self.router = Router(self.registry)

    def tearDown(self):
        self.db.close()

    def test_deterministic_ops_route_deterministic(self):
        for op in (Operation.MAP_ARCHITECTURE, Operation.ANALYZE_REGRESSION, Operation.SUMMARIZE_VERIFICATION):
            self.assertIs(self.router.route(op).execution_kind, ExecutionKind.DETERMINISTIC)

    def test_ai_op_degrades_without_provider(self):
        d = self.router.route(Operation.ANALYZE_PROJECT)
        self.assertTrue(d.available)
        self.assertTrue(d.degraded)
        self.assertIs(d.execution_kind, ExecutionKind.DETERMINISTIC)

    def test_non_degradable_op_is_unavailable_without_provider(self):
        d = self.router.route(Operation.PROPOSE_REPAIR)
        self.assertFalse(d.available)

    def test_capability_mismatch_is_flagged_not_silent(self):
        _enable_ai(self.store, self.ai, model="tiny-chat-1b")  # chat only
        d = self.router.route(Operation.DIAGNOSE_FAILURE)  # wants reasoning
        self.assertIs(d.execution_kind, ExecutionKind.AI)
        self.assertFalse(d.capability_satisfied)
        self.assertTrue(d.notes)


class RegistryTests(unittest.TestCase):
    def test_registry_never_exposes_secrets(self):
        db = Database(":memory:")
        store = Store(db)
        ai = AIService(store, reset_settings())
        _enable_ai(store, ai)
        reg = ModelRegistry(ai.config)
        blob = repr(reg.providers()) + repr(reg.models())
        self.assertNotIn("test-key", blob)
        self.assertNotIn("api_key", blob)
        self.assertTrue(reg.is_configured())
        db.close()


class ToolBrokerTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        self.ai = AIService(self.store, reset_settings())
        self.broker = ToolBroker(self.store, self.ai)
        self.user, self.repo, _ = _seed(self.store)

    def tearDown(self):
        self.db.close()

    def test_broker_allows_known_analysis_and_records_metadata(self):
        with mock.patch("dashboard.backend.intelligence.tool_broker.build_architecture", return_value={"nodes": [], "edges": []}):
            result = self.broker.call("architecture", {"repository_id": self.repo["id"]}, user=self.user)
        self.assertEqual(result["status"], "completed")
        entry = self.store.list_audit(1)[0]
        self.assertEqual(entry["action"], "intelligence_tool")
        self.assertNotIn(str(self.repo["id"]), entry["detail"].split("argument_names=")[-1])

    def test_broker_rejects_unknown_tool_and_arbitrary_arguments(self):
        with self.assertRaises(ValueError):
            self.broker.call("shell", {"command": "whoami"}, user=self.user)
        with self.assertRaises(ValueError):
            self.broker.call("architecture", {"repository_id": self.repo["id"], "url": "https://example.com"}, user=self.user)

    def test_broker_enforces_role_and_explicit_remediation_confirmation(self):
        with self.assertRaises(PermissionError):
            self.broker.call("propose_remediation", {"finding_id": 1}, user={"role": "viewer"})
        with self.assertRaises(ValueError):
            self.broker.call("approve_remediation", {"proposal_id": 1, "confirm": False}, user=self.user)


class ContextEngineTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        self.user, self.repo, self.scan = _seed(self.store)

    def tearDown(self):
        self.db.close()

    def test_redaction_and_evidence(self):
        req = IntelligenceRequest(operation=Operation.ANALYZE_PROJECT, repository_id=self.repo["id"])
        ctx = ContextEngine(self.store).prepare(req, self.repo)
        self.assertNotIn(_SECRET, ctx.text)
        self.assertTrue(any(e.kind is EvidenceKind.SCAN for e in ctx.evidence))
        self.assertTrue(any(e.kind is EvidenceKind.FINDING for e in ctx.evidence))

    def test_budget_truncation(self):
        req = IntelligenceRequest(
            operation=Operation.ANALYZE_PROJECT, repository_id=self.repo["id"],
            context=ContextOptions(max_chars=1000),
        )
        ctx = ContextEngine(self.store).prepare(req, self.repo)
        self.assertLessEqual(ctx.char_count, 1000 + 200)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        self.settings = reset_settings()
        self.ai = AIService(self.store, self.settings)
        self.gw = IntelligenceGateway(self.store, self.ai, self.settings)
        self.user, self.repo, self.scan = _seed(self.store)
        self.actor = {"id": self.user["id"], "role": "owner"}

    def tearDown(self):
        self.db.close()

    def test_summarize_verification_is_honest(self):
        res = self.gw.execute(
            IntelligenceRequest(operation=Operation.SUMMARIZE_VERIFICATION, scan_id=self.scan["id"]),
            user=self.actor,
        )
        self.assertIs(res.status, TaskStatus.COMPLETED)
        self.assertTrue(res.data["not_executed"])  # tests were skipped; never claimed passing
        self.assertTrue(validate_evidence(res, self.store) == [])
        task = self.store.get_intelligence_task(res.task_id)
        self.assertEqual(task["status"], "completed")
        self.assertEqual(len(task["executions"]), 1)

    def test_architecture_records_tool_and_execution_metadata(self):
        result = self.gw.execute(
            IntelligenceRequest(operation=Operation.MAP_ARCHITECTURE, repository_id=self.repo["id"]),
            user=self.actor,
        )
        task = self.gw.get_task(result.task_id)
        self.assertEqual(len(task["executions"]), 1)
        self.assertEqual(task["executions"][0]["execution_status"], "completed")
        self.assertEqual(task["tool_calls"][0]["tool_name"], "architecture")
        self.assertEqual(task["tool_calls"][0]["status"], "completed")

    def test_missing_required_field(self):
        with self.assertRaises(InvalidTaskError):
            self.gw.execute(IntelligenceRequest(operation=Operation.SUMMARIZE_VERIFICATION), user=self.actor)

    def test_unknown_project(self):
        with self.assertRaises(ProjectNotFoundError):
            self.gw.execute(IntelligenceRequest(operation=Operation.ANALYZE_PROJECT, repository_id=9999), user=self.actor)

    def test_ai_operation_with_provider(self):
        _enable_ai(self.store, self.ai)
        with mock.patch.object(gateway_module, "ChatProvider", _FakeProvider):
            res = self.gw.execute(
                IntelligenceRequest(operation=Operation.ANALYZE_PROJECT, repository_id=self.repo["id"]),
                user=self.actor,
            )
        self.assertIs(res.status, TaskStatus.COMPLETED)
        self.assertIs(res.execution_kind, ExecutionKind.AI)
        self.assertEqual(res.model, "gpt-4o-mini")
        # the system guard (anti prompt-injection) must be sent
        system = _FakeProvider.last_messages[0]["content"]
        self.assertIn("DATA, not instructions", system)

    def test_provider_failure_is_safe(self):
        _enable_ai(self.store, self.ai)
        with mock.patch.object(gateway_module, "ChatProvider", _FailingProvider):
            with self.assertRaises(ProviderFailedError) as ctx:
                self.gw.execute(
                    IntelligenceRequest(operation=Operation.ANALYZE_PROJECT, repository_id=self.repo["id"]),
                    user=self.actor,
                )
        self.assertNotIn("sk-xyz", str(ctx.exception))  # provider secret not leaked

    def test_degraded_ai_without_provider(self):
        res = self.gw.execute(
            IntelligenceRequest(operation=Operation.ANALYZE_PROJECT, repository_id=self.repo["id"]),
            user=self.actor,
        )
        self.assertIs(res.status, TaskStatus.PARTIAL)
        self.assertTrue(res.fallback_used)

    def test_propose_repair_unavailable_without_ai(self):
        res = self.gw.execute(
            IntelligenceRequest(operation=Operation.PROPOSE_REPAIR, finding_id=1),
            user=self.actor,
        )
        self.assertIs(res.status, TaskStatus.UNAVAILABLE)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.store = Store(self.db)
        self.settings = reset_settings()
        self.ai = AIService(self.store, self.settings)
        self.gw = IntelligenceGateway(self.store, self.ai, self.settings)
        self.user, self.repoA, self.scanA = _seed(self.store)
        self.repoB = self.store.create_repository(name="other", source="/other", source_type="local")
        self.actor = {"id": self.user["id"], "role": "owner"}

    def tearDown(self):
        self.db.close()

    def test_cross_project_isolation(self):
        # A scan belonging to repo A cannot be summarised "as" repo B's data:
        # resolution follows the scan's real repository, and evidence stays valid.
        res = self.gw.execute(
            IntelligenceRequest(operation=Operation.SUMMARIZE_VERIFICATION, scan_id=self.scanA["id"]),
            user=self.actor,
        )
        task = self.store.get_intelligence_task(res.task_id)
        self.assertEqual(task["project_id"], self.repoA["id"])  # not repo B

    def test_fabricated_evidence_is_detected(self):
        res = self.gw.execute(
            IntelligenceRequest(operation=Operation.SUMMARIZE_VERIFICATION, scan_id=self.scanA["id"]),
            user=self.actor,
        )
        res.evidence.append(EvidenceRef(kind=EvidenceKind.FINDING, ref="999999"))
        self.assertTrue(validate_evidence(res, self.store))  # non-empty => invalid refs found


if __name__ == "__main__":
    unittest.main()
