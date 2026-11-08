"""Docker integration tests for the isolated test-execution sandbox.

Unlike the unit tests (which mock the Docker CLI), these tests start real
containers with the production ``run_tests`` code path and assert the isolation
guarantees end to end: the container starts, the network is disabled, the source
snapshot is mounted read-only, the workspace is writable, resource limits and
timeouts apply, developer environment variables do not leak, secrets are
redacted, and the test-status classification never reports a pass without
evidence.

They are skipped by default so the normal unit-test run needs no Docker. The CI
``docker-integration`` job sets ``VCQA_DOCKER_INTEGRATION=1`` and fails if a
Docker daemon is expected but not reachable. The required image is pulled by CI
explicitly; the engine itself never pulls images or installs dependencies.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibe_coding_qa.engine import run_tests


INTEGRATION_ENABLED = os.environ.get("VCQA_DOCKER_INTEGRATION") == "1"
TEST_IMAGE = os.environ.get("VCQA_INTEGRATION_IMAGE", "python:3.12-slim")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


if INTEGRATION_ENABLED and not _docker_available():  # pragma: no cover
    raise RuntimeError(
        "VCQA_DOCKER_INTEGRATION=1 was set but no Docker daemon is reachable. "
        "The integration job must fail when Docker is expected but unavailable."
    )


@unittest.skipUnless(INTEGRATION_ENABLED, "set VCQA_DOCKER_INTEGRATION=1 to run Docker integration tests")
class DockerSandboxIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="vcqa-it-"))
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

    def _run(self, command, **kwargs):
        return run_tests(
            self.repo,
            command=command,
            test_image=TEST_IMAGE,
            explicit_permission=True,
            **kwargs,
        )

    def _write(self, name, content):
        (self.repo / name).write_text(content, encoding="utf-8")

    def test_container_starts_and_passing_suite_is_verified(self):
        self._write(
            "test_ok.py",
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    def test_ok(self):\n        self.assertTrue(True)\n",
        )
        result = self._run("python -m unittest discover -s . -v")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["execution_mode"], "docker_isolated")
        limits = result["resource_limits"]
        self.assertTrue(limits["enforced"])
        self.assertEqual(limits["source_mount"], "read-only")
        self.assertEqual(limits["workspace"], "tmpfs-read-write")

    def test_failing_suite_fails(self):
        self._write(
            "test_bad.py",
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    def test_bad(self):\n        self.assertEqual(1, 2)\n",
        )
        result = self._run("python -m unittest discover -s . -v")
        self.assertEqual(result["status"], "fail")

    def test_all_tests_skipped_is_not_verified(self):
        self._write(
            "test_skip.py",
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    @unittest.skip('later')\n    def test_a(self):\n        self.assertTrue(True)\n"
            "    @unittest.skip('later')\n    def test_b(self):\n        self.assertTrue(True)\n",
        )
        result = self._run("python -m unittest discover -s . -v")
        self.assertEqual(result["status"], "skip")
        self.assertNotEqual(result["status"], "pass")

    def test_missing_dependency_is_not_a_pass(self):
        self._write(
            "test_ok.py",
            "import unittest\n\n\nclass T(unittest.TestCase):\n"
            "    def test_ok(self):\n        self.assertTrue(True)\n",
        )
        # The default image does not include pytest; a missing dependency is not a pass.
        result = self._run("python -m pytest")
        self.assertNotEqual(result["status"], "pass")

    def test_network_is_disabled(self):
        self._write(
            "netcheck.py",
            "import socket, sys\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
            "except OSError:\n"
            "    sys.exit(7)\n"
            "sys.exit(0)\n",
        )
        result = self._run("python netcheck.py")
        self.assertEqual(result["returncode"], 7)

    def test_source_mount_is_read_only(self):
        self._write(
            "try_write.py",
            "import sys\n"
            "try:\n"
            "    with open('/vcqa-src/should_not_exist.txt', 'w') as handle:\n"
            "        handle.write('x')\n"
            "except OSError:\n"
            "    sys.exit(9)\n"
            "sys.exit(0)\n",
        )
        result = self._run("python try_write.py")
        self.assertEqual(result["returncode"], 9)
        self.assertFalse((self.repo / "should_not_exist.txt").exists())

    def test_workspace_is_writable(self):
        self._write(
            "write_ws.py",
            "with open('/workspace/proof.txt', 'w') as handle:\n"
            "    handle.write('workspace-ok')\n"
            "print('PROOF', open('/workspace/proof.txt').read())\n",
        )
        result = self._run("python write_ws.py")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("workspace-ok", result["stdout"])

    def test_developer_environment_is_not_inherited(self):
        self._write(
            "envcheck.py",
            "import os\nprint('LEAK=' + os.environ.get('VCQA_SECRET_LEAK_TEST', 'NONE'))\n",
        )
        os.environ["VCQA_SECRET_LEAK_TEST"] = "topsecret-value"
        self.addCleanup(os.environ.pop, "VCQA_SECRET_LEAK_TEST", None)
        result = self._run("python envcheck.py")
        self.assertIn("LEAK=NONE", result["stdout"])
        self.assertNotIn("topsecret-value", result["stdout"] + result["summary"])

    def test_secrets_are_redacted(self):
        secret = "sk-" + "a" * 40
        self._write("leak.txt", 'OPENAI_API_KEY = "%s"\n' % secret)
        self._write("dump.py", "print(open('leak.txt').read())\n")
        result = self._run("python dump.py")
        combined = (result.get("stdout") or "") + (result.get("summary") or "") + (result.get("stderr") or "")
        self.assertNotIn(secret, combined)
        self.assertNotEqual(result["status"], "pass")

    def test_timeout_is_a_failure(self):
        self._write("slow.py", "import time\ntime.sleep(60)\n")
        result = self._run("python slow.py", timeout=5)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["execution_mode"], "timeout")


if __name__ == "__main__":
    unittest.main()
