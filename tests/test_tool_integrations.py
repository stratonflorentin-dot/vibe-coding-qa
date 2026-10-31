import contextlib
import http.server
import importlib.util
import io
import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / ".claude" / "skills" / "vibe-coding-qa" / "scripts" / "vibe_coding_qa.py"
SPEC = importlib.util.spec_from_file_location("vibe_coding_qa", SCRIPT)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


class PentagiHandler(http.server.BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        type(self).requests.append((self.command, self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"flows":[]}')

    def log_message(self, _format, *_args):
        return


class ToolIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PentagiHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_pentagi_url_uses_documented_read_only_route(self):
        endpoint = qa.validate_pentagi_url("https://pentagi.example/prefix/")
        self.assertEqual(endpoint, "https://pentagi.example/prefix/api/v1/flows")

    def test_pentagi_rejects_remote_http_and_embedded_credentials(self):
        with self.assertRaises(qa.ToolError):
            qa.validate_pentagi_url("http://pentagi.example")
        with self.assertRaises(qa.ToolError):
            qa.validate_pentagi_url("https://user:pass@pentagi.example")

    def test_pentagi_probe_sends_only_authenticated_get_and_hides_body(self):
        PentagiHandler.requests.clear()
        port = self.server.server_address[1]
        args = SimpleNamespace(base_url=f"http://127.0.0.1:{port}", probe=True, timeout=3)
        output = io.StringIO()
        with patch.dict("os.environ", {"PENTAGI_API_TOKEN": "secret-test-token"}), contextlib.redirect_stdout(output):
            result = qa.command_pentagi(args)
        self.assertEqual(result, 0)
        self.assertEqual(PentagiHandler.requests, [("GET", "/api/v1/flows", "Bearer secret-test-token")])
        self.assertNotIn("secret-test-token", output.getvalue())
        self.assertNotIn('{"flows"', output.getvalue())

    def test_api_anything_read_requires_explicit_read_only_schema(self):
        args = qa.build_parser().parse_args(["tools", "api-anything", "call", "demo", "lookup", "--arg", "id=7", "--execute-read"])
        completed = SimpleNamespace(stdout='{"op":"lookup","readOnly":true}', stderr="", returncode=0)
        calls = []

        def run(argv, timeout):
            calls.append((argv, timeout))
            if "--schema" in argv:
                return completed
            return SimpleNamespace(stdout='{"ok":true}', stderr="", returncode=0)

        with patch.object(qa, "api_executable", return_value=["api-anything"]), patch.object(qa, "run_capture", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            result = qa.command_api_anything(args)
        self.assertEqual(result, 0)
        self.assertEqual(calls[0][0], ["api-anything", "ops", "demo", "lookup", "--schema"])
        self.assertEqual(calls[1][0], ["api-anything", "call", "demo", "lookup", "id=7", "--max-tier", "1"])

    def test_api_anything_refuses_unknown_read_contract(self):
        args = qa.build_parser().parse_args(["tools", "api-anything", "call", "demo", "lookup", "--execute-read"])
        completed = SimpleNamespace(stdout='{"op":"lookup"}', stderr="", returncode=0)
        with patch.object(qa, "api_executable", return_value=["api-anything"]), patch.object(qa, "run_capture", return_value=completed):
            with self.assertRaises(qa.ToolError):
                qa.command_api_anything(args)

    def test_api_anything_write_requires_write_schema_and_exact_confirmation(self):
        args = qa.build_parser().parse_args(["tools", "api-anything", "call", "demo", "update", "--arg", "name=sample", "--execute-write", "--confirm-write", "demo.update"])
        completed = SimpleNamespace(stdout='{"op":"update","readOnly":false}', stderr="", returncode=0)
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            if "--schema" in argv:
                return completed
            return SimpleNamespace(stdout='{"ok":true}', stderr="", returncode=0)

        with patch.object(qa, "api_executable", return_value=["api-anything"]), patch.object(qa, "run_capture", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            result = qa.command_api_anything(args)
        self.assertEqual(result, 0)
        self.assertEqual(calls[1][-1], "--allow-writes")

    def test_api_anything_dry_run_does_not_fetch_operation_or_execute(self):
        args = qa.build_parser().parse_args(["tools", "api-anything", "call", "demo", "update", "--arg", "name=sample", "--dry-run"])
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            return SimpleNamespace(stdout='{"ok":true}', stderr="", returncode=0)

        with patch.object(qa, "api_executable", return_value=["api-anything"]), patch.object(qa, "run_capture", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            result = qa.command_api_anything(args)
        self.assertEqual(result, 0)
        self.assertEqual(calls, [["api-anything", "call", "demo", "update", "name=sample", "--dry", "--allow-writes"]])

    def test_secret_redaction_handles_upstream_json_fields(self):
        value = qa.redact_value({"apiKey": "secret", "result": "Authorization: Bearer token-value"})
        self.assertEqual(value["apiKey"], "[REDACTED]")
        self.assertNotIn("token-value", value["result"])

    def test_fallow_fix_preview_is_non_mutating_and_machine_readable(self):
        args = qa.build_parser().parse_args(["tools", "fallow", "--action", "fix-preview", "--root", str(Path.cwd())])
        captured = []
        result = SimpleNamespace(stdout='{"changes":[]}', stderr="", returncode=0)
        with patch.object(qa, "ensure_executable", return_value="fallow"), patch.object(qa, "run_capture", return_value=result) as run, contextlib.redirect_stdout(io.StringIO()):
            status = qa.command_fallow(args)
        captured.extend(run.call_args.args[0])
        self.assertEqual(status, 0)
        self.assertIn("--dry-run", captured)
        self.assertIn("--format", captured)


if __name__ == "__main__":
    unittest.main()
