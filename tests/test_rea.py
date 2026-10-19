"""Transport contract tests; no REA install, network or target execution needed."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea.rea import ReaError, ReaSession


class FakeProcess:
    def __init__(self):
        self.stdin = io.StringIO()

    def poll(self):
        return None


class ReaTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with patch("antirea.rea.load_environment", return_value=({}, {})):
            self.session = ReaSession(self.temp.name, Path(self.temp.name) / "logs", timeout_s=0.01)
        self.session.process = FakeProcess()

    def test_preserves_evidence_payload(self):
        evidence = {"normalized_result": [], "limitations": ["incomplete"], "confidence": "observed"}
        self.assertIs(ReaSession.result_payload({"structuredContent": evidence}), evidence)

    def test_falls_back_to_text_json(self):
        result = {"content": [{"type": "text", "text": '{"result": [1, 2]}'}]}
        self.assertEqual(ReaSession.result_payload(result), {"result": [1, 2]})

    def test_tool_errors_remain_visible(self):
        result = {"isError": True, "content": [{"type": "text", "text": "unavailable"}]}
        self.session._queue.put({"jsonrpc": "2.0", "id": 1, "result": result})
        self.assertEqual(self.session.call("list_procedures"), result)
        log = json.loads((self.session.log_dir / "0001-list_procedures.json").read_text())
        self.assertTrue(log["response"]["result"]["isError"])
        self.assertGreaterEqual(log["elapsed_s"], 0)

    def test_protocol_errors_are_logged_and_raise(self):
        self.session._queue.put({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "missing"}})
        with self.assertRaises(ReaError):
            self.session.call("absent")
        log = json.loads((self.session.log_dir / "0001-absent.json").read_text())
        self.assertEqual(log["response"]["error"]["code"], -32601)

    def test_timeout_sends_cancellation_and_records_incompleteness(self):
        with self.assertRaisesRegex(ReaError, "incomplete"):
            self.session.call("list_procedures")
        messages = [json.loads(line) for line in self.session.process.stdin.getvalue().splitlines()]
        self.assertEqual(messages[-1]["method"], "notifications/cancelled")
        self.assertEqual(messages[-1]["params"]["requestId"], 1)
        log = json.loads((self.session.log_dir / "0001-list_procedures.json").read_text())
        self.assertTrue(log["timeout"])

    def test_notifications_do_not_replace_requested_response(self):
        self.session._queue.put({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
        self.session._queue.put({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        self.assertEqual(self.session.request("tools/list", {}), {"tools": []})
        log = json.loads((self.session.log_dir / "0001-tools_list.json").read_text())
        self.assertEqual(len(log["notifications"]), 1)

    def test_open_binary_uses_explicit_absolute_target_and_ghidra(self):
        with patch.object(self.session, "call", return_value={"structuredContent": {"result": {}}}) as call:
            self.session.open_binary(Path(self.temp.name) / "fixture.exe")
        name, args = call.call_args.args
        self.assertEqual(name, "open_binary")
        self.assertEqual(args["provider_id"], "ghidra")
        self.assertTrue(Path(args["path"]).is_absolute())

    def test_log_name_cannot_escape_directory(self):
        self.session._queue.put({"jsonrpc": "2.0", "id": 1, "result": {}})
        self.session.call("..\\..\\elsewhere")
        self.assertEqual(len(list(self.session.log_dir.glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
