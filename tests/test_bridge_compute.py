"""Evidence paging and bounded computation; no model or analysis engine runs."""

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from antirea.attack import TOOL_NAMES
from antirea.bridge import Bridge, ENGINE_SOURCES, MAX_CACHE_CHARS, PAGE_CHARS, TOOLS
from antirea.judge import scratch_compute
from antirea.process import run_logged


class PagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-paging-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bridge = Bridge({"root": str(self.root), "binary": str(self.root / "unused.exe"),
                              "log_dir": str(self.root), "query_limit": 256,
                              "deadline_epoch": time.time() + 60})

    def response(self, name, args):
        result = self.bridge.call(name, args)
        return result, json.loads(result["content"][0]["text"])

    def test_large_response_is_fully_retrievable_and_audited(self):
        original = {"result": "abc" * 30_000, "limitations": ["test evidence"]}
        self.bridge.rea = Mock(return_value=original)
        response, first = self.response("decompile", {"procedure": "test"})
        self.assertFalse(response["isError"])
        self.assertFalse(first["page"]["evidence_complete"])
        chunks = [first["text"]]
        current = first
        while current["page"]["next_offset"] is not None:
            response, current = self.response("fetch_page", {
                "token": first["page"]["token"], "offset": current["page"]["next_offset"]})
            self.assertFalse(response["isError"])
            chunks.append(current["text"])
        self.assertEqual(json.loads("".join(chunks)), original)
        self.assertTrue(current["page"]["evidence_complete"])
        audit = [json.loads(line) for line in (self.root / "bridge-audit.jsonl").read_text().splitlines()]
        self.assertTrue(audit[0]["paginated"])
        self.assertFalse(audit[0]["evidence_complete"])
        self.assertTrue(audit[-1]["evidence_complete"])
        self.assertIn("seconds_remaining", audit[-1])

    def test_reading_last_page_does_not_hide_gaps(self):
        self.bridge.rea = Mock(return_value={"result": "x" * 100_000})
        _, first = self.response("decompile", {"procedure": "test"})
        _, last = self.response("fetch_page", {"token": first["page"]["token"],
                                               "offset": first["page"]["total_chars"] - PAGE_CHARS})
        self.assertIsNone(last["page"]["next_offset"])
        self.assertFalse(last["page"]["evidence_complete"])
        self.assertGreater(last["page"]["undelivered_chars"], 0)

    def test_invalid_token_and_cache_capacity_are_explicit_errors(self):
        response, _ = self.response("fetch_page", {"token": "../../private.json", "offset": 0})
        self.assertTrue(response["isError"])
        self.bridge.rea = Mock(return_value={"result": "x" * 80_000})
        self.bridge.cached_chars = MAX_CACHE_CHARS
        response, data = self.response("decompile", {"procedure": "test"})
        self.assertTrue(response["isError"])
        self.assertIn("capacity", data["error"])

    def test_compute_does_not_query_binary_and_failures_are_visible(self):
        with patch("antirea.judge.scratch_compute", return_value={"status": "passed", "outputs": [3]}):
            response, data = self.response("compute", {"code": "def solve(x,y): return x+y", "pairs": [[1, 2]]})
        self.assertFalse(response["isError"])
        self.assertEqual(data["outputs"], [3])
        self.assertEqual(self.bridge.queried, 0)
        with patch("antirea.judge.scratch_compute", return_value={"status": "timeout"}):
            response, _ = self.response("compute", {"code": "test", "pairs": [[1, 2]]})
        self.assertTrue(response["isError"])

    def test_all_tools_are_explicitly_allowed_by_attacker(self):
        self.assertEqual(set(TOOL_NAMES), {tool["name"] for tool in TOOLS})

    def test_engine_source_allowlist_has_no_target_source(self):
        self.assertTrue({"fla", "sub", "co", "selection"}.issubset(ENGINE_SOURCES))
        self.assertTrue(all(".." not in Path(path).parts for path in ENGINE_SOURCES.values()))
        for key in ("core.cpp", "generated_config.h", "../../private.json"):
            with self.assertRaises(ValueError):
                self.bridge.execute("engine_source", {"file": key})


class ScratchTests(unittest.TestCase):
    def test_real_worker_returns_json_and_applies_memory_limit(self):
        result = scratch_compute("def solve(x,y):\n    return {'pair':[x,y], 'sum':x+y}\n", [[3, 4]])
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["outputs"], [{"pair": [3, 4], "sum": 7}])
        self.assertEqual(result["limits"]["memory"]["bytes"], 256 * 1024 * 1024)

    def test_unsafe_syntax_and_excessive_inputs_are_rejected(self):
        for code in ("import os\ndef solve(x,y): return 0", "def solve(x,y): return x.real"):
            self.assertEqual(scratch_compute(code, [[0, 0]])["status"], "rejected")
        self.assertEqual(scratch_compute("def solve(x,y): return x", [[0, 0]] * 33)["status"], "rejected")

    def test_timeout_and_output_limit_are_not_valid_results(self):
        self.assertEqual(scratch_compute("def solve(x,y):\n    while True:\n        pass", [[0, 0]], .1)["status"], "timeout")
        self.assertEqual(scratch_compute("def solve(x,y): return 'x' * 100000", [[0, 0]])["status"], "error")

    def test_worker_memory_job_can_nest_inside_attack_process_job(self):
        with tempfile.TemporaryDirectory(prefix="antirea-nested-job-") as temporary:
            root = Path(temporary)
            worker = Path(__file__).resolve().parent.parent / "antirea/judge.py"
            result = run_logged([sys.executable, "-I", "-S", str(worker), "--scratch-worker"],
                                root, root / "worker", timeout=5,
                                stdin=json.dumps({"code": "def solve(x,y): return x+y", "pairs": [[2, 5]]}))
            self.assertEqual(result["returncode"], 0, result)
            actual = json.loads(Path(result["stdout"]).read_text())
            self.assertEqual(actual["status"], "passed", actual)
            self.assertEqual(actual["outputs"], [7])


if __name__ == "__main__":
    unittest.main()
