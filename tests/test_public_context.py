"""Revision 3 context/computation contract tests; no model is launched."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import attack
from antirea.bridge import Bridge, COMPUTE_HELP, normalize_public_context, public_context_hash
from antirea.judge import judge_candidate, scratch_compute, validate_candidate


class PublicContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-public-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.context = {"kind": "cli_text", "title": "Synthetic score CLI",
                        "description": "Input: unsigned x y pairs. Output: one unsigned score. 공개 인터페이스."}

    def bridge(self, context=None):
        return Bridge({"root": str(self.root), "binary": str(self.root / "unused.exe"),
                       "log_dir": str(self.root), "query_limit": 256, "public_context": context})

    def test_explicit_context_is_identical_across_arms_without_file_reads(self):
        with patch.object(Path, "read_text") as read:
            contexts = [self.bridge(self.context).execute("public_context", {}) for _ in range(3)]
            read.assert_not_called()
        self.assertEqual(contexts, [self.context] * 3)
        self.assertEqual(len({public_context_hash(item) for item in contexts}), 1)

    def test_no_context_has_a_stable_digest(self):
        default = normalize_public_context(None)
        canonical = json.dumps(default, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(public_context_hash(None), hashlib.sha256(canonical).hexdigest())
        self.assertEqual(public_context_hash(default), public_context_hash())
        self.assertEqual(self.bridge().execute("public_context", {}), default)

    def test_context_cannot_load_paths_or_private_artifacts(self):
        invalid = ["../defender/private.json", {**self.context, "path": "../private.json"},
                   {**self.context, "screenshots": ["secret.png"]},
                   {**self.context, "source": "private.cpp"}, {"kind": "gui", "description": "image"}]
        with patch.object(Path, "read_text") as read:
            for value in invalid:
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        normalize_public_context(value)
            with self.assertRaises(ValueError):
                self.bridge(self.context).execute("public_context", {"path": "private.json"})
            read.assert_not_called()

    def test_context_is_bounded_and_return_does_not_mutate_configuration(self):
        with self.assertRaises(ValueError):
            normalize_public_context({"kind": "cli_text", "description": "x" * 65_536})
        bridge = self.bridge(self.context)
        result = bridge.execute("public_context", {})
        result["description"] = "changed"
        self.assertEqual(bridge.execute("public_context", {}), self.context)

    def test_run_attack_records_revision_context_hash_and_copies_only_public_text(self):
        destination = self.root / "attack"

        def fake_run(argv, cwd, prefix, timeout, env, prompt):
            messages = [
                {"type": "system", "subtype": "init", "model": "unit-test-model",
                 "tools": [f"mcp__anti_rea__{name}" for name in attack.TOOL_NAMES]},
                {"type": "result", "subtype": "success", "is_error": False,
                 "structured_output": {"code": "def solve(x,y): return x+y", "explanation": "test"}},
            ]
            stdout = prefix.with_suffix(".stdout.log")
            stdout.write_text("".join(json.dumps(item) + "\n" for item in messages), encoding="utf-8")
            (destination / "bridge-audit.jsonl").write_text('{"rea":true,"error":false}\n', encoding="utf-8")
            return {"returncode": 0, "timed_out": False, "seconds": .1, "stdout": str(stdout)}

        with patch("antirea.attack.claude_command", return_value="not-launched.exe"), \
                patch("antirea.attack.run_logged", side_effect=fake_run):
            result = attack.run_attack(self.root, self.root / "unused.exe", destination,
                                       seconds=30, budget_usd=1, public_context=self.context)
        config = json.loads((destination / "bridge.json").read_text(encoding="utf-8"))
        self.assertEqual(config["public_context"], self.context)
        self.assertEqual(result["public_context_sha256"], public_context_hash(self.context))
        self.assertEqual(result["attacker_interface_version"], 3)
        self.assertIn("public_context", attack.TOOL_NAMES)


class ComputationContractTests(unittest.TestCase):
    CODE = (
        "def solve(x, y):\n"
        "    data = bytes([65, 66])\n"
        "    values = list((x, y))\n"
        "    table = dict([('left', values[0]), ('right', values[1])])\n"
        "    if ord('A') in data and 'missing' not in table:\n"
        "        return int(hex(sum(tuple(values))), 16)\n"
        "    return 0\n"
    )

    def test_new_pure_builtins_and_membership_work_in_scratch_and_final_candidate(self):
        scratch = scratch_compute(self.CODE, [[3, 4]])
        self.assertEqual(scratch["status"], "passed", scratch)
        self.assertEqual(scratch["outputs"], [7])
        with patch("antirea.judge._run_binary", return_value={"status": "passed", "outputs": [7], "elapsed_seconds": 0}):
            scored = judge_candidate(self.CODE, Path("unused-reference.exe"), [(3, 4)])
        self.assertEqual(scored["status"], "passed", scored)
        self.assertEqual(scored["limits"]["memory_bytes"], 256 * 1024 * 1024)

    def test_missing_pairs_provides_explicit_schema_example(self):
        with tempfile.TemporaryDirectory(prefix="antirea-compute-help-") as temporary:
            root = Path(temporary)
            bridge = Bridge({"root": str(root), "binary": str(root / "unused.exe"),
                             "log_dir": str(root), "query_limit": 256})
            result = bridge.call("compute", {"code": "def solve(x,y): return x+y"})
        self.assertTrue(result["isError"])
        output = json.loads(result["content"][0]["text"])
        self.assertEqual(output["status"], "rejected")
        self.assertIn("BOTH code and pairs", output["error"])
        self.assertIn('"pairs":[[2,3]]', output["error"])
        self.assertIn("solve(x,y)", COMPUTE_HELP)

    def test_validator_identifies_unknown_call_and_source_line(self):
        result = scratch_compute("def solve(x,y):\n    return sorted([x,y])\n", [[0, 0]])
        self.assertEqual(result["status"], "rejected")
        self.assertIn("sorted", result["error"])
        self.assertIn("line 2", result["error"])
        self.assertIn("allowed builtins", result["error"])

    def test_validator_explains_computed_top_level_setup(self):
        result = scratch_compute("DATA = list((1,2))\ndef solve(x,y): return DATA[x]\n", [[0, 0]])
        self.assertEqual(result["status"], "rejected")
        self.assertIn("assignment 'DATA' at line 1", result["error"])
        self.assertIn("inside solve", result["error"])

    def test_runtime_diagnostics_are_informative_for_attacker_owned_inputs(self):
        result = scratch_compute("def solve(x,y): return [1][x]\n", [[2, 0]])
        self.assertEqual(result["status"], "error")
        self.assertIn("IndexError", result["error"])
        self.assertIn("out of range", result["error"])

    def test_new_builtins_do_not_enable_attributes_imports_or_io(self):
        for code in ("def solve(x,y): return bytes.__class__", "def solve(x,y): return open(x)",
                     "def solve(x,y): return __import__('os')", "def solve(x,y): return list.__base__",
                     "def solve(x,y):\n    a=[]\n    a.append(x)\n    return 0"):
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    validate_candidate(code)


if __name__ == "__main__":
    unittest.main()
