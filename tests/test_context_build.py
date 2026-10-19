"""Fixture policy checks plus opt-in real Windows build integration tests.

Run the expensive checks explicitly after bootstrap:
  $env:ANTI_REA_CONTEXT_BUILD_TESTS='1'
  python -m unittest discover -s tests -p test_context_build.py -v
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from antirea.judge import _run_binary, generate_cases


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "samples/context_ledger"
MASK = (1 << 64) - 1


def smoke_oracle(x, y):
    """Reference for the checked-in PUBLIC smoke constants, not run secrets."""
    k0, k1, k2, k3 = 0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F
    state = (((x + k0) ^ (y << 17)) + (y ^ k1) * 257) & MASK
    state ^= state >> 19
    for round_index in range(5):
        state ^= state >> 13
        state = state * (k2 | 1) & MASK
        if (state ^ x ^ round_index) & 1:
            state = (state + (y << 11) + round_index) & MASK
        else:
            state ^= (x << 7) + 0x045D9F3B
        state = (state + (round_index + 1) * 0x9E3779B97F4A7C15) & MASK
    return ((state ^ (state >> 23)) + (x + y) * (k3 | 1)) & MASK


class ContextFixtureTests(unittest.TestCase):
    def test_policy_keeps_public_wrapper_outside_sensitive_set(self):
        policy = json.loads((FIXTURE / "protection-policy.json").read_text())
        self.assertEqual(policy["core_roots"], ["antirea_mix"])
        self.assertEqual(policy["sensitive_functions"], [])
        self.assertEqual(set(policy["public_presentation"]), {"antirea_present_score"})
        self.assertTrue(policy["public_presentation"]["antirea_present_score"])
        self.assertFalse(set(policy["sensitive_functions"]) & set(policy["public_presentation"]))
        self.assertEqual(policy["sensitive_globals"], [])

    def test_public_context_has_no_config_values(self):
        context = (FIXTURE / "public/interface.md").read_text()
        self.assertNotIn("ANTI_REA_K", context)
        self.assertNotIn("0x9E3779B9", context)
        self.assertIn("not a GUI", context)


@unittest.skipUnless(os.name == "nt" and os.environ.get("ANTI_REA_CONTEXT_BUILD_TESTS") == "1",
                     "real Windows LLVM/Kagura build is opt-in")
class ContextBuildIntegrationTests(unittest.TestCase):
    def test_scope_modes_cover_targets_and_match_public_oracle(self):
        smoke_root = ROOT / ".tools/context-smoke"
        smoke_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="integration-", dir=smoke_root) as temp:
            cases = generate_cases(4096, seed=20261018)
            expected = [smoke_oracle(x, y) for x, y in cases]
            for mode, selected_count in (("none", 0), ("core", 1), ("expanded", 4)):
                output = Path(temp) / mode
                command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                           str(ROOT / "scripts/build_context_sample.ps1"),
                           "-SourceDir", str(FIXTURE), "-OutputDir", str(output),
                           "-ConfigInclude", str(FIXTURE), "-Protection", mode, "-Seed", "480868569"]
                built = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                coverage = json.loads((output / "coverage.json").read_text())
                self.assertEqual(coverage["scope_plan"]["status"], "ready")
                self.assertEqual(len(coverage["selected_functions"]), selected_count)
                self.assertEqual(coverage["vm_call_count"], selected_count)
                if mode == "expanded":
                    reasons = coverage["scope_plan"]["reasons"]
                    self.assertIn("caller_of:antirea_mix", reasons["antirea_score"])
                    self.assertIn("callee_of:antirea_score", reasons["antirea_prepare"])
                    self.assertIn("callee_of:antirea_score", reasons["antirea_adjust"])
                self.assertTrue(coverage["public_boundaries_unvirtualized"])
                self.assertTrue(coverage["function_coverage"]["antirea_present_score"]
                                ["body_unchanged_ignoring_attribute_ids"])
                for name in coverage["selected_functions"]:
                    self.assertTrue(coverage["function_coverage"][name]["virtualized"])
                    self.assertGreater(coverage["function_coverage"][name]["bytecode_size"], 0)
                actual = _run_binary(output / "app.exe", cases, 20)
                self.assertEqual(actual["status"], "passed")
                self.assertEqual(actual["outputs"], expected)


if __name__ == "__main__":
    unittest.main()
