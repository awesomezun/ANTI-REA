"""Scope-aware runner checks, without launching models, compilers or binaries."""

import argparse
import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import cli
from antirea.attack import public_context_hash


def coverage(profile):
    functions = ["core"] if profile == "core" else ["core", "preprocess", "score"]
    return {"protection": profile, "target_virtualized": profile != "none",
            "scope_plan": {"status": "ready", "mode": profile, "selected_functions": functions},
            "selected_functions": functions if profile != "none" else [],
            "function_coverage": {name: {"virtualized": profile != "none"} for name in functions},
            "public_boundaries_unvirtualized": True}


class ScopedPipelineTests(unittest.TestCase):
    def test_profile_keeps_strength_fixed_and_changes_scope(self):
        self.assertEqual(cli.profile_arms("scoped"),
                         (("baseline", "none"), ("core_reference", "core"), ("protected", "expanded")))
        fixture, script, inputs = cli.fixture_config(Path("test-root"), "scoped")
        self.assertEqual(fixture.name, "context_ledger")
        self.assertEqual(script.name, "build_context_sample.ps1")
        self.assertIn("protection-policy.json", inputs)
        self.assertIn("public/interface.md", inputs)

    def test_every_selected_function_must_be_virtualized(self):
        good = coverage("expanded")
        cli.require_build_coverage("protected", "expanded", good)
        bad = copy.deepcopy(good)
        bad["function_coverage"]["preprocess"]["virtualized"] = False
        with self.assertRaisesRegex(RuntimeError, "one or more selected"):
            cli.require_build_coverage("protected", "expanded", bad)

    def test_unresolved_scope_and_missing_public_boundary_proof_block(self):
        for field in ("status", "selection", "boundary"):
            with self.subTest(field=field):
                bad = coverage("expanded")
                if field == "status":
                    bad["scope_plan"]["status"] = "needs_review"
                elif field == "selection":
                    bad["selected_functions"] = ["core"]
                else:
                    bad["public_boundaries_unvirtualized"] = False
                with self.assertRaises(RuntimeError):
                    cli.require_build_coverage("protected", "expanded", bad)

    @unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows")
    def test_three_arms_use_same_public_context_and_new_fixture(self):
        with tempfile.TemporaryDirectory(prefix="antirea-scoped-cycle-") as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            (run_dir / "defender").mkdir(parents=True)
            fixture = root / "samples/context_ledger"
            (fixture / "public").mkdir(parents=True)
            (fixture / "public/interface.md").write_text("Public decimal pair interface only.", encoding="utf-8")
            (root / ".tools/rea").mkdir(parents=True)
            cli.write_json(root / ".tools/kagura-toolchain.json", {})
            cli.write_json(root / ".tools/rea/environment.json", {})
            cli.write_json(run_dir / "defender/private.json", {"cases": 300, "functional_seed": 1,
                                                               "attack_test_seed": 2, "kagura_seed": 3})
            context = {"kind": "cli_text", "title": "Public scoring application interface",
                       "description": "Public decimal pair interface only."}
            report = {"run_id": "scope-test", "status": "incomplete", "protection_profile": "scoped",
                      "attacks": {}, "builds": {}, "public_context": context, "source_hashes": {},
                      "versions": cli.tool_versions(root, {}, {}),
                      "limits": {"attack_seconds_each": 30, "model_budget_usd_each": 1,
                                 "black_box_pairs_each": 256, "tool_calls_each": 100, "hidden_cases": 300}}
            cli.write_json(run_dir / "report.json", report)
            builds, contexts = [], []

            def fake_build(argv, cwd, prefix, timeout):
                builds.append(argv)
                destination = Path(argv[argv.index("-OutputDir") + 1])
                destination.mkdir(parents=True)
                profile = argv[argv.index("-Protection") + 1]
                (destination / "app.exe").write_bytes(b"test-only never executed")
                cli.write_json(destination / "coverage.json", coverage(profile))
                return {"returncode": 0, "timed_out": False}

            def fake_attack(root, target, directory, **kwargs):
                contexts.append(kwargs["public_context"])
                directory.mkdir(parents=True)
                (directory / "candidate.py").write_text("def solve(x,y): return x+y", encoding="utf-8")
                return {"status": "candidate_submitted", "model": "test", "rea_calls": 1, "tool_errors": 0,
                        "attacker_interface_version": cli.ATTACK_INTERFACE_VERSION,
                        "incomplete_page_tokens": [], "public_context_sha256": public_context_hash(kwargs["public_context"]),
                        "limits": {"seconds": 30, "model_budget_usd": 1, "black_box_pairs": 256, "tool_calls": 100}}

            score = {"status": "passed", "matched": 300, "total": 300}
            args = argparse.Namespace(resume=run_dir, protection="scoped", cases=300, attack_seconds=30, budget_usd=1)
            with patch.object(cli, "ROOT", root), \
                    patch.object(cli, "doctor", return_value={"kagura_ready": True, "rea_ready": True, "claude_cli": "mock"}), \
                    patch.object(cli, "run_logged", side_effect=fake_build), \
                    patch.object(cli, "differential", return_value=score), \
                    patch.object(cli, "run_attack", side_effect=fake_attack), \
                    patch.object(cli, "judge_candidate", return_value=score), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = cli.run_cycle(args)
            saved = cli.read_json(run_dir / "report.json")
            self.assertEqual(result, 0, saved.get("error"))
            self.assertEqual([cmd[cmd.index("-Protection") + 1] for cmd in builds], ["none", "core", "expanded"])
            self.assertTrue(all(cmd[cmd.index("-SourceDir") + 1] == str(fixture) for cmd in builds))
            self.assertEqual(contexts, [context, context, context])
            self.assertTrue(saved["comparison"]["comparable"])
            saved["attacks"]["protected"]["attack"]["public_context_sha256"] = "different"
            self.assertFalse(cli.comparison_conditions(saved)["comparable"])


if __name__ == "__main__":
    unittest.main()
