"""Profile and fair-comparison tests; no compiler, model or executable runs."""

import argparse
import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from antirea import cli


def scored(status="passed"):
    return {"attack": {"status": "candidate_submitted", "model": "test-model",
                       "attacker_interface_version": cli.ATTACK_INTERFACE_VERSION,
                       "limits": {"seconds": 30, "model_budget_usd": 1,
                                  "black_box_pairs": 256, "tool_calls": 100},
                       "tool_errors": 0, "rea_calls": 1, "incomplete_page_tokens": []},
            "judge": {"status": status, "matched": 300 if status == "passed" else 0, "total": 300}}


def fixture_report(profile="vm"):
    return {"run_id": "profile-test", "status": "running", "protection_profile": profile,
            "builds": {}, "attacks": {name: scored() for name, _ in cli.profile_arms(profile)},
            "limits": {"attack_seconds_each": 30, "model_budget_usd_each": 1,
                       "black_box_pairs_each": 256, "tool_calls_each": 100, "hidden_cases": 300}}


def coverage(profile):
    evidence = {"function_found": True, "fla_dispatcher": True,
                "substitution_instructions": 5, "constant_obfuscation_instructions": 9}
    return {"protection": profile, "target_virtualized": profile != "none",
            "requested_core_passes": ["fla", "sub", "co", "vm"] if profile == "layered" else (["vm"] if profile == "vm" else []),
            "pre_vm_evidence": evidence if profile == "layered" else None,
            "runtime_evidence": evidence if profile == "layered" else None}


class ProfileTests(unittest.TestCase):
    def test_default_and_layered_arms(self):
        self.assertEqual(cli.profile_arms(), (("baseline", "none"), ("protected", "vm")))
        self.assertEqual(cli.profile_arms("layered"),
                         (("baseline", "none"), ("vm_reference", "vm"), ("protected", "layered")))
        with self.assertRaises(ValueError):
            cli.profile_arms("pretend-unbreakable")

    def test_resume_legacy_defaults_to_vm_but_rejects_profile_change(self):
        report = fixture_report()
        report.pop("protection_profile")
        args = argparse.Namespace(attack_seconds=30, budget_usd=1, cases=300)
        cli.require_resume_limits(report, args)
        args.protection = "layered"
        with self.assertRaisesRegex(RuntimeError, "original protection profile"):
            cli.require_resume_limits(report, args)

    def test_all_protected_arms_require_real_vm(self):
        for name, profile in cli.profile_arms("layered"):
            cli.require_build_coverage(name, profile, coverage(profile))
            if profile != "none":
                bad = coverage(profile)
                bad["target_virtualized"] = False
                with self.assertRaisesRegex(RuntimeError, "not actually virtualized"):
                    cli.require_build_coverage(name, profile, bad)

    def test_layered_requires_both_pre_vm_and_runtime_evidence(self):
        for field in ("pre_vm_evidence", "runtime_evidence"):
            bad = coverage("layered")
            bad[field] = None
            with self.assertRaisesRegex(RuntimeError, field):
                cli.require_build_coverage("protected", "layered", bad)
        bad = coverage("layered")
        bad["requested_core_passes"] = ["vm"]
        with self.assertRaisesRegex(RuntimeError, "pass configuration"):
            cli.require_build_coverage("protected", "layered", bad)

    def test_profile_label_must_match_coverage(self):
        with self.assertRaisesRegex(RuntimeError, "different protection profile"):
            cli.require_build_coverage("protected", "layered", coverage("vm"))
        with self.assertRaisesRegex(RuntimeError, "Baseline unexpectedly"):
            cli.require_build_coverage("baseline", "none", {"target_virtualized": True})


class ComparisonTests(unittest.TestCase):
    def test_matching_models_interfaces_and_caps_are_comparable(self):
        self.assertTrue(cli.comparison_conditions(fixture_report("layered"))["comparable"])

    def test_missing_or_changed_model_interface_and_limits_block_comparison(self):
        changes = (("model", None), ("model", "different-model"),
                   ("attacker_interface_version", None), ("attacker_interface_version", -1),
                   ("limits", None), ("limits", {"seconds": 31}))
        for key, value in changes:
            with self.subTest(key=key, value=value):
                report = fixture_report("layered")
                report["attacks"]["vm_reference"]["attack"][key] = value
                report["attacks"]["protected"]["judge"]["status"] = "failed"
                cli.finish_evaluation(report)
                self.assertFalse(report["comparison"]["comparable"])
                self.assertNotIn("limited non-recovery", report["interpretation"])
                self.assertIn("not attributable", report["interpretation"])
                self.assertEqual(report["status"], "completed")

    def test_layered_failure_requires_successful_baseline_and_vm_reference_for_incremental_claim(self):
        report = fixture_report("layered")
        report["attacks"]["protected"] = scored("failed")
        cli.finish_evaluation(report)
        self.assertIn("baseline and VM-only reference were recovered", report["interpretation"])
        self.assertIn("limited non-recovery", report["interpretation"])
        report["attacks"]["vm_reference"] = scored("failed")
        cli.finish_evaluation(report)
        self.assertIn("does not establish an incremental advantage", report["interpretation"])

    def test_tool_errors_or_unread_pages_do_not_support_nonrecovery_claim(self):
        for field, value in (("tool_errors", 1), ("incomplete_page_tokens", ["unread"]),
                             ("incomplete_page_tokens", None)):
            report = fixture_report("layered")
            report["attacks"]["protected"] = scored("failed")
            report["attacks"]["protected"]["attack"][field] = value
            cli.finish_evaluation(report)
            self.assertNotIn("limited non-recovery", report["interpretation"])
            self.assertIn("not defense success", report["interpretation"])

    def test_successful_recovery_remains_valid_despite_unread_irrelevant_pages(self):
        report = fixture_report("layered")
        report["attacks"]["protected"]["attack"]["incomplete_page_tokens"] = ["unread"]
        cli.finish_evaluation(report)
        self.assertEqual(report["status"], "completed")
        self.assertIn("did not prevent", report["interpretation"])

    def test_every_arm_needs_a_valid_scored_candidate_to_complete(self):
        for name, _ in cli.profile_arms("layered"):
            for status in ("rejected", "timeout", "execution_error"):
                report = fixture_report("layered")
                report["attacks"][name]["judge"]["status"] = status
                cli.finish_evaluation(report)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("not defense success", report["interpretation"])
            report = fixture_report("layered")
            report["attacks"][name]["attack"]["status"] = "incomplete_cost_budget"
            cli.finish_evaluation(report)
            self.assertEqual(report["status"], "incomplete")

    def test_report_renders_dynamic_arms_and_invalid_candidate_as_unscored(self):
        report = fixture_report("layered")
        report["attacks"]["protected"] = scored("rejected")
        cli.finish_evaluation(report)
        with tempfile.TemporaryDirectory(prefix="antirea-profile-report-") as temporary:
            cli.render_report(Path(temporary), report)
            text = (Path(temporary) / "report.md").read_text(encoding="utf-8")
        self.assertIn("vm_reference", text)
        self.assertIn("not scored (rejected)", text)
        self.assertNotIn("rejected 0/300", text)
        self.assertIn("non-VM passes", text)

    def test_report_accepts_legacy_single_pass_string(self):
        report = fixture_report()
        report["builds"]["protected"] = {
            "sha256": "test", "bytes": 1,
            "coverage": {"target_virtualized": True, "requested_core_passes": "vm"}}
        with tempfile.TemporaryDirectory(prefix="antirea-profile-label-") as temporary:
            cli.render_report(Path(temporary), report)
            text = (Path(temporary) / "report.md").read_text(encoding="utf-8")
        self.assertIn("| protected | vm | vm |", text)
        self.assertNotIn("v, m", text)


@unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows only")
class ProfileCycleTests(unittest.TestCase):
    def test_layered_cycle_builds_and_attacks_three_arms_with_shared_seeds_and_caps(self):
        with tempfile.TemporaryDirectory(prefix="antirea-profile-cycle-") as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            (run_dir / "defender").mkdir(parents=True)
            (root / ".tools/rea").mkdir(parents=True)
            cli.write_json(root / ".tools/kagura-toolchain.json", {})
            cli.write_json(root / ".tools/rea/environment.json", {})
            private = {"cases": 300, "functional_seed": 11, "attack_test_seed": 22, "kagura_seed": 33}
            cli.write_json(run_dir / "defender/private.json", private)
            report = fixture_report("layered")
            report.update({"attacks": {}, "source_hashes": {}, "versions": cli.tool_versions(root, {}, {})})
            cli.write_json(run_dir / "report.json", report)
            build_commands, attacked, functional_cases, judged_cases = [], [], [], []

            def fake_build(argv, cwd, prefix, timeout):
                build_commands.append(argv)
                destination = Path(argv[argv.index("-OutputDir") + 1])
                profile = argv[argv.index("-Protection") + 1]
                destination.mkdir(parents=True)
                (destination / "app.exe").write_bytes(b"test-only non-executable " + profile.encode())
                cli.write_json(destination / "coverage.json", coverage(profile))
                return {"returncode": 0, "timed_out": False}

            def fake_differential(baseline, protected, cases, **kwargs):
                functional_cases.append(copy.deepcopy(cases))
                return {"status": "passed", "matched": len(cases), "total": len(cases)}

            def fake_attack(root, target, directory, **kwargs):
                attacked.append((target.parent.name, kwargs))
                directory.mkdir(parents=True)
                (directory / "candidate.py").write_text("def solve(x,y): return x+y\n", encoding="utf-8")
                return scored()["attack"]

            def fake_judge(code, baseline, cases, **kwargs):
                judged_cases.append(copy.deepcopy(cases))
                return {"status": "passed", "matched": len(cases), "total": len(cases)}

            args = argparse.Namespace(resume=run_dir, protection="layered", cases=300, attack_seconds=30, budget_usd=1)
            with patch.object(cli, "ROOT", root), \
                    patch.object(cli, "doctor", return_value={"kagura_ready": True, "rea_ready": True, "claude_cli": "mock"}), \
                    patch.object(cli, "run_logged", side_effect=fake_build), \
                    patch.object(cli, "differential", side_effect=fake_differential), \
                    patch.object(cli, "run_attack", side_effect=fake_attack), \
                    patch.object(cli, "judge_candidate", side_effect=fake_judge), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = cli.run_cycle(args)
            saved = cli.read_json(run_dir / "report.json")
            self.assertEqual(result, 0, saved.get("error"))
            self.assertEqual([cmd[cmd.index("-Protection") + 1] for cmd in build_commands], ["none", "vm", "layered"])
            self.assertEqual({cmd[cmd.index("-Seed") + 1] for cmd in build_commands}, {"33"})
            self.assertEqual({cmd[cmd.index("-ConfigInclude") + 1] for cmd in build_commands}, {str(run_dir / "defender")})
            self.assertEqual([name for name, _ in attacked], ["baseline", "vm_reference", "protected"])
            self.assertTrue(all(caps == {"seconds": 30, "budget_usd": 1} for _, caps in attacked))
            self.assertEqual(functional_cases[0], functional_cases[1])
            self.assertEqual(judged_cases[0], judged_cases[1])
            self.assertEqual(judged_cases[1], judged_cases[2])
            self.assertNotEqual(functional_cases[0], judged_cases[0])
            self.assertEqual(set(saved["functional_by_arm"]), {"vm_reference", "protected"})
            self.assertEqual(saved["functional"], saved["functional_by_arm"]["protected"])
            self.assertTrue(saved["comparison"]["comparable"])


if __name__ == "__main__":
    unittest.main()
