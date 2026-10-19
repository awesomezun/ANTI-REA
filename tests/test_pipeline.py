"""Pipeline boundary tests: no compiler, model, REA, or target is launched."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from antirea import attack, cli, process
from antirea.bridge import Bridge


class AttackStatusTests(unittest.TestCase):
    def run_case(self, *, init=True, extra_tools=(), timed_out=False,
                 denial=False, candidate=True, audit=None, is_error=False, subtype="success"):
        with tempfile.TemporaryDirectory(prefix="antirea-attack-test-") as temporary:
            root = Path(temporary)
            destination = root / "attack"

            def fake_run(argv, cwd, prefix, timeout, env, prompt):
                messages = []
                if init:
                    messages.append({"type": "system", "subtype": "init",
                                     "tools": [f"mcp__anti_rea__{name}" for name in attack.TOOL_NAMES] + list(extra_tools),
                                     "model": "unit-test-model"})
                final = {"type": "result", "subtype": subtype, "is_error": is_error,
                         "permission_denials": ["denied"] if denial else []}
                if candidate:
                    final["structured_output"] = {"code": "def solve(x, y):\n    return x + y\n",
                                                  "explanation": "Unit-test fixture only."}
                messages.append(final)
                stdout = prefix.with_suffix(".stdout.log")
                stdout.write_text("".join(json.dumps(item) + "\n" for item in messages), encoding="utf-8")
                records = [{"rea": True, "error": False}] if audit is None else audit
                (destination / "bridge-audit.jsonl").write_text(
                    "".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
                return {"stdout": str(stdout), "returncode": 0, "timed_out": timed_out, "seconds": 0.01}

            with patch("antirea.attack.claude_command", return_value="not-launched.exe"), \
                    patch("antirea.attack.run_logged", side_effect=fake_run):
                result = attack.run_attack(root, root / "target.exe", destination, seconds=30, budget_usd=1)
            return result, (destination / "candidate.py").exists()

    def test_valid_candidate_requires_successful_rea_evidence(self):
        result, saved = self.run_case()
        self.assertEqual(result["status"], "candidate_submitted")
        self.assertEqual(result["rea_calls"], 1)
        self.assertTrue(saved)

    def test_failed_rea_attempts_are_not_successful_calls(self):
        result, _ = self.run_case(audit=[{"rea": True, "error": True}])
        self.assertEqual(result["status"], "unevaluated_no_rea")
        self.assertEqual(result["rea_attempts"], 1)
        self.assertEqual(result["rea_calls"], 0)

    def test_queries_without_rea_are_unevaluated(self):
        result, _ = self.run_case(audit=[{"rea": False, "error": False}])
        self.assertEqual(result["status"], "unevaluated_no_rea")

    def test_unexpected_tools_and_missing_initialization_fail_isolation(self):
        for kwargs in ({"extra_tools": ["Read"]}, {"init": False}):
            with self.subTest(kwargs=kwargs):
                result, saved = self.run_case(**kwargs)
                self.assertEqual(result["status"], "isolation_error")
                self.assertFalse(saved)

    def test_timeout_is_incomplete_even_if_a_candidate_appears(self):
        result, saved = self.run_case(timed_out=True)
        self.assertEqual(result["status"], "incomplete_timeout")
        self.assertFalse(saved)

    def test_denial_and_model_errors_are_execution_errors(self):
        for kwargs in ({"denial": True}, {"is_error": True}):
            with self.subTest(kwargs=kwargs):
                result, _ = self.run_case(**kwargs)
                self.assertEqual(result["status"], "execution_error")

    def test_missing_candidate_is_incomplete(self):
        result, _ = self.run_case(candidate=False)
        self.assertEqual(result["status"], "incomplete_no_candidate")

    def test_cost_exhaustion_is_not_execution_failure_or_defense_win(self):
        result, saved = self.run_case(candidate=False, is_error=True, subtype="error_max_budget_usd")
        self.assertEqual(result["status"], "incomplete_cost_budget")
        self.assertIsNone(result["cost_usd"])
        self.assertFalse(saved)

    def test_interface_revision_is_recorded(self):
        result, _ = self.run_case()
        self.assertEqual(result["attacker_interface_version"], attack.ATTACK_INTERFACE_VERSION)


class BridgeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="antirea-bridge-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bridge = Bridge({"root": str(self.root), "binary": str(self.root / "only-target.exe"),
                              "log_dir": str(self.root), "query_limit": 2})

    def test_query_inputs_and_batch_size_are_bounded(self):
        pairs = ([], [[-1, 0]], [[True, 0]], [[4294967296, 0]], [[0]], [[0, 0]] * 33)
        with patch("antirea.bridge.subprocess.run") as run:
            for value in pairs:
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        self.bridge.execute("query", {"pairs": value})
            run.assert_not_called()

    def test_query_uses_only_fixed_binary_and_enforces_total_budget(self):
        completed = SimpleNamespace(stdout="3\n7\n")
        with patch("antirea.bridge.subprocess.run", return_value=completed) as run:
            result = self.bridge.execute("query", {"pairs": [[1, 2], [3, 4]], "binary": "other.exe"})
            self.assertEqual(result["results"], [3, 7])
            self.assertEqual(result["queries_remaining"], 0)
            self.assertEqual(run.call_args.args[0], [str(self.root / "only-target.exe")])
            with self.assertRaises(ValueError):
                self.bridge.execute("query", {"pairs": [[1, 2]]})
            self.assertEqual(run.call_count, 1)

    def test_read_bytes_bounds_and_discarded_path_arguments(self):
        self.bridge.rea = Mock(return_value={"bytes": "00"})
        for length in (0, 4097):
            with self.assertRaises(ValueError):
                self.bridge.execute("read_bytes", {"address": "140000000", "length": length})
        self.bridge.execute("read_bytes", {"address": "140000000", "length": 1, "path": "private.json"})
        self.bridge.rea.assert_called_once_with("read_bytes", {"address": "140000000", "length": 1})

    def test_query_rejects_out_of_range_target_output(self):
        for value in (-1, 18446744073709551616):
            with self.subTest(value=value), patch("antirea.bridge.subprocess.run", return_value=SimpleNamespace(stdout=f"{value}\n")):
                with self.assertRaisesRegex(RuntimeError, "unsigned 64-bit"):
                    self.bridge.execute("query", {"pairs": [[0, 0]]})

    def test_engine_source_cannot_select_arbitrary_files(self):
        with patch.object(Path, "read_text") as read:
            for name in ("../../defender/private.json", "core.cpp", "generated_config.h"):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        self.bridge.execute("engine_source", {"file": name})
            read.assert_not_called()

    def test_tool_call_budget_is_enforced(self):
        self.bridge.calls = 100
        self.bridge.rea = Mock()
        with self.assertRaises(ValueError):
            self.bridge.execute("procedures", {})
        self.bridge.rea.assert_not_called()

    def test_procedure_pagination_preserves_limitations(self):
        self.bridge.rea = Mock(return_value={"result": [{"name": "core_a"}, {"name": "noise"}, {"name": "core_b"}],
                                             "limitations": ["unit-test limitation"]})
        result = self.bridge.execute("procedures", {"query": "core", "offset": 1, "limit": 1})
        self.assertEqual(result["items"], [{"name": "core_b"}])
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["limitations"], ["unit-test limitation"])

    def test_failed_rea_call_is_audited_as_error(self):
        self.bridge.rea = Mock(side_effect=RuntimeError("fixture tool failure"))
        result = self.bridge.call("decompile", {"procedure": "core"})
        self.assertTrue(result["isError"])
        record = json.loads((self.root / "bridge-audit.jsonl").read_text(encoding="utf-8"))
        self.assertTrue(record["rea"])
        self.assertTrue(record["error"])


class ReportCompletionTests(unittest.TestCase):
    def run_cycle_case(self, judge_statuses, attack_statuses=None):
        with tempfile.TemporaryDirectory(prefix="antirea-cycle-test-") as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            (run_dir / "defender").mkdir(parents=True)
            (root / ".tools/rea").mkdir(parents=True)
            cli.write_json(root / ".tools/kagura-toolchain.json", {})
            cli.write_json(root / ".tools/rea/environment.json", {})
            cli.write_json(run_dir / "defender/private.json", {"cases": 300, "functional_seed": 1,
                                                               "attack_test_seed": 2, "kagura_seed": 3})
            report = {"run_id": "unit-test", "status": "incomplete", "attacks": {}, "builds": {},
                      "limits": {"attack_seconds_each": 30, "model_budget_usd_each": 1, "hidden_cases": 300},
                      "source_hashes": {}, "versions": cli.tool_versions(root, {}, {})}
            for name in ("baseline", "protected"):
                path = run_dir / "defender" / name / "app.exe"
                path.parent.mkdir()
                path.write_bytes(b"unit-test placeholder, never executed")
                report["builds"][name] = {"sha256": cli.digest(path), "bytes": path.stat().st_size,
                                          "coverage": {"target_virtualized": name == "protected"}}
            cli.write_json(run_dir / "report.json", report)
            statuses = iter(attack_statuses or ["candidate_submitted", "candidate_submitted"])

            def fake_attack(root, target, directory, **kwargs):
                directory.mkdir(parents=True)
                (directory / "candidate.py").write_text("def solve(x, y):\n    return x + y\n", encoding="utf-8")
                return {"status": next(statuses), "rea_calls": 1, "tool_errors": 0,
                        "model": "unit-test-model", "attacker_interface_version": attack.ATTACK_INTERFACE_VERSION,
                        "limits": {"seconds": kwargs["seconds"], "model_budget_usd": kwargs["budget_usd"],
                                   "black_box_pairs": 256, "tool_calls": 100},
                        "incomplete_page_tokens": []}

            scores = [{"status": status, "matched": 300 if status == "passed" else 0, "total": 300}
                      for status in judge_statuses]
            args = argparse.Namespace(resume=run_dir, cases=300, attack_seconds=30, budget_usd=1)
            with patch.object(cli, "ROOT", root), \
                    patch.object(cli, "doctor", return_value={"kagura_ready": True, "rea_ready": True, "claude_cli": "mock"}), \
                    patch.object(cli, "differential", return_value={"status": "passed", "total": 300, "matched": 300}), \
                    patch.object(cli, "run_attack", side_effect=fake_attack), \
                    patch.object(cli, "judge_candidate", side_effect=scores), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = cli.run_cycle(args)
            return code, cli.read_json(run_dir / "report.json")

    @unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows only")
    def test_both_scored_results_complete_even_without_defense_advantage(self):
        code, report = self.run_cycle_case(["passed", "passed"])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "completed")
        self.assertIn("did not prevent", report["interpretation"])

    @unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows only")
    def test_wrong_protected_candidate_is_limited_nonrecovery(self):
        code, report = self.run_cycle_case(["passed", "failed"])
        self.assertEqual(code, 0)
        self.assertIn("limited non-recovery", report["interpretation"])

    @unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows only")
    def test_invalid_candidate_does_not_complete_or_claim_defense(self):
        code, report = self.run_cycle_case(["passed", "rejected"])
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("not defense success", report["interpretation"])

    @unittest.skipUnless(cli.os.name == "nt", "first build adapter intentionally supports Windows only")
    def test_protected_timeout_is_not_defense_success(self):
        code, report = self.run_cycle_case(["passed"], ["candidate_submitted", "incomplete_timeout"])
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("not defense success", report["interpretation"])


class ResumeProvenanceTests(unittest.TestCase):
    def test_changed_limits_are_rejected(self):
        report = {"limits": {"attack_seconds_each": 600, "model_budget_usd_each": 5, "hidden_cases": 1024}}
        cli.require_resume_limits(report, argparse.Namespace(attack_seconds=600, budget_usd=5, cases=1024))
        for field, changed in (("attack_seconds", 900), ("budget_usd", 10), ("cases", 2048)):
            values = {"attack_seconds": 600, "budget_usd": 5, "cases": 1024}
            values[field] = changed
            with self.assertRaisesRegex(RuntimeError, "original attack"):
                cli.require_resume_limits(report, argparse.Namespace(**values))

    def test_lockfile_change_changes_provenance(self):
        with tempfile.TemporaryDirectory(prefix="antirea-version-test-") as temporary:
            root = Path(temporary)
            lock = root / ".tools/rea/runtime/package-lock.json"
            lock.parent.mkdir(parents=True)
            lock.write_text('{"version":1}', encoding="utf-8")
            first = cli.tool_versions(root, {}, {"ghidra_install_dir": str(root / "ghidra_12.1.4_PUBLIC")})
            lock.write_text('{"version":2}', encoding="utf-8")
            second = cli.tool_versions(root, {}, {"ghidra_install_dir": str(root / "ghidra_12.1.4_PUBLIC")})
            self.assertNotEqual(first["rea_lock_sha256"], second["rea_lock_sha256"])
            self.assertEqual(first["ghidra"], "ghidra_12.1.4_PUBLIC")


class ProcessTimeoutTests(unittest.TestCase):
    def test_timeout_requests_tree_cleanup_and_records_incomplete_execution(self):
        with tempfile.TemporaryDirectory(prefix="antirea-process-test-") as temporary:
            root = Path(temporary)
            child = Mock()
            child.returncode = -9
            child.communicate.side_effect = [subprocess.TimeoutExpired("unit-test", 0.1), None]
            with patch("antirea.process.subprocess.Popen", return_value=child), \
                    patch("antirea.process.stop_tree") as stop:
                result = process.run_logged(["not-launched.exe"], root, root / "child", timeout=0.1)
            stop.assert_called_once_with(child)
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["returncode"], -9)
            self.assertTrue((root / "child.process.json").is_file())


if __name__ == "__main__":
    unittest.main()
