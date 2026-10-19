"""Fast campaign tests: all attackers, binary checks and judges are mocked."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import attack_existing as runner


def passed(count):
    return {"status": "passed", "total": count, "matched": count}


class ExistingAttackTests(unittest.TestCase):
    CODE = "def solve(x, y):\n    return x + y\n"
    WORKFLOW = ("antirea/attack.py", "antirea/process.py", "antirea/bridge.py",
                "antirea/rea.py", "antirea/judge.py", "scripts/attack_existing.py")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="antirea-campaign-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "original"
        self.destination = self.root / "campaign"
        for name in self.WORKFLOW:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# test-only workflow: " + name, encoding="utf-8")
        builds = {}
        for arm in ("baseline", "protected"):
            path = self.source / "defender" / arm / "app.exe"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("never-executed-" + arm).encode())
            builds[arm] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.original = {"run_id": "historical", "target": "windows-x86_64",
                         "protection_profile": "layered", "attacker_interface_version": 2,
                         "builds": builds}
        (self.source / "report.json").write_text(json.dumps(self.original), encoding="utf-8")
        (self.source / "old-candidate.py").write_text("# historical evidence", encoding="utf-8")
        self.original_bytes = {p.relative_to(self.source): p.read_bytes()
                               for p in self.source.rglob("*") if p.is_file()}
        self.expected = builds["protected"]["sha256"]
        self.attack_calls = []
        self.generated = []

    def write_submission(self, directory, *, code=None, transcript_code=None,
                         target_hash=None, extra_metadata=None, tools=None, subtype="success"):
        directory.mkdir(parents=True, exist_ok=False)
        code = self.CODE if code is None else code
        transcript_code = code if transcript_code is None else transcript_code
        messages = [
            {"type": "system", "subtype": "init", "model": "unit-test-model",
             "tools": tools if tools is not None else ["StructuredOutput", "mcp__anti_rea__decompile"]},
            {"type": "result", "subtype": subtype, "is_error": False,
             "structured_output": {"code": transcript_code, "explanation": "test only"}},
        ]
        (directory / "candidate.py").write_text(code, encoding="utf-8")
        (directory / "attacker.stdout.log").write_text(
            "".join(json.dumps(m) + "\n" for m in messages), encoding="utf-8")
        rea = directory / "rea"
        rea.mkdir()
        metadata = {"sha256": self.expected if target_hash is None else target_hash}
        metadata.update(extra_metadata or {})
        record = {"response": {"result": {"structuredContent": {"result": metadata}}}}
        (rea / "0002-open_binary.json").write_text(json.dumps(record), encoding="utf-8")
        return {"status": "candidate_submitted", "returncode": 0, "timed_out": False,
                "cancelled": False, "unexpected_tools": [], "permission_denials": [],
                "rea_calls": 1, "cost_usd": .25}

    def fake_attack(self, root, target, directory, **kwargs):
        self.attack_calls.append((root, target, directory, kwargs))
        self.assertEqual(root, self.root)
        self.assertEqual(target, self.destination / "target.exe")
        self.assertEqual(kwargs["cancel_file"], self.destination / "STOP")
        self.assertFalse(directory.exists(), "Each attempt must have a fresh directory")
        return self.write_submission(directory)

    def fake_cases(self, count, seed):
        self.generated.append((count, seed))
        return [(seed & 0xffffffff, 0)] * count

    def invoke(self, *, attacker=None, judge=None, functional=None, once=False):
        judge = judge or (lambda code, binary, cases, timeout: passed(len(cases)))
        functional = functional or (lambda baseline, target, cases, timeout: passed(len(cases)))
        with patch.object(runner, "run_attack", side_effect=attacker or self.fake_attack) as attacks, \
                patch.object(runner, "judge_candidate", side_effect=judge) as judges, \
                patch.object(runner, "differential", side_effect=functional), \
                patch.object(runner, "generate_cases", side_effect=self.fake_cases), \
                patch.object(runner.secrets, "randbits", side_effect=range(100, 130)), \
                contextlib.redirect_stdout(io.StringIO()):
            result = runner.campaign(self.root, self.source, self.destination,
                                     seconds=10, budget_usd=.5, once=once)
        self.assertEqual(json.loads((self.destination / "report.json").read_text()), result)
        return result, attacks, judges

    def assert_originals_unchanged(self):
        actual = {p.relative_to(self.source): p.read_bytes()
                  for p in self.source.rglob("*") if p.is_file()}
        self.assertEqual(actual, self.original_bytes)

    def test_complete_score_requires_passed_and_both_exact_counts(self):
        self.assertTrue(runner.complete_score(passed(1024), 1024))
        bad = [{}, {"status": "not_scored"}, passed(4096),
               {"status": "failed", "total": 1024, "matched": 1024},
               {"status": "passed", "total": 1024, "matched": 1023},
               {"status": "passed", "total": 1023, "matched": 1024}]
        for value in bad:
            with self.subTest(value=value):
                self.assertFalse(runner.complete_score(value, 1024))

    def test_submitted_code_requires_exact_transcript_match(self):
        directory = self.root / "attack"
        attack = self.write_submission(directory, transcript_code=self.CODE + "\n")
        with self.assertRaisesRegex(ValueError, "Candidate differs"):
            runner.submitted_code(directory, attack, self.expected)

    def test_target_hash_must_be_metadata_hash_not_text_elsewhere(self):
        directory = self.root / "attack"
        attack = self.write_submission(directory, target_hash="0" * 64,
                                       extra_metadata={"note": self.expected})
        with self.assertRaisesRegex(ValueError, "target hash"):
            runner.submitted_code(directory, attack, self.expected)

    def test_non_success_final_is_not_a_submission(self):
        directory = self.root / "attack"
        attack = self.write_submission(directory, subtype="error_max_budget_usd")
        with self.assertRaises(ValueError):
            runner.submitted_code(directory, attack, self.expected)

    def test_unexpected_tools_are_rejected_from_actual_initialization(self):
        directory = self.root / "attack"
        attack = self.write_submission(directory, tools=["StructuredOutput", "Bash"])
        with self.assertRaisesRegex(ValueError, "Unexpected exposed"):
            runner.submitted_code(directory, attack, self.expected)

    def test_recovered_requires_1024_and_fresh_4096_and_preserves_originals(self):
        result, attacks, judges = self.invoke()
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(attacks.call_count, 1)
        self.assertEqual([len(c.args[2]) for c in judges.call_args_list], [1024, 4096])
        self.assertEqual([count for count, _ in self.generated], [1024, 1024, 4096])
        self.assertEqual(len({seed for _, seed in self.generated}), 3)
        self.assertFalse(result["binary_rebuilt"])
        self.assertEqual(result["reported_cost_usd"], .25)
        self.assertEqual(result["unknown_cost_attempts"], 0)
        item = result["attempts"][0]
        self.assertEqual(item["status"], "recovered")
        self.assertEqual(item["judge"], passed(1024))
        self.assertEqual(item["verification"], passed(4096))
        self.assertEqual((self.destination / "target.exe").read_bytes(),
                         (self.source / "defender/protected/app.exe").read_bytes())
        for name in self.WORKFLOW:
            self.assertEqual((self.destination / "workflow" / name).read_bytes(),
                             (self.root / name).read_bytes())
        self.assert_originals_unchanged()

    def test_passing_first_suite_alone_is_not_recovered(self):
        def score(code, binary, cases, timeout):
            return passed(1024) if len(cases) == 1024 else {"status": "timeout"}
        result, attacks, judges = self.invoke(judge=score, once=True)
        self.assertEqual(result["status"], "attempt_finished")
        self.assertEqual(result["attempts"][0]["status"], "candidate_not_verified")
        self.assertEqual(attacks.call_count, 1)
        self.assertEqual(judges.call_count, 2)

    def test_wrong_verification_count_cannot_be_recovered(self):
        result, _, _ = self.invoke(judge=lambda *args: passed(1024), once=True)
        self.assertEqual(result["status"], "attempt_finished")
        self.assertEqual(result["attempts"][0]["status"], "candidate_not_verified")

    def test_failed_candidate_retries_in_fresh_directory_and_fresh_private_suite(self):
        scores = iter([{"status": "failed", "total": 1024, "matched": 10},
                       passed(1024), passed(4096)])
        result, attacks, judges = self.invoke(judge=lambda *args: next(scores))
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(attacks.call_count, 2)
        self.assertEqual(judges.call_count, 3)
        self.assertEqual([c[2].name for c in self.attack_calls], ["attempt-001", "attempt-002"])
        self.assertEqual(result["attempts"][0]["verification"], {"status": "not_scored"})
        self.assertEqual(result["attempts"][1]["status"], "recovered")
        self.assertEqual(len({seed for _, seed in self.generated}), 4)
        for _, _, _, kwargs in self.attack_calls:
            self.assertEqual(set(kwargs), {"seconds", "budget_usd", "cancel_file"})
        self.assert_originals_unchanged()

    def test_incomplete_attempt_is_not_scored_or_called_recovered(self):
        def incomplete(*args, **kwargs):
            return {"status": "incomplete_timeout", "timed_out": True, "cost_usd": None}
        result, attacks, judges = self.invoke(attacker=incomplete, once=True)
        self.assertEqual(result["status"], "attempt_finished")
        self.assertEqual(attacks.call_count, 1)
        judges.assert_not_called()
        self.assertEqual(result["unknown_cost_attempts"], 1)
        self.assertEqual(result["attempts"][0]["judge"], {"status": "not_scored"})
        self.assertEqual(result["attempts"][0]["verification"], {"status": "not_scored"})

    def test_execution_error_stops_for_inspection_without_scoring(self):
        result, attacks, judges = self.invoke(
            attacker=lambda *args, **kwargs: {"status": "execution_error", "cost_usd": None})
        self.assertEqual(result["status"], "needs_inspection")
        self.assertEqual(attacks.call_count, 1)
        judges.assert_not_called()
        self.assertEqual(result["attempts"][0]["judge"], {"status": "not_scored"})

    def test_mismatched_submission_stops_without_judging(self):
        def bad_submission(root, target, directory, **kwargs):
            return self.write_submission(directory, transcript_code=self.CODE + "# different\n")
        result, attacks, judges = self.invoke(attacker=bad_submission)
        self.assertEqual(result["status"], "needs_inspection")
        self.assertIn("Candidate differs", result["stop_reason"])
        self.assertEqual(attacks.call_count, 1)
        judges.assert_not_called()
        self.assertEqual(result["attempts"][0]["verification"], {"status": "not_scored"})

    def test_stop_cancels_once_and_never_automatically_restarts(self):
        def cancelled(root, target, directory, **kwargs):
            kwargs["cancel_file"].touch()
            return {"status": "cancelled", "cancelled": True, "cost_usd": None}
        result, attacks, judges = self.invoke(attacker=cancelled)
        self.assertEqual(result["status"], "user_stopped")
        self.assertEqual(attacks.call_count, 1)
        judges.assert_not_called()
        self.assertEqual(result["attempts"][0]["judge"], {"status": "not_scored"})
        saved = (self.destination / "report.json").read_bytes()
        with patch.object(runner, "run_attack") as restarted, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(FileExistsError):
                runner.campaign(self.root, self.source, self.destination)
            restarted.assert_not_called()
        self.assertEqual((self.destination / "report.json").read_bytes(), saved)
        self.assert_originals_unchanged()

    def test_stop_before_first_attempt_launches_nothing(self):
        def preflight(*args):
            (self.destination / "STOP").touch()
            return passed(1024)
        result, attacks, judges = self.invoke(functional=preflight)
        self.assertEqual(result["status"], "user_stopped")
        self.assertEqual(result["attempts"], [])
        attacks.assert_not_called()
        judges.assert_not_called()

    def test_stop_during_first_judge_prevents_verification_and_retry(self):
        def score(*args):
            (self.destination / "STOP").touch()
            return passed(1024)
        result, attacks, judges = self.invoke(judge=score)
        self.assertEqual(result["status"], "user_stopped")
        self.assertEqual(attacks.call_count, 1)
        self.assertEqual(judges.call_count, 1)
        self.assertEqual(result["attempts"][0]["verification"], {"status": "not_scored"})

    def test_stop_during_verification_preserves_scores_without_restarting(self):
        def score(code, binary, cases, timeout):
            if len(cases) == 4096:
                (self.destination / "STOP").touch()
            return passed(len(cases))
        result, attacks, judges = self.invoke(judge=score)
        self.assertEqual(result["status"], "user_stopped")
        self.assertEqual(attacks.call_count, 1)
        self.assertEqual(judges.call_count, 2)
        self.assertEqual(result["attempts"][0]["verification"], passed(4096))

    def test_failed_functional_preflight_launches_no_attack(self):
        result, attacks, judges = self.invoke(functional=lambda *args: passed(1023))
        self.assertEqual(result["status"], "needs_inspection")
        self.assertEqual(result["attempts"], [])
        attacks.assert_not_called()
        judges.assert_not_called()

    def test_keyboard_interrupt_is_recorded_without_retry_or_score(self):
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()
        result, attacks, judges = self.invoke(attacker=interrupted)
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(attacks.call_count, 1)
        judges.assert_not_called()
        self.assertEqual(result["attempts"][0]["judge"], {"status": "not_scored"})
        self.assert_originals_unchanged()


if __name__ == "__main__":
    unittest.main()
