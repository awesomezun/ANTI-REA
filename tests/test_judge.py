from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from antirea.judge import (
    U32_MAX, _run_binary, differential, generate_cases, judge_candidate, validate_candidate,
)


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.cases = [(0, 0), (1, 2), (U32_MAX, U32_MAX), (12345, 65432)]

    def reference(self, *args):
        return {"status": "passed", "outputs": [x + y for x, y in self.cases],
                "elapsed_seconds": 0.001}

    def judge(self, code, timeout=5):
        with patch("antirea.judge._run_binary", side_effect=self.reference):
            return judge_candidate(code, Path("unused-reference.exe"), self.cases, timeout)

    def test_cases_are_reproducible_and_include_boundaries(self):
        one = generate_cases(1000, seed=123)
        self.assertEqual(one, generate_cases(1000, seed=123))
        self.assertNotEqual(one, generate_cases(1000, seed=456))
        self.assertIn((U32_MAX, 0), one)
        self.assertIn((0, U32_MAX), one)
        self.assertIn((U32_MAX, U32_MAX), one)
        self.assertEqual(len(one), 1000)

    def test_correct_candidate_in_real_child_process(self):
        result = self.judge("def solve(x, y):\n    return x + y\n")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["matched"], len(self.cases))
        self.assertNotIn("outputs", result)

    def test_helper_loop_and_unsigned_arithmetic(self):
        result = self.judge(
            "def helper(x):\n"
            "    a = 0\n"
            "    for k in range(2):\n"
            "        a += x\n"
            "    return a >> 1\n"
            "def solve(x, y):\n"
            "    return (helper(x) + y) & 0xffffffffffffffff\n"
        )
        self.assertEqual(result["status"], "passed")

    def test_literal_data_and_interpreter_style_replay(self):
        result = self.judge(
            "OPCODES = [1, 1, 2, 3]\n"
            "OFFSETS = (0, 1)\n"
            "LABELS = {'push': 1, 'add': 2, 'return': 3}\n"
            "def solve(x, y):\n"
            "    args = [x, y]\n"
            "    stack = [0] * 8\n"
            "    sp = 0\n"
            "    arg = 0\n"
            "    for pc, opcode in enumerate(OPCODES):\n"
            "        if opcode == LABELS['push']:\n"
            "            stack[sp] = args[OFFSETS[arg]]\n"
            "            sp += 1\n"
            "            arg += 1\n"
            "        elif opcode == LABELS['add']:\n"
            "            sp -= 1\n"
            "            stack[sp - 1] += stack[sp]\n"
            "        elif opcode == LABELS['return']:\n"
            "            return stack[sp - 1]\n"
            "    return 0\n"
        )
        self.assertEqual(result["status"], "passed")

    def test_safe_container_builtins_and_bytes(self):
        result = self.judge(
            "DATA = b'12'\n"
            "def solve(x, y):\n"
            "    pairs = [(x, y)]\n"
            "    values = [0, 0]\n"
            "    for i, pair in zip(range(len(pairs)), pairs):\n"
            "        values[i] = sum(pair)\n"
            "    if bool(int('1')) and DATA[0] == 49:\n"
            "        return values[0]\n"
            "    return 0\n"
        )
        self.assertEqual(result["status"], "passed")

    def test_wrong_candidate_is_scored_failure(self):
        result = self.judge("def solve(x, y):\n    return 0\n")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["matched"], 1)

    def test_nonterminating_candidate_times_out(self):
        result = self.judge("def solve(x, y):\n    while True:\n        pass\n", timeout=0.5)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["stage"], "candidate_execution")

    def test_candidate_runtime_error_is_not_wrong_logic_score(self):
        result = self.judge("def solve(x, y):\n    return 1 // 0\n")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["matched"], 0)

    def test_candidate_must_return_uint64(self):
        for expr in ("-1", "1 << 64", "True"):
            with self.subTest(expr=expr):
                self.assertEqual(self.judge(f"def solve(x, y):\n    return {expr}\n")["status"], "error")

    def test_rejects_unsafe_or_unsupported_syntax(self):
        candidates = [
            "import os\ndef solve(x, y):\n    return x\n",
            "def solve(x, y):\n    return x.__class__\n",
            "def solve(x, y):\n    return __import__(1)\n",
            "def solve(x, y):\n    return open(1)\n",
            "def solve(x, y):\n    return eval(1)\n",
            "def solve(x, y):\n    return exec(1)\n",
            "def solve(x, y):\n    global z\n    z = 1\n    return z\n",
            "@min\ndef solve(x, y):\n    return 0\n",
            "def solve(x, y=1):\n    return x\n",
            "def solve(x, y):\n    return x ** y\n",
            "def solve(x, y):\n    return [i for i in range(x)]\n",
            "TABLE = range(5)\ndef solve(x, y):\n    return x\n",
            "solve = [1]\ndef solve(x, y):\n    return x\n",
            "len = [1]\ndef solve(x, y):\n    return x\n",
        ]
        for code in candidates:
            with self.subTest(code=code):
                result = self.judge(code)
                self.assertEqual(result["status"], "rejected")

    def test_requires_solve_signature(self):
        for code in ("", "def helper(x, y):\n    return x\n",
                     "def solve(x):\n    return x\n"):
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    validate_candidate(code)

    def test_differential_passes_and_detects_mismatch(self):
        good = self.reference()
        bad = {**good, "outputs": [0] * len(self.cases)}
        with patch("antirea.judge._run_binary", side_effect=[good, good]):
            result = differential(Path("baseline.exe"), Path("protected.exe"), self.cases)
        self.assertEqual(result["status"], "passed")
        with patch("antirea.judge._run_binary", side_effect=[good, bad]):
            result = differential(Path("baseline.exe"), Path("protected.exe"), self.cases)
        self.assertEqual(result["status"], "failed")

    def test_missing_binary_is_error_not_defense_success(self):
        result = differential(Path("does-not-exist-baseline.exe"),
                              Path("does-not-exist-protected.exe"), self.cases)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["stage"], "baseline")

    def test_binary_output_requires_correct_count_and_uint64_decimal(self):
        for output in ("0\n", "0\n1\n2\n-1\n", "0\n1\n2\n18446744073709551616\n",
                       "0\n1\n2\n1.5\n", "0\n1\n2\nhello\n"):
            with self.subTest(output=output):
                completed = SimpleNamespace(returncode=0, stdout=output)
                with patch("antirea.judge.subprocess.run", return_value=completed):
                    result = _run_binary(Path("fixture.exe"), self.cases, 1)
                self.assertEqual(result["status"], "error")

    def test_binary_exit_and_timeout_are_execution_failures(self):
        with patch("antirea.judge.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout="")):
            result = _run_binary(Path("fixture.exe"), self.cases, 1)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["exit_code"], 2)
        with patch("antirea.judge.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture.exe", 1)):
            result = _run_binary(Path("fixture.exe"), self.cases, 1)
        self.assertEqual(result["status"], "timeout")

    def test_protected_execution_failure_does_not_pass_differential(self):
        with patch("antirea.judge._run_binary", side_effect=[self.reference(), {"status": "error", "error": "failed"}]):
            result = differential(Path("baseline.exe"), Path("protected.exe"), self.cases)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["stage"], "protected")

    def test_rejects_invalid_cases_and_timeout(self):
        for cases in ([], [(U32_MAX + 1, 0)], [(-1, 0)], [(True, 0)], [(0,)]):
            with self.subTest(cases=cases):
                with self.assertRaises(ValueError):
                    differential(Path("a"), Path("b"), cases)
        with self.assertRaises(ValueError):
            differential(Path("a"), Path("b"), self.cases, timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
