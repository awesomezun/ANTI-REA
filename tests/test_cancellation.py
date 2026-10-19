"""Cancellation tests use owned local Python children; no model or REA calls."""

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from antirea import attack, process


def windows_pid_running(pid):
    """Read only the exact PID emitted by a test-owned process."""
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x00100000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return False
        raise OSError(error, "Cannot inspect the test-owned PID")
    try:
        state = kernel.WaitForSingleObject(handle, 0)
        if state == 0:
            return False
        if state == 258:
            return True
        raise OSError(ctypes.get_last_error(), "WaitForSingleObject failed")
    finally:
        kernel.CloseHandle(handle)


class ProcessCancellationTests(unittest.TestCase):
    def test_existing_marker_never_launches_child_and_writes_manifest(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-before-") as temporary:
            root = Path(temporary)
            marker = root / "STOP"
            marker.touch()
            with patch.object(process.subprocess, "Popen") as launch, \
                    patch.object(process, "_WindowsJob") as job, \
                    patch.object(process, "stop_tree") as stop:
                result = process.run_logged(["never-launched.exe"], root, root / "run",
                                            cancel_file=marker)
            launch.assert_not_called()
            job.assert_not_called()
            stop.assert_not_called()
            self.assertTrue(result["cancelled"])
            self.assertFalse(result["timed_out"])
            self.assertIsNone(result["pid"])
            self.assertIsNone(result["returncode"])
            self.assertEqual(result["cleanup"]["status"], "not_started")
            self.assertEqual((root / "run.stdout.log").read_text(), "")
            self.assertEqual((root / "run.stderr.log").read_text(), "")
            self.assertEqual(json.loads((root / "run.process.json").read_text()), result)

    def test_polling_sends_stdin_only_once_and_bounds_waits(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-poll-") as temporary:
            root = Path(temporary)
            child = Mock(pid=123456789, returncode=0)
            child.poll.return_value = 0
            child.communicate.side_effect = [subprocess.TimeoutExpired("mock", .25),
                                             subprocess.TimeoutExpired("mock", .25), None]
            with patch.object(process.subprocess, "Popen", return_value=child), \
                    patch.object(process, "stop_tree", return_value={"status": "mock"}) as stop:
                result = process.run_logged(["never-launched.exe"], root, root / "run",
                                            timeout=5, stdin="one prompt", cancel_file=root / "STOP")
            self.assertFalse(result["cancelled"])
            self.assertFalse(result["timed_out"])
            self.assertEqual([c.args for c in child.communicate.call_args_list],
                             [("one prompt",), (None,), (None,)])
            self.assertTrue(all(0 < c.kwargs["timeout"] <= .25
                                for c in child.communicate.call_args_list))
            stop.assert_called_once_with(child)

    def test_real_normal_exit_with_absent_marker(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-normal-") as temporary:
            root = Path(temporary)
            result = process.run_logged([sys.executable, "-I", "-S", "-c", "print('complete')"],
                                        root, root / "run", timeout=5, cancel_file=root / "STOP")
            self.assertEqual(result["returncode"], 0)
            self.assertFalse(result["cancelled"])
            self.assertFalse(result["timed_out"])
            self.assertEqual((root / "run.stdout.log").read_text().strip(), "complete")

    def test_real_timeout_is_not_cancellation(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-timeout-") as temporary:
            root = Path(temporary)
            result = process.run_logged(
                [sys.executable, "-I", "-S", "-c", "import time;print('partial',flush=True);time.sleep(60)"],
                root, root / "run", timeout=.6, cancel_file=root / "STOP")
            self.assertFalse(result["cancelled"])
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["cleanup"]["parent_exit_confirmed"])
            self.assertEqual((root / "run.stdout.log").read_text().strip(), "partial")

    @unittest.skipUnless(os.name == "nt", "Windows Job Object owned-descendant verification")
    def test_real_cancel_preserves_output_and_cleans_only_owned_tree(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-tree-") as temporary:
            root = Path(temporary)
            marker = root / "STOP"
            stdout = root / "run.stdout.log"
            errors = []
            noticed = []

            def request_stop_after_output():
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if stdout.exists() and "ready" in stdout.read_text(encoding="utf-8"):
                        noticed.append(time.monotonic())
                        marker.touch()
                        return
                    time.sleep(.01)
                errors.append("child never emitted ready output")
                marker.touch()

            sentinel = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time;time.sleep(60)"])
            requester = threading.Thread(target=request_stop_after_output, daemon=True)
            try:
                requester.start()
                code = ("import subprocess,sys,time,json; payload=sys.stdin.read(); "
                        "child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)']); "
                        "print(json.dumps({'ready':True,'pid':child.pid,'payload':payload}),flush=True); "
                        "print('partial stderr',file=sys.stderr,flush=True); time.sleep(60)")
                with patch.object(process, "stop_tree", wraps=process.stop_tree) as stop:
                    result = process.run_logged([sys.executable, "-I", "-S", "-c", code],
                                                root, root / "run", timeout=10, stdin="only once\n",
                                                cancel_file=marker)
                completed = time.monotonic()
                requester.join(timeout=1)
                self.assertFalse(errors, errors)
                self.assertFalse(requester.is_alive())
                self.assertTrue(result["cancelled"])
                self.assertFalse(result["timed_out"])
                self.assertLess(completed - noticed[0], 3)
                self.assertEqual(stop.call_count, 1)
                self.assertEqual(stop.call_args.args[0].pid, result["pid"])
                partial = json.loads(stdout.read_text(encoding="utf-8"))
                self.assertEqual(partial["payload"], "only once\n")
                self.assertIn("partial stderr", (root / "run.stderr.log").read_text())
                self.assertTrue(result["cleanup"]["job_assigned"])
                self.assertTrue(result["cleanup"]["job_handle_closed"])
                self.assertEqual(result["cleanup"]["active_after"], 0)
                self.assertTrue(result["cleanup"]["parent_exit_confirmed"])
                self.assertFalse(windows_pid_running(result["pid"]))
                self.assertFalse(windows_pid_running(partial["pid"]))
                self.assertIsNone(sentinel.poll(), "Unrelated test-owned process must remain running")
                self.assertEqual(json.loads((root / "run.process.json").read_text()), result)
            finally:
                requester.join(timeout=6)
                sentinel.kill()
                sentinel.wait(timeout=3)


class AttackCancellationTests(unittest.TestCase):
    def run_cancelled(self, *, with_final=False, with_partial_audit=False):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-attack-") as temporary:
            root = Path(temporary)
            destination = root / "attack"
            marker = root / "STOP"
            saved_kwargs = {}

            def fake_run(argv, cwd, prefix, timeout, env, prompt, **kwargs):
                saved_kwargs.update(kwargs)
                messages = []
                if with_final:
                    messages = [
                        {"type": "system", "subtype": "init", "tools": ["StructuredOutput"]},
                        {"type": "result", "structured_output": {"code": "def solve(x,y): return 0"}},
                    ]
                out = prefix.with_suffix(".stdout.log")
                out.write_text("".join(json.dumps(m) + "\n" for m in messages) + '{"partial":',
                               encoding="utf-8")
                if with_partial_audit:
                    (destination / "bridge-audit.jsonl").write_text(
                        '{"tool":"decompile","rea":true,"error":false}\n{"tool":', encoding="utf-8")
                return {"stdout": str(out), "returncode": 1, "timed_out": False,
                        "cancelled": True, "seconds": .1}

            with patch.object(attack, "claude_command", return_value="never-launched.exe"), \
                    patch.object(attack, "run_logged", side_effect=fake_run):
                result = attack.run_attack(root, root / "target.exe", destination,
                                           seconds=10, budget_usd=1, cancel_file=marker)
            self.assertEqual(saved_kwargs, {"cancel_file": marker})
            self.assertEqual(result["status"], "cancelled")
            self.assertTrue(result["cancelled"])
            self.assertFalse((destination / "candidate.py").exists())
            self.assertFalse((destination / "explanation.txt").exists())
            self.assertTrue((destination / "attacker.stdout.log").read_text().endswith('{"partial":'))
            self.assertEqual(json.loads((destination / "result.json").read_text()), result)
            if with_partial_audit:
                self.assertEqual(result["rea_calls"], 1)
                self.assertEqual(result["tool_calls"], 1)
                self.assertEqual(result["incomplete_audit_lines"], [2])
                self.assertEqual(result["audit_parse_errors"][0]["line"], 2)
                self.assertTrue(result["audit_parse_errors"][0]["trailing_partial"])
                self.assertTrue(result["audit_parse_errors"][0]["error"])
                self.assertTrue((destination / "bridge-audit.jsonl").read_text().endswith('{"tool":'))

    def test_cancel_without_initialization_is_not_isolation_failure(self):
        self.run_cancelled()

    def test_cancel_does_not_submit_candidate_even_if_final_message_arrived(self):
        self.run_cancelled(with_final=True)

    def test_cancel_preserves_incomplete_audit_and_records_only_complete_calls(self):
        self.run_cancelled(with_partial_audit=True)

    def test_existing_marker_prevents_actual_attack_launch(self):
        with tempfile.TemporaryDirectory(prefix="antirea-cancel-attack-before-") as temporary:
            root = Path(temporary)
            marker = root / "STOP"
            marker.touch()
            destination = root / "attack"
            with patch.object(attack, "claude_command", return_value="never-launched.exe"), \
                    patch.object(process.subprocess, "Popen") as launch:
                result = attack.run_attack(root, root / "target.exe", destination,
                                           seconds=10, budget_usd=1, cancel_file=marker)
            launch.assert_not_called()
            self.assertEqual(result["status"], "cancelled")
            self.assertIsNone(result["model"])
            self.assertEqual(result["tool_calls"], 0)
            self.assertFalse((destination / "candidate.py").exists())
            self.assertTrue((destination / "attacker.process.json").exists())
            self.assertTrue((destination / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
