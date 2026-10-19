import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from antirea import process


def windows_pid_running(pid):
    """Inspect exactly one PID emitted by the child owned by this test."""
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: no such PID
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


class ProcessManifestTests(unittest.TestCase):
    def test_launch_failure_still_writes_manifest_and_logs(self):
        with tempfile.TemporaryDirectory(prefix="antirea-launch-test-") as temporary:
            root = Path(temporary)
            result = process.run_logged([str(root / "nonexistent-program.exe")], root, root / "launch", timeout=1)
            self.assertIsNone(result["returncode"])
            self.assertIsNone(result["pid"])
            self.assertIn("FileNotFoundError", result["error"])
            self.assertFalse(result["timed_out"])
            saved = json.loads((root / "launch.process.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["error"], result["error"])
            self.assertTrue((root / "launch.stdout.log").exists())
            self.assertTrue((root / "launch.stderr.log").exists())

    def test_second_timeout_still_writes_manifest(self):
        with tempfile.TemporaryDirectory(prefix="antirea-wait-test-") as temporary:
            root = Path(temporary)
            child = Mock()
            child.pid = 123456789
            child.returncode = None
            child.poll.return_value = None
            child.communicate.side_effect = subprocess.TimeoutExpired("unit-test", 1)
            with patch("antirea.process.subprocess.Popen", return_value=child), \
                    patch("antirea.process.stop_tree", return_value={"method": "mock", "status": "unverified"}):
                result = process.run_logged(["never-launched.exe"], root, root / "wait", timeout=1)
            self.assertTrue(result["timed_out"])
            self.assertIn("TimeoutExpired", result["post_cleanup_wait_error"])
            self.assertFalse(result["cleanup"]["parent_exit_confirmed"])
            self.assertTrue((root / "wait.process.json").exists())

    def test_normal_command_records_pid_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="antirea-normal-test-") as temporary:
            root = Path(temporary)
            result = process.run_logged([sys.executable, "-I", "-S", "-c", "print('owned test')"],
                                        root, root / "normal", timeout=5)
            self.assertEqual(result["returncode"], 0)
            self.assertIsInstance(result["pid"], int)
            self.assertTrue(result["cleanup"]["parent_exit_confirmed"])
            self.assertEqual((root / "normal.stdout.log").read_text(encoding="utf-8").strip(), "owned test")
            if os.name == "nt":
                self.assertTrue(result["cleanup"]["job_assigned"])
                self.assertTrue(result["cleanup"]["job_handle_closed"])

    @unittest.skipUnless(os.name == "nt", "Windows fallback test")
    def test_failed_job_assignment_is_reported_without_containment_claim(self):
        def fail_assignment(job, child):
            job.error = "unit-test assignment failure"
            return False

        with tempfile.TemporaryDirectory(prefix="antirea-job-fallback-test-") as temporary:
            root = Path(temporary)
            with patch.object(process._WindowsJob, "assign", fail_assignment):
                result = process.run_logged([sys.executable, "-I", "-S", "-c", "pass"],
                                            root, root / "fallback", timeout=5)
            self.assertEqual(result["returncode"], 0)
            self.assertFalse(result["cleanup"]["job_assigned"])
            self.assertEqual(result["cleanup"]["method"], "taskkill_fallback")
            self.assertIn("unverified", result["cleanup"]["status"])
            self.assertEqual(result["cleanup"]["job_setup_error"], "unit-test assignment failure")

    @unittest.skipUnless(os.name == "nt", "Windows fallback test")
    def test_taskkill_failure_is_not_reported_as_verified_tree_cleanup(self):
        child = Mock()
        child.pid = 123456789
        child.poll.side_effect = [None, None, 0]
        with patch("antirea.process.subprocess.run", return_value=Mock(returncode=1)) as kill:
            cleanup = process.stop_tree(child)
        self.assertEqual(kill.call_args.args[0], ["taskkill", "/PID", "123456789", "/T", "/F"])
        self.assertEqual(cleanup["status"], "taskkill_failed")
        self.assertEqual(cleanup["taskkill_returncode"], 1)
        self.assertTrue(cleanup["parent_kill_requested"])
        self.assertTrue(cleanup["parent_exit_confirmed"])
        child.kill.assert_called_once_with()

    @unittest.skipUnless(os.name == "nt", "Windows Job Object test")
    def test_windows_job_timeout_terminates_exact_child_pid(self):
        with tempfile.TemporaryDirectory(prefix="antirea-owned-tree-test-") as temporary:
            root = Path(temporary)
            code = ("import subprocess,sys,time; "
                    "child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)']); "
                    "print(child.pid,flush=True); time.sleep(60)")
            result = process.run_logged([sys.executable, "-I", "-S", "-c", code],
                                        root, root / "tree", timeout=1)
            pid = int((root / "tree.stdout.log").read_text(encoding="utf-8").strip())
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["cleanup"]["job_assigned"])
            self.assertEqual(result["cleanup"]["method"], "windows_job")
            self.assertEqual(result["cleanup"]["active_after"], 0)
            self.assertTrue(result["cleanup"]["parent_exit_confirmed"])
            self.assertFalse(windows_pid_running(result["pid"]))
            self.assertFalse(windows_pid_running(pid))

    @unittest.skipUnless(os.name == "nt", "Windows Job Object test")
    def test_normal_parent_exit_cleans_lingering_exact_child_pid(self):
        with tempfile.TemporaryDirectory(prefix="antirea-owned-orphan-test-") as temporary:
            root = Path(temporary)
            code = ("import subprocess,sys; "
                    "child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(60)']); "
                    "print(child.pid,flush=True)")
            result = process.run_logged([sys.executable, "-I", "-S", "-c", code],
                                        root, root / "orphan", timeout=5)
            pid = int((root / "orphan.stdout.log").read_text(encoding="utf-8").strip())
            self.assertEqual(result["returncode"], 0)
            self.assertFalse(result["timed_out"])
            self.assertTrue(result["cleanup"]["job_assigned"])
            self.assertEqual(result["cleanup"]["active_after"], 0)
            self.assertFalse(windows_pid_running(pid))


if __name__ == "__main__":
    unittest.main()
