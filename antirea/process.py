"""Bounded owned process trees with logs and explicit cleanup evidence.

Windows uses a kill-on-close Job Object where assignment is available. Assignment
occurs immediately *after* Popen starts the child, so this is not an atomic launch
or a security sandbox. Fallback cleanup is deliberately labelled best-effort.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time


class _WindowsJob:
    """A private unnamed job; only the process owned by run_logged is assigned."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                        ("maximum_working_set", ctypes.c_size_t), ("active_process_limit", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority_class", wintypes.DWORD),
                        ("scheduling_class", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("read_operations", "write_operations", "other_operations",
                         "read_bytes", "write_bytes", "other_bytes")]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", IoCounters),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [("user_time", ctypes.c_longlong), ("kernel_time", ctypes.c_longlong),
                        ("period_user_time", ctypes.c_longlong), ("period_kernel_time", ctypes.c_longlong),
                        ("page_faults", wintypes.DWORD), ("total_processes", wintypes.DWORD),
                        ("active_processes", wintypes.DWORD), ("terminated_processes", wintypes.DWORD)]

        self.ctypes, self.Accounting = ctypes, Accounting
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                        wintypes.DWORD, ctypes.c_void_p]
        self.kernel.QueryInformationJobObject.restype = wintypes.BOOL
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        self.assigned = False
        self.error = None
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        limits = ExtendedLimits()
        limits.basic.flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise OSError(error, "SetInformationJobObject failed")

    def assign(self, child: subprocess.Popen) -> bool:
        handle = getattr(child, "_handle", None)
        if not isinstance(handle, int):
            self.error = "Popen process handle is unavailable"
        elif not self.kernel.AssignProcessToJobObject(self.handle, handle):
            self.error = f"AssignProcessToJobObject failed (Windows error {self.ctypes.get_last_error()})"
        else:
            self.assigned = True
        return self.assigned

    def active_processes(self) -> int:
        accounting = self.Accounting()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, self.ctypes.byref(accounting),
                                                    self.ctypes.sizeof(accounting), None):
            raise OSError(self.ctypes.get_last_error(), "QueryInformationJobObject failed")
        return int(accounting.active_processes)

    def terminate(self) -> None:
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise OSError(self.ctypes.get_last_error(), "TerminateJobObject failed")

    def close(self) -> bool:
        if not self.handle:
            return True
        closed = bool(self.kernel.CloseHandle(self.handle))
        if closed:
            self.handle = None
        return closed


def _owned_pid(child) -> int | None:
    pid = getattr(child, "pid", None)
    return pid if type(pid) is int and pid > 0 else None


def stop_tree(process: subprocess.Popen) -> dict:
    """Clean only this owned tree, even if its original parent already exited."""
    pid = _owned_pid(process)
    job = getattr(process, "_antirea_job", None)
    result = {"parent_pid": pid, "status": "unverified", "parent_exit_confirmed": False}
    if isinstance(job, _WindowsJob) and job.assigned:
        result.update({"method": "windows_job", "job_assigned": True,
                       "assignment_timing": "immediately_after_launch",
                       "limitations": ["Descendants created before job assignment may escape containment."]})
        try:
            result["active_before"] = job.active_processes()
            if result["active_before"]:
                job.terminate()
            deadline = time.monotonic() + 3
            while True:
                active = job.active_processes()
                if active == 0 or time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
            result["active_after"] = active
            result["status"] = "assigned_job_empty" if active == 0 else "job_termination_pending"
        except (OSError, ValueError) as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
    elif os.name == "nt":
        result.update({"method": "taskkill_fallback", "job_assigned": False,
                       "limitations": ["Fallback cannot independently verify all descendants."]})
        if pid is not None and process.poll() is None:
            try:
                killed = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        timeout=10, check=False)
                result["taskkill_returncode"] = killed.returncode
                result["status"] = "best_effort" if killed.returncode == 0 else "taskkill_failed"
            except (OSError, subprocess.TimeoutExpired) as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"
            if process.poll() is None:
                try:
                    process.kill()
                    result["parent_kill_requested"] = True
                except OSError as exc:
                    result["parent_kill_error"] = f"{type(exc).__name__}: {exc}"
        else:
            result["status"] = "parent_exited_descendants_unverified"
    else:
        import signal
        result["method"] = "posix_process_group"
        if pid is not None:
            try:
                # run_logged started a new session; the owned group can outlive
                # its original parent, so do not return merely because poll did.
                os.killpg(pid, signal.SIGKILL)
                result["status"] = "group_kill_requested"
            except ProcessLookupError:
                result["status"] = "group_absent"
            except OSError as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"
    try:
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["parent_wait_error"] = f"{type(exc).__name__}: {exc}"
    result["parent_exit_confirmed"] = process.poll() is not None
    return result


def run_logged(argv: list[str], directory: Path, log_prefix: Path,
               timeout: float = 600, env: dict[str, str] | None = None,
               stdin: str | None = None, *, cancel_file: Path | None = None) -> dict:
    """Run an owned process, optionally checking a cancellation marker every 250ms.

    Cancellation preserves partial logs and uses the same tree cleanup as timeout.
    The poll interval bounds detection while communicate is waiting, not the time
    required for operating-system process creation, stdin writes or cleanup.
    """
    log_prefix.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    options = {"start_new_session": True} if os.name != "nt" else {}
    child = None
    job = None
    job_error = None
    timed_out = False
    cancelled = False
    cleanup = {"method": "not_started", "status": "not_started", "parent_exit_confirmed": False}
    error = None
    wait_error = None
    communicated = False
    with log_prefix.with_suffix(".stdout.log").open("w", encoding="utf-8") as out, \
            log_prefix.with_suffix(".stderr.log").open("w", encoding="utf-8") as err:
        try:
            if cancel_file is not None and cancel_file.exists():
                cancelled = True
            else:
                if os.name == "nt":
                    try:
                        job = _WindowsJob()
                    except (OSError, AttributeError) as exc:
                        job_error = f"{type(exc).__name__}: {exc}"
                child = subprocess.Popen(argv, cwd=directory, env=env, stdin=subprocess.PIPE,
                                         stdout=out, stderr=err, text=True, encoding="utf-8",
                                         **options)
                if job is not None:
                    job.assign(child)
                    child._antirea_job = job
                    job_error = job.error
                if cancel_file is None:
                    child.communicate(stdin, timeout=timeout)
                    communicated = True
                else:
                    deadline = started + timeout
                    first_communication = True
                    while True:
                        if cancel_file.exists():
                            cancelled = True
                            break
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            break
                        supplied_input = stdin if first_communication else None
                        first_communication = False
                        try:
                            child.communicate(supplied_input, timeout=min(0.25, remaining))
                            communicated = True
                            break
                        except subprocess.TimeoutExpired:
                            # communicate may be retried after timeout, but input
                            # must only be supplied on its first invocation.
                            continue
        except subprocess.TimeoutExpired:
            timed_out = True
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if child is not None:
                try:
                    cleanup_result = stop_tree(child)
                    cleanup = cleanup_result if isinstance(cleanup_result, dict) else {
                        "method": "external", "status": "unverified"}
                except Exception as exc:
                    cleanup = {"method": "cleanup_error", "status": "unverified",
                               "error": f"{type(exc).__name__}: {exc}"}
            # Closing the job is an independent last-resort cleanup path, even
            # when termination/accounting or the parent wait failed above.
            if job is not None:
                try:
                    cleanup["job_handle_closed"] = job.close()
                except Exception as exc:
                    cleanup["job_close_error"] = f"{type(exc).__name__}: {exc}"
            if child is not None and not communicated:
                try:
                    child.communicate(timeout=3)
                except Exception as exc:
                    wait_error = f"{type(exc).__name__}: {exc}"
            if child is not None:
                cleanup["parent_exit_confirmed"] = child.poll() is not None
            if job_error:
                cleanup["job_setup_error"] = job_error
    result = {"argv": argv, "returncode": child.returncode if child is not None else None,
              "pid": _owned_pid(child) if child is not None else None, "timed_out": timed_out,
              "cancelled": cancelled,
              "seconds": round(time.monotonic() - started, 3),
              "stdout": str(log_prefix.with_suffix(".stdout.log")),
              "stderr": str(log_prefix.with_suffix(".stderr.log")), "cleanup": cleanup}
    if error:
        result["error"] = error
    if wait_error:
        result["post_cleanup_wait_error"] = wait_error
    log_prefix.with_suffix(".process.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

