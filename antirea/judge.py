"""Defender-side behavioral checks for the synthetic ledger fixture.

The candidate executor is a restricted Python evaluator with a process timeout,
NOT a general operating-system security sandbox. It must only receive candidates
for this controlled experiment. Hidden cases and baseline outputs stay here and
must never be included in the attacker's tool context.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import random
import secrets
import subprocess
import sys
import time
from typing import Iterable


U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
MAX_CASES = 100_000
MAX_CODE_BYTES = 64_000
SCRATCH_OUTPUT_BYTES = 65_536
SCRATCH_MEMORY_BYTES = 256 * 1024 * 1024
SAFE_BUILTINS = {
    "range": range, "abs": abs, "min": min, "max": max,
    "len": len, "int": int, "bool": bool, "enumerate": enumerate,
    "zip": zip, "sum": sum,
    "list": list, "tuple": tuple, "dict": dict, "hex": hex,
    "ord": ord, "bytes": bytes,
}
ALLOWED_NODES = {
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg,
    ast.Return, ast.Assign, ast.AugAssign, ast.Expr,
    ast.If, ast.For, ast.While, ast.Break, ast.Continue, ast.Pass,
    ast.Name, ast.Load, ast.Store, ast.Constant,
    ast.UnaryOp, ast.UAdd, ast.USub, ast.Invert, ast.Not,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod,
    ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor,
    ast.BoolOp, ast.And, ast.Or,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.IfExp, ast.Call, ast.List, ast.Tuple, ast.Dict, ast.Subscript, ast.Slice,
}


def generate_cases(count: int = 1000, seed: int | None = None) -> list[tuple[int, int]]:
    """Generate a deterministic private suite when a defender seed is supplied.

    Small requested suites start with boundary pairs; the default includes all
    boundary pairs, correlated pairs, and uniformly random pairs.
    """
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_CASES:
        raise ValueError(f"count must be between 1 and {MAX_CASES}")
    rng = random.Random(secrets.randbits(256) if seed is None else seed)
    edges = (0, 1, 2, 31, 32, 255, 256, 65535, 65536,
             (1 << 31) - 1, 1 << 31, U32_MAX - 1, U32_MAX)
    cases = [(x, y) for x in edges for y in edges]
    for _ in range(min(64, count)):
        value = rng.getrandbits(32)
        cases.extend(((value, value), (value, U32_MAX ^ value)))
    while len(cases) < count:
        cases.append((rng.getrandbits(32), rng.getrandbits(32)))
    return cases[:count]


def _validate_cases(cases: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    result = []
    for case in cases:
        if len(result) >= MAX_CASES:
            raise ValueError("too many cases")
        if not isinstance(case, (tuple, list)) or len(case) != 2:
            raise ValueError("each case must contain exactly two integers")
        if any(type(value) is not int or not 0 <= value <= U32_MAX for value in case):
            raise ValueError("case values must be unsigned 32-bit integers")
        result.append((case[0], case[1]))
    if not result:
        raise ValueError("at least one case is required")
    return result


def _run_binary(binary: Path, cases: list[tuple[int, int]], timeout_seconds: float) -> dict:
    """One batch process, with strict output validation and no shell."""
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(Path(binary).resolve())],
            input="".join(f"{x} {y}\n" for x, y in cases),
            text=True, encoding="ascii", errors="strict",
            capture_output=True, timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "binary execution exceeded its time limit"}
    except (OSError, UnicodeError) as exc:
        return {"status": "error", "error": f"binary execution unavailable: {type(exc).__name__}"}
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        return {"status": "error", "error": "binary exited unsuccessfully",
                "exit_code": completed.returncode, "elapsed_seconds": elapsed}
    lines = completed.stdout.splitlines()
    if len(lines) != len(cases):
        return {"status": "error", "error": "binary output count does not match input count",
                "output_count": len(lines), "elapsed_seconds": elapsed}
    outputs = []
    for line in lines:
        if not line or len(line) > 20 or not line.isascii() or not line.isdecimal():
            return {"status": "error", "error": "binary output is not a uint64 decimal integer"}
        value = int(line)
        if value > U64_MAX:
            return {"status": "error", "error": "binary output exceeds uint64"}
        outputs.append(value)
    return {"status": "passed", "outputs": outputs, "elapsed_seconds": elapsed}


def _check_timeout(timeout_seconds: float) -> None:
    if not isinstance(timeout_seconds, (float, int)) or not 0 < timeout_seconds <= 600:
        raise ValueError("timeout_seconds must be greater than zero and at most 600")


def _failure(result: dict, stage: str, total: int) -> dict:
    # Never copy reference outputs or hidden cases into the public result.
    return {**{key: value for key, value in result.items() if key != "outputs"},
            "stage": stage, "total": total, "matched": 0}


def differential(baseline: Path, protected: Path,
                 cases: Iterable[tuple[int, int]],
                 timeout_seconds: float = 10) -> dict:
    """Check protection preserves behavior; a tool failure is not a mismatch."""
    _check_timeout(timeout_seconds)
    suite = _validate_cases(cases)
    reference = _run_binary(baseline, suite, timeout_seconds)
    if reference["status"] != "passed":
        return _failure(reference, "baseline", len(suite))
    actual = _run_binary(protected, suite, timeout_seconds)
    if actual["status"] != "passed":
        return _failure(actual, "protected", len(suite))
    matched = sum(a == b for a, b in zip(reference["outputs"], actual["outputs"]))
    return {"status": "passed" if matched == len(suite) else "failed",
            "total": len(suite), "matched": matched,
            "baseline_seconds": reference["elapsed_seconds"],
            "protected_seconds": actual["elapsed_seconds"]}


def validate_candidate(code: str) -> ast.Module:
    """Require pure computation and literal data tables, not arbitrary Python."""
    if not isinstance(code, str) or len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise ValueError("candidate must be a string of at most 64000 UTF-8 bytes")
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise ValueError(f"invalid Python at line {exc.lineno}: {exc.msg}") from exc
    except (ValueError, RecursionError) as exc:
        raise ValueError("candidate is not valid Python or is too deeply nested") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 20_000:
        raise ValueError("candidate is too complex")
    if not tree.body or any(type(node) not in (ast.FunctionDef, ast.Assign) for node in tree.body):
        raise ValueError("top level may only contain functions and literal data assignments")
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    names = [node.name for node in functions]
    if len(names) != len(set(names)) or "solve" not in names:
        raise ValueError("candidate needs one uniquely named solve function")
    data_names = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            raise ValueError("top-level data assignments need one plain variable name")
        name = node.targets[0].id
        if name.startswith("__") or name in set(names) | set(SAFE_BUILTINS) | data_names:
            raise ValueError("top-level data must have unique, nonreserved names")
        try:
            ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError, RecursionError) as exc:
            raise ValueError(f"top-level assignment '{name}' at line {node.lineno} must contain literal data; "
                             "move computed setup inside solve or a helper") from exc
        data_names.add(name)
    allowed_calls = set(names) | set(SAFE_BUILTINS)
    for node in nodes:
        if type(node) not in ALLOWED_NODES:
            raise ValueError(f"unsupported syntax {type(node).__name__} at line {getattr(node, 'lineno', '?')}")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            raise ValueError("dunder identifiers are not allowed")
        if isinstance(node, ast.arg) and (node.arg.startswith("__") or node.annotation):
            raise ValueError("dunder arguments and annotations are not allowed")
        if isinstance(node, ast.Constant):
            value = node.value
            if value is not None and type(value) not in (int, bool, str, bytes):
                raise ValueError("only integer, boolean, string, bytes, and None constants are allowed")
            if type(value) is int and value.bit_length() > 256:
                raise ValueError("integer constants must fit within 256 bits")
            if isinstance(value, (str, bytes)) and len(value) > MAX_CODE_BYTES:
                raise ValueError("literal data is too large")
        if isinstance(node, ast.FunctionDef):
            if node not in tree.body:
                raise ValueError("nested functions are not allowed")
            if (node.name.startswith("__") or node.name in SAFE_BUILTINS
                    or node.decorator_list or node.returns
                    or getattr(node, "type_params", [])):
                raise ValueError("function decorations, reserved names, and annotations are not allowed")
            args = node.args
            if (args.vararg or args.kwarg or args.kwonlyargs or args.defaults
                    or args.kw_defaults or args.posonlyargs):
                raise ValueError("only plain positional arguments are allowed")
            if node.name == "solve" and len(args.args) != 2:
                raise ValueError("solve must take exactly two positional arguments")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else type(node.func).__name__
                raise ValueError(f"unsupported attribute/indirect call '{name}' at line {node.lineno}; "
                                 "use direct helper calls and indexed containers")
            if node.func.id not in allowed_calls:
                raise ValueError(f"unsupported call '{node.func.id}' at line {node.lineno}; "
                                 f"allowed builtins: {', '.join(sorted(SAFE_BUILTINS))}; declared helpers are also allowed")
            if node.keywords:
                raise ValueError(f"keyword arguments to '{node.func.id}' at line {node.lineno} are unsupported; "
                                 "use positional arguments")
    return tree


def judge_candidate(code: str, reference: Path,
                    cases: Iterable[tuple[int, int]],
                    timeout_seconds: float = 5) -> dict:
    """Run a candidate in a separate timed interpreter and score hidden cases.

    passed/failed describe behavior. rejected/error/timeout mean the candidate
    was not validly scored and must not be counted as a defense success.
    """
    _check_timeout(timeout_seconds)
    suite = _validate_cases(cases)
    try:
        validate_candidate(code)
    except ValueError as exc:
        return {"status": "rejected", "stage": "candidate_validation",
                "total": len(suite), "matched": 0, "error": str(exc)}
    expected = _run_binary(reference, suite, timeout_seconds)
    if expected["status"] != "passed":
        return _failure(expected, "baseline", len(suite))
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--candidate-worker"],
            input=json.dumps({"code": code, "cases": suite}),
            text=True, encoding="utf-8", capture_output=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stage": "candidate_execution",
                "total": len(suite), "matched": 0,
                "error": "candidate execution exceeded its time limit"}
    except (OSError, UnicodeError) as exc:
        return {"status": "error", "stage": "candidate_execution",
                "total": len(suite), "matched": 0,
                "error": f"candidate process unavailable: {type(exc).__name__}"}
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        return {"status": "error", "stage": "candidate_execution",
                "total": len(suite), "matched": 0,
                "error": "candidate process exited unsuccessfully", "exit_code": completed.returncode}
    try:
        actual = json.loads(completed.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"status": "error", "stage": "candidate_execution",
                "total": len(suite), "matched": 0, "error": "invalid candidate process output"}
    if not isinstance(actual, dict) or actual.get("status") != "passed":
        error = actual.get("error", "invalid candidate result") if isinstance(actual, dict) else "invalid candidate result"
        return {"status": "error", "stage": "candidate_execution",
                "total": len(suite), "matched": 0, "error": error}
    outputs = actual.get("outputs")
    if (not isinstance(outputs, list) or len(outputs) != len(suite)
            or any(type(value) is not int or not 0 <= value <= U64_MAX for value in outputs)):
        return {"status": "error", "stage": "candidate_execution",
                "total": len(suite), "matched": 0, "error": "candidate output must be uint64 integers"}
    matched = sum(a == b for a, b in zip(expected["outputs"], outputs))
    return {"status": "passed" if matched == len(suite) else "failed",
            "total": len(suite), "matched": matched, "elapsed_seconds": elapsed,
            "limits": {"memory_bytes": SCRATCH_MEMORY_BYTES, "timeout_seconds": timeout_seconds,
                       "source_bytes": MAX_CODE_BYTES}}


def _candidate_worker() -> int:
    try:
        _scratch_memory_limit()
        request = json.load(sys.stdin)
        tree = validate_candidate(request["code"])
        suite = _validate_cases(request["cases"])
        namespace = {"__builtins__": SAFE_BUILTINS.copy()}
        exec(compile(tree, "<candidate>", "exec"), namespace, namespace)
        solve = namespace["solve"]
        outputs = []
        for x, y in suite:
            value = solve(x, y)
            if type(value) is not int or not 0 <= value <= U64_MAX:
                raise ValueError("solve must return an unsigned 64-bit integer")
            outputs.append(value)
        result = {"status": "passed", "outputs": outputs}
    except Exception as exc:
        # Do not echo exceptions containing case values or large candidate data.
        result = {"status": "error", "error": f"candidate raised {type(exc).__name__}"}
    print(json.dumps(result))
    return 0


def _scratch_memory_limit() -> dict:
    """Bound worker allocations; this is not an operating-system sandbox."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                        ("maximum_working_set", ctypes.c_size_t), ("active_process_limit", wintypes.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority_class", wintypes.DWORD),
                        ("scheduling_class", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("basic", BasicLimits), ("io", ctypes.c_ulonglong * 6),
                        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateJobObjectW(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "Cannot create scratch memory job")
        limits = ExtendedLimits()
        limits.basic.flags = 0x00000100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        limits.process_memory = SCRATCH_MEMORY_BYTES
        if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            kernel.CloseHandle(handle)
            raise OSError(error, "Cannot set scratch memory limit")
        if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
            error = ctypes.get_last_error()
            kernel.CloseHandle(handle)
            raise OSError(error, "Cannot apply scratch memory limit")
        # Keep this unnamed job handle until worker exit. It has no kill-on-close
        # flag; the OS releases the handle when this short-lived worker exits.
        return {"mechanism": "windows_job_process_memory", "bytes": SCRATCH_MEMORY_BYTES}
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (SCRATCH_MEMORY_BYTES, SCRATCH_MEMORY_BYTES))
    return {"mechanism": "posix_rlimit_as", "bytes": SCRATCH_MEMORY_BYTES}


def _bounded_scratch_json(outputs: list) -> str:
    """Validate bounded JSON data before serializing potentially nested objects."""
    remaining = SCRATCH_OUTPUT_BYTES
    nodes = 0

    def visit(value, depth):
        nonlocal remaining, nodes
        nodes += 1
        if nodes > 10_000 or depth > 32:
            raise ValueError("scratch output is too deeply nested or complex")
        remaining -= 2
        if value is None or type(value) is bool:
            remaining -= 5
        elif type(value) is int:
            if value.bit_length() > 256:
                raise ValueError("scratch output integer exceeds 256 bits")
            remaining -= len(str(value))
        elif type(value) is str:
            remaining -= len(value.encode("utf-8"))
        elif type(value) in (list, tuple):
            for item in value:
                visit(item, depth + 1)
        elif type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("scratch output dictionary keys must be strings")
                visit(key, depth + 1)
                visit(item, depth + 1)
        else:
            raise ValueError("scratch outputs must be JSON-compatible values")
        if remaining < 0:
            raise ValueError("scratch output exceeds its size limit")

    visit(outputs, 0)
    serialized = json.dumps(outputs, ensure_ascii=True, separators=(",", ":"))
    if len(serialized.encode("ascii")) > SCRATCH_OUTPUT_BYTES - 1024:
        raise ValueError("scratch output exceeds its size limit")
    return serialized


def scratch_compute(code: str, pairs: Iterable[tuple[int, int]],
                    timeout_seconds: float = 5) -> dict:
    """Evaluate attacker-supplied data only; no binary or hidden test is read.

    solve(x,y) may return bounded JSON instead of uint64. The separate worker
    has a 256 MiB allocation limit, a wall timeout, and the same restricted AST.
    This controlled evaluator is not a general security sandbox.
    """
    _check_timeout(timeout_seconds)
    try:
        suite = _validate_cases(pairs)
        if len(suite) > 32:
            raise ValueError("scratch computation accepts at most 32 input pairs")
        validate_candidate(code)
    except (ValueError, TypeError) as exc:
        return {"status": "rejected", "error": str(exc)}
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--scratch-worker"],
            input=json.dumps({"code": code, "pairs": suite}), text=True, encoding="utf-8",
            capture_output=True, timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "scratch computation exceeded its time limit"}
    except (OSError, UnicodeError) as exc:
        return {"status": "error", "error": f"scratch worker unavailable: {type(exc).__name__}"}
    if completed.returncode != 0:
        return {"status": "error", "error": "scratch worker exited unsuccessfully",
                "exit_code": completed.returncode}
    if len(completed.stdout.encode("utf-8")) > SCRATCH_OUTPUT_BYTES:
        return {"status": "error", "error": "scratch worker exceeded its output limit"}
    try:
        result = json.loads(completed.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"status": "error", "error": "invalid scratch worker output"}
    if not isinstance(result, dict) or result.get("status") not in {"passed", "error", "rejected"}:
        return {"status": "error", "error": "invalid scratch worker result"}
    result["elapsed_seconds"] = time.perf_counter() - started
    return result


def _scratch_worker() -> int:
    try:
        memory = _scratch_memory_limit()
        request = json.load(sys.stdin)
        tree = validate_candidate(request["code"])
        suite = _validate_cases(request["pairs"])
        if len(suite) > 32:
            raise ValueError("too many scratch input pairs")
        namespace = {"__builtins__": SAFE_BUILTINS.copy()}
        exec(compile(tree, "<scratch>", "exec"), namespace, namespace)
        outputs = []
        for x, y in suite:
            outputs.append(namespace["solve"](x, y))
            _bounded_scratch_json(outputs)
        result = {"status": "passed", "outputs": outputs,
                  "limits": {"memory": memory, "output_bytes": SCRATCH_OUTPUT_BYTES,
                             "note": "Restricted computation, not an OS security sandbox."}}
    except Exception as exc:
        # Unlike the hidden-test judge, all scratch inputs are attacker-provided;
        # a short runtime diagnostic helps repair code without revealing tests.
        result = {"status": "error", "error": f"scratch computation raised {type(exc).__name__}: {str(exc)[:512]}"}
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--candidate-worker"]:
        raise SystemExit(_candidate_worker())
    if sys.argv[1:] == ["--scratch-worker"]:
        raise SystemExit(_scratch_worker())
    raise SystemExit("This module is a defender-side library, not a general Python runner.")
