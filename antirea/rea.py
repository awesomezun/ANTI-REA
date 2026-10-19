"""Small stdlib-only client for one persistent, locally installed REA MCP server.

This is a transport adapter, not an agent sandbox. Callers must restrict the
tools/arguments they expose to an attack agent. Full REA results are retained in
the trusted log directory, including errors, limitations and timings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
from typing import Any


class ReaError(RuntimeError):
    """REA transport, protocol, configuration or explicitly checked tool failure."""


def load_environment(project_root: str | Path) -> tuple[dict[str, Any], dict[str, str]]:
    root = Path(project_root).resolve()
    config_path = root / ".tools" / "rea" / "environment.json"
    if not config_path.is_file():
        raise ReaError("REA is not bootstrapped; run scripts/bootstrap_rea.ps1 first.")
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    for key in ("node", "entry", "ghidra_install_dir", "java_home"):
        if not isinstance(config.get(key), str) or not Path(config[key]).exists():
            raise ReaError(f"Missing REA environment path: {key}")
    env = dict(os.environ)
    env.update(
        GHIDRA_INSTALL_DIR=config["ghidra_install_dir"],
        JAVA_HOME=config["java_home"],
        REA_ANALYSIS_PROVIDER="ghidra",
        REA_GHIDRA_STARTUP_TIMEOUT_MS="600000",
        GHIDRA_HEADLESS_MAXMEM="2G",
    )
    env["PATH"] = os.pathsep.join(
        (str(Path(config["node"]).parent), str(Path(config["java_home"]) / "bin"), env.get("PATH", ""))
    )
    return config, env


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class ReaSession:
    """A single imported target, shared across serial MCP tool calls.

    ``call`` returns the exact MCP CallToolResult (including ``isError``).
    ``result_payload`` extracts its JSON delivery without discarding Evidence.
    The initial Ghidra import happens on the first analysis query, not open_binary.
    """

    def __init__(self, project_root: str | Path, log_dir: str | Path, timeout_s: float = 600):
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.project_root = Path(project_root).resolve()
        self.log_dir = Path(log_dir).resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s
        self.config, self.environment = load_environment(self.project_root)
        self.process: subprocess.Popen[str] | None = None
        self._stderr: Any = None
        self._queue: queue.Queue[Any] = queue.Queue()
        self._lock = threading.RLock()
        self._counter = 0
        self._closed = False
        self._opened = False
        self.cleanup_status: dict[str, Any] | None = None

    def __enter__(self) -> "ReaSession":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def start(self) -> None:
        if self.process is not None:
            return
        if self._closed:
            raise ReaError("A closed REA session cannot be restarted.")
        command = [self.config["node"], self.config["entry"], "mcp"]
        self._stderr = (self.log_dir / "server.stderr.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            command, cwd=self.project_root, env=self.environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr,
            text=True, encoding="utf-8", errors="strict", bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        _write_json(self.log_dir / "server.json", {
            "command": command, "pid": self.process.pid,
            "rea_version": self.config.get("rea_version"),
            "rea_commit": self.config.get("rea_commit"),
            "ghidra_install_dir": self.config["ghidra_install_dir"],
            "java_home": self.config["java_home"],
        })
        threading.Thread(target=self._read_stdout, daemon=True, name="rea-mcp-reader").start()
        try:
            self.request("initialize", {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "antirea-benchmark", "version": "0.1.0"},
            }, timeout_s=min(self.timeout_s, 60))
            self.notify("notifications/initialized", {})
        except BaseException:
            self.close()
            raise

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            while True:
                # REA can return a full inventory. Bound transport memory while
                # retaining the fact that an overlarge response was not observed.
                line = self.process.stdout.readline(128 * 1024 * 1024 + 1)
                if not line:
                    self._queue.put(ReaError("REA MCP stdout closed."))
                    return
                if len(line) > 128 * 1024 * 1024:
                    raise ReaError("REA MCP response exceeded the 128 Mi-character transport limit.")
                if line.strip():
                    self._queue.put(json.loads(line))
        except BaseException as exc:
            self._queue.put(ReaError(f"REA MCP output reader failed: {exc}"))

    def _send(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None or self.process.poll() is not None:
            raise ReaError("REA MCP server is not running.")
        self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        with self._lock:
            self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict[str, Any], timeout_s: float | None = None) -> dict[str, Any]:
        with self._lock:
            self._counter += 1
            request_id = self._counter
            payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            started = time.monotonic()
            timeout = self.timeout_s if timeout_s is None else timeout_s
            record: dict[str, Any] = {"request": payload, "timeout_s": timeout}
            try:
                self._send(payload)
                deadline = started + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise queue.Empty
                    message = self._queue.get(timeout=remaining)
                    if isinstance(message, BaseException):
                        raise message
                    if not isinstance(message, dict):
                        raise ReaError("REA returned a non-object JSON-RPC message.")
                    if message.get("id") == request_id and ("result" in message or "error" in message):
                        record["response"] = message
                        if "error" in message:
                            raise ReaError(f"REA JSON-RPC error: {message['error']}")
                        result = message.get("result")
                        if not isinstance(result, dict):
                            raise ReaError("REA returned a non-object JSON-RPC result.")
                        return result
                    record.setdefault("notifications", []).append(message)
                    if "method" in message and "id" in message:
                        self._send({"jsonrpc": "2.0", "id": message["id"], "error": {
                            "code": -32601, "message": "Benchmark client does not handle server requests."
                        }})
            except queue.Empty as exc:
                record["timeout"] = True
                try:
                    self.notify("notifications/cancelled", {"requestId": request_id, "reason": "ANTI-REA time budget exceeded"})
                except (OSError, ReaError):
                    pass
                raise ReaError(f"REA {method} timed out after {timeout}s; results are incomplete.") from exc
            except BaseException as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                record["elapsed_s"] = time.monotonic() - started
                label = re.sub(r"[^A-Za-z0-9_-]", "_", str(params.get("name", method)))[:100]
                _write_json(self.log_dir / f"{request_id:04d}-{label}.json", record)

    def call(self, tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.process is None:
            self.start()
        return self.request("tools/call", {"name": tool_name, "arguments": arguments or {}})

    def list_tools(self) -> list[dict[str, Any]]:
        if self.process is None:
            self.start()
        tools: list[dict[str, Any]] = []
        params: dict[str, Any] = {}
        while True:
            result = self.request("tools/list", params)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
            params = {"cursor": cursor}

    def open_binary(self, binary_path: str | Path) -> dict[str, Any]:
        result = self.call("open_binary", {"path": str(Path(binary_path).resolve()), "provider_id": "ghidra"})
        if result.get("isError"):
            raise ReaError(f"REA open_binary failed: {self.result_payload(result)}")
        self._opened = True
        return result

    @staticmethod
    def result_payload(result: dict[str, Any]) -> Any:
        if "structuredContent" in result:
            return result["structuredContent"]
        texts = [part["text"] for part in result.get("content", []) if part.get("type") == "text"]
        if len(texts) == 1:
            try:
                return json.loads(texts[0])
            except json.JSONDecodeError:
                return texts[0]
        return result

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            status: dict[str, Any] = {"close_binary_attempted": False, "forced_terminate": False}
            if self.process is not None:
                if self._opened and self.process.poll() is None:
                    status["close_binary_attempted"] = True
                    try:
                        response = self.request("tools/call", {"name": "close_binary", "arguments": {}}, timeout_s=30)
                        status["close_binary_is_error"] = bool(response.get("isError"))
                    except (OSError, ReaError) as exc:
                        status["close_error"] = str(exc)
                if self.process.stdin is not None and not self.process.stdin.closed:
                    try:
                        self.process.stdin.close()
                    except OSError:
                        pass
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    status["forced_terminate"] = True
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=10)
                status["returncode"] = self.process.returncode
                # A forced stop is not proof that external process cleanup completed.
                status["provider_cleanup_confirmed"] = (
                    status.get("close_binary_attempted", False)
                    and not status.get("close_binary_is_error", True)
                    and not status.get("close_error")
                    and not status["forced_terminate"]
                    and self.process.returncode == 0
                )
            if self._stderr is not None:
                self._stderr.close()
            self.cleanup_status = status
            _write_json(self.log_dir / "cleanup.json", status)


def run_cli(project_root: str | Path, arguments: list[str], log_dir: str | Path,
            timeout_s: float = 120) -> dict[str, Any]:
    """Run a diagnostic CLI command and retain exact output; no shell interpolation."""
    config, env = load_environment(project_root)
    destination = Path(log_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    command = [config["node"], config["entry"], *arguments]
    started = time.monotonic()
    record: dict[str, Any] = {"command": command, "timeout_s": timeout_s}
    try:
        completed = subprocess.run(command, cwd=Path(project_root).resolve(), env=env,
                                   capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   timeout=timeout_s,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        record.update(returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
    except subprocess.TimeoutExpired as exc:
        record.update(timeout=True, stdout=str(exc.stdout or ""), stderr=str(exc.stderr or ""))
    record["elapsed_s"] = time.monotonic() - started
    _write_json(destination / "cli.json", record)
    return record
