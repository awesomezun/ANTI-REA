"""Event-driven local defender scheduling. Never runs an attacker or report code.

The scheduled precheck is cheap: stable intake, deduplication, and a dispatch lease.
An agent claims the lease before working, renews it, and releases it afterwards.
OS locks protect short transactions; leases recover after an interrupted agent.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
import uuid

from antirea.exchange import Exchange


ROOT = Path(__file__).resolve().parents[1]
OUTBOUND = Path(os.environ.get("ANTIREA_OUTBOUND_DIR", str(Path.home() / "attackerfolder")))
DISPATCH_SECONDS = 600
LEASE_SECONDS = 1800


class Busy(RuntimeError):
    pass


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextmanager
def transaction(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Busy("another controller transaction is active") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class Controller:
    def __init__(self, root=ROOT, outbound=OUTBOUND):
        self.root = Path(root).resolve()
        self.directory = self.root / ".runs/defense-loop"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state_path = self.directory / "controller.json"
        self.stop_path = self.directory / "STOP"
        self.lock_path = self.directory / "controller.lock"
        self.exchange = Exchange(self.root, self.root / "rea-analysis-reports", outbound)

    def _state(self):
        if self.state_path.exists():
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        return {"schema_version": 1, "lease": None, "retry_after": 0, "wake_requested": False}

    def _save(self, state):
        state["updated_utc"] = utc()
        write_json(self.state_path, state)

    def _require_owner(self, state, owner):
        if self.stop_path.exists():
            raise Busy("STOP marker present")
        lease = state.get("lease") or {}
        if lease.get("kind") != "agent" or lease.get("owner") != owner:
            raise Busy("claim an agent lease before this operation")
        if lease.get("expires", 0) <= time.time():
            raise Busy("agent lease expired; claim again before working")

    def precheck(self):
        """Exit nonzero when idle/stopped/busy. No model launch or build here."""
        with transaction(self.lock_path):
            state = self._state()
            if self.stop_path.exists():
                return {"status": "stopped"}
            now = time.time()
            lease = state.get("lease") or {}
            if lease.get("expires", 0) > now:
                return {"status": "busy", "kind": lease.get("kind")}
            if state.get("retry_after", 0) > now:
                return {"status": "retry_backoff"}
            scan = self.exchange.scan()
            status = self.exchange.status()
            pending = status.get("pending_reports", [])
            journal_path = self.directory / "sync-publication.json"
            journal = json.loads(journal_path.read_text(encoding="utf-8")) if journal_path.exists() else {}
            recovery = (bool(status.get("publication_pending"))
                        or journal.get("status") in {"pausing", "paused", "needs_recovery"}
                        or bool(state.get("in_progress"))
                        or lease.get("kind") == "agent")
            if not pending and not state.get("wake_requested") and not recovery:
                state["lease"] = None
                state["last_poll_utc"] = utc()
                state["last_poll_status"] = scan.get("status")
                self._save(state)
                return {"status": "idle", "scan_status": scan.get("status")}
            state["lease"] = {"kind": "dispatch", "owner": uuid.uuid4().hex,
                              "expires": now + DISPATCH_SECONDS, "created_utc": utc()}
            self._save(state)
            return {"status": "ready", "pending_reports": len(pending),
                    "wake_requested": state.get("wake_requested", False), "recovery_needed": recovery}

    def claim(self, owner):
        with transaction(self.lock_path):
            state = self._state()
            if self.stop_path.exists():
                raise Busy("STOP marker present")
            lease = state.get("lease") or {}
            if (lease.get("kind") == "agent" and lease.get("owner") != owner
                    and lease.get("expires", 0) > time.time()):
                raise Busy("another agent owns this cycle")
            state["lease"] = {"kind": "agent", "owner": owner,
                              "expires": time.time() + LEASE_SECONDS, "claimed_utc": utc()}
            # Keep a durable reason to wake if the worker crashes after claiming
            # a retry-only job or after acknowledging its last incoming report.
            state["in_progress"] = {"owner": owner, "claimed_utc": utc()}
            self._save(state)
            return {"status": "claimed", "owner": owner, "lease_seconds": LEASE_SECONDS}

    def heartbeat(self, owner):
        with transaction(self.lock_path):
            state = self._state()
            self._require_owner(state, owner)
            state["lease"]["expires"] = time.time() + LEASE_SECONDS
            self._save(state)
            return {"status": "renewed", "owner": owner}

    def release(self, owner, *, retry=False, summary=""):
        with transaction(self.lock_path):
            state = self._state()
            lease = state.get("lease") or {}
            if lease.get("owner") != owner:
                raise Busy("cannot release another agent's lease")
            state["lease"] = None
            state["in_progress"] = None
            state["wake_requested"] = bool(retry)
            state["retry_after"] = time.time() + 900 if retry else 0
            state["last_cycle"] = {"ended_utc": utc(), "summary": summary,
                                   "retry_requested": bool(retry)}
            self._save(state)
            return {"status": "released", "retry_requested": bool(retry)}

    def stop(self):
        # Independent of the controller lock so publication/build coordination
        # cannot prevent an operator stop from becoming visible immediately.
        try:
            with self.stop_path.open("x", encoding="utf-8") as stream:
                stream.write("User requested stop. Do not remove without explicit resume.\n")
        except FileExistsError:
            pass
        return {"status": "stopped", "marker": str(self.stop_path)}

    def status(self):
        with transaction(self.lock_path):
            return {"status": "stopped" if self.stop_path.exists() else "active",
                    "controller": self._state(), "exchange": self.exchange.status()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--outbound", type=Path, default=OUTBOUND)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("precheck", "status", "stop"):
        sub.add_parser(name)
    for name in ("claim", "heartbeat", "release"):
        command = sub.add_parser(name)
        command.add_argument("--owner", required=True)
        if name == "release":
            command.add_argument("--retry", action="store_true")
            command.add_argument("--summary", default="")
    args = parser.parse_args(argv)
    try:
        controller = Controller(args.root, args.outbound)
        if args.command in {"precheck", "status", "stop"}:
            result = getattr(controller, args.command)()
        elif args.command == "release":
            result = controller.release(args.owner, retry=args.retry, summary=args.summary)
        else:
            result = getattr(controller, args.command)(args.owner)
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return int(args.command == "precheck" and result["status"] != "ready")


if __name__ == "__main__":
    raise SystemExit(main())
