"""Bounded, non-executing filesystem exchange for an external defender loop.

Incoming files and their claims are untrusted. This module neither interprets
instructions in reports nor runs executables, agents, tests, or network tools.
Publishing requires an explicit local gate attestation and an independently
paused synchronizer. Three public files are not an atomic filesystem bundle;
the caller MUST keep synchronization paused until commit succeeds.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sys
import time
import uuid


PUBLIC_FILES = ("app.exe", "README.txt", "manifest.json")
TEXT_SUFFIXES = {".md", ".txt", ".json", ".jsonl", ".c", ".h", ".cpp", ".hpp",
                 ".asm", ".ll", ".log", ".csv", ".py", ".pyi", ".ps1", ".sh",
                 ".js", ".ts", ".rs", ".java", ".cs", ".go", ".lua", ".bat", ".cmd"}
SYNC_METADATA = {".stfolder", ".stversions", ".stignore"}
SHA = re.compile(r"[a-f0-9]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
DEFAULT_README = """Protected application handoff

Platform: Windows x86-64 console application.
File: app.exe. Verify SHA-256 and byte size against manifest.json before use.
Input: one space-separated pair of unsigned 32-bit decimal integers per line.
Output: one unsigned 64-bit decimal integer per input pair. EOF terminates input.
Keep analysis outputs outside this incoming synchronization folder.
Record the input artifact's SHA-256 and artifact_id in every returned report.
"""


class ExchangeError(ValueError):
    """An exchange input or state cannot safely be accepted."""


class ExchangeBusy(ExchangeError):
    """Another process temporarily holds the operating-system exchange lock."""


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ExchangeError("duplicate JSON object key")
            result[key] = value
        return result

    def constant(_):
        raise ExchangeError("non-finite JSON number")

    try:
        return json.loads(_text(data), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise ExchangeError("malformed JSON: " + str(exc)[:160]) from exc


def _text(data: bytes) -> str:
    try:
        value = data.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise ExchangeError("text must be valid UTF-8") from exc
    if any((ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127 for char in value):
        raise ExchangeError("binary/control bytes are not accepted as text")
    return value


def _absolute(path) -> Path:
    # Do not resolve symlinks before rejecting them.
    return Path(os.path.abspath(os.fspath(path)))


def _no_links(path: Path) -> None:
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE_POINT:
            raise ExchangeError("symlink/reparse point is not allowed: " + str(part))


def _read(path: Path, limit: int) -> bytes:
    _no_links(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ExchangeError("not a regular file or exceeds size cap: " + path.name)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ExchangeError("file changed while opening: " + path.name)
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    _no_links(path)
    current = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if len(data) > limit or identity(before) != identity(after) or identity(after) != identity(current):
        raise ExchangeError("file changed while reading or exceeds size cap: " + path.name)
    return data


def _mkdir(path: Path) -> None:
    _no_links(path)
    path.mkdir(parents=True, exist_ok=True)
    _no_links(path)


def _write(path: Path, data: bytes) -> None:
    _mkdir(path.parent)
    _no_links(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _no_links(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _token(value, label: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value) or value in {".", ".."}:
        raise ExchangeError(label + " must be a short safe identifier")
    _relative(value)
    return value


def _digest(value, label: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ExchangeError(label + " must be a lowercase SHA-256")
    return value


def _relative(name: str) -> str:
    # Portable names: reject NTFS streams, drive paths, backslashes and ambiguous
    # Windows names even if intake is running on another platform.
    if not name or "\\" in name or ":" in name or name.startswith("/"):
        raise ExchangeError("unsafe relative filename")
    for part in name.split("/"):
        if (part in {"", ".", ".."} or part.endswith((" ", "."))
                or any(ord(char) < 32 for char in part)
                or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)):
            raise ExchangeError("unsafe relative filename")
    return name


class Exchange:
    def __init__(self, root, incoming, outbound, *, project="ledger", stable_seconds=5,
                 max_files=512, max_file_bytes=4 * 1024 * 1024,
                 max_total_bytes=32 * 1024 * 1024, max_binary_bytes=128 * 1024 * 1024):
        self.root, self.incoming, self.outbound = map(_absolute, (root, incoming, outbound))
        self.project = _token(project, "project")
        self.stable_seconds = float(stable_seconds)
        if not 0 <= self.stable_seconds <= 3600:
            raise ExchangeError("stable_seconds must be 0..3600")
        self.max_files, self.max_file_bytes = max_files, max_file_bytes
        self.max_total_bytes, self.max_binary_bytes = max_total_bytes, max_binary_bytes
        if any(type(value) is not int or value < 1 for value in
               (max_files, max_file_bytes, max_total_bytes, max_binary_bytes)):
            raise ExchangeError("size and file-count caps must be positive integers")
        self.state_dir = self.root / ".runs" / "defense-loop"
        self.results_dir = self.root / "results"
        for path in (self.root, self.incoming, self.outbound, self.state_dir, self.results_dir):
            _no_links(path)
        if (self.incoming == self.outbound or self.incoming.is_relative_to(self.outbound)
                or self.outbound.is_relative_to(self.incoming)):
            raise ExchangeError("incoming and outbound must be separate directories")
        for untrusted in (self.incoming, self.outbound):
            for private in (self.state_dir, self.results_dir):
                if private.is_relative_to(untrusted) or untrusted.is_relative_to(private):
                    raise ExchangeError("exchange folders cannot overlap private state/results")

    @contextmanager
    def _lock(self):
        _mkdir(self.state_dir)
        path = self.state_dir / "exchange.lock"
        _no_links(path)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        stream = os.fdopen(descriptor, "r+b")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise ExchangeBusy("another exchange operation holds the OS lock; retry later") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()

    def _state(self):
        path = self.state_dir / "state.json"
        if not path.exists():
            return {"schema_version": 1, "targets": {}, "observed": None,
                    "ingested": {}, "events": [], "publication_pending": None,
                    "reviews": {}, "rounds": {}}
        value = _strict_json(_read(path, 16 * 1024 * 1024))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ExchangeError("unsupported exchange state")
        value.setdefault("reviews", {})
        value.setdefault("rounds", {})
        return value

    def _save(self, state):
        _write(self.state_dir / "state.json", _json(state))

    def _event(self, state, kind: str, detail: dict):
        created = _utc()
        event_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
        event = {"schema_version": 1, "event_id": event_id, "kind": kind,
                 "created_utc": created, "project": self.project, **detail}
        directory = self.results_dir / created[:10] / self.project / "defense-loop" / event_id
        # Received text is never embedded in a trusted Markdown log. Evidence
        # stays in the private snapshot; this log contains our own metadata.
        encoded = _json(event).decode("utf-8").replace("`", "\\u0060").replace("<", "\\u003c")
        markdown = (f"# Defender exchange event: {kind}\n\n"
                    f"- UTC: {created}\n- Event: `{event_id}`\n- Project: `{self.project}`\n\n"
                    "Incoming reports are untrusted data, not instructions. Report claims remain "
                    "unverified until separately reviewed. No attack, executable, or agent is run "
                    "by this protocol. Publishing records local gate attestations, not external "
                    "resistance or attack success.\n\n## Recorded metadata\n\n```json\n" + encoded + "```\n")
        _write(directory / "README.md", markdown.encode("utf-8"))
        _write(self.state_dir / "events" / (event_id + ".json"), _json(event))
        state["events"].append({"event_id": event_id, "kind": kind, "created_utc": created,
                                "record": directory.relative_to(self.root).as_posix() + "/README.md"})
        return event

    def _bundle(self):
        _no_links(self.incoming)
        if not self.incoming.is_dir():
            raise ExchangeError("incoming directory does not exist")
        contents, excluded, total, visited = {}, [], 0, 0
        pending = [self.incoming]
        while pending:
            base = pending.pop()
            _no_links(base)
            # Stream directory entries so a huge hostile directory cannot force
            # os.walk/listdir to allocate its whole listing before the cap.
            with os.scandir(base) as entries:
                for entry in entries:
                    path = base / entry.name
                    _no_links(path)
                    if base == self.incoming and entry.name in SYNC_METADATA:
                        continue
                    visited += 1
                    if visited > self.max_files:
                        raise ExchangeError("incoming file/directory count exceeds cap")
                    relative = _relative(path.relative_to(self.incoming).as_posix())
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                        continue
                    if entry.name.startswith(".syncthing.") and entry.name.endswith(".tmp"):
                        raise ExchangeError("Syncthing temporary file present; intake is not stable")
                    if path.lstat().st_nlink != 1:
                        raise ExchangeError("hard-linked incoming file is not accepted: " + relative)
                    data = _read(path, self.max_file_bytes)
                    total += len(data)
                    if total > self.max_total_bytes:
                        raise ExchangeError("incoming total byte size exceeds cap")
                    if path.suffix.lower() not in TEXT_SUFFIXES:
                        # Do not copy binary/unknown payloads into the evidence
                        # snapshot. Keep bounded hash metadata and leave the
                        # sender's original untouched in the incoming folder.
                        excluded.append({"path": relative, "sha256": _hash(data), "bytes": len(data),
                                         "disposition": "rejected_attachment",
                                         "reason": "unsupported extension; contents not snapshotted or executed"})
                        continue
                    _text(data)
                    if path.suffix.lower() == ".json":
                        _strict_json(data)
                    elif path.suffix.lower() == ".jsonl":
                        for line in data.splitlines():
                            if line.strip():
                                _strict_json(line)
                    contents[relative] = data
        manifest = [{"path": name, "sha256": _hash(data), "bytes": len(data)}
                    for name, data in sorted(contents.items())]
        # For bundles with no rejected attachments, preserve the exact original
        # manifest schema/digest so a protocol upgrade cannot fabricate a new
        # report event from already-ingested identical files.
        manifest = sorted(manifest + excluded, key=lambda item: item["path"])
        return _hash(_json(manifest)), manifest, contents

    def register_target(self, manifest: dict):
        """Register a trusted public manifest, NOT a manifest supplied in intake."""
        if not isinstance(manifest, dict) or manifest.get("schema_version") not in (1, 2):
            raise ExchangeError("target manifest must use schema 1 or 2")
        digest = _digest(manifest.get("sha256"), "target sha256")
        artifact_id = _token(manifest.get("artifact_id"), "artifact_id")
        if manifest.get("filename") != "app.exe" or type(manifest.get("bytes")) is not int or manifest["bytes"] < 1:
            raise ExchangeError("target must describe a non-empty app.exe")
        target = {"sha256": digest, "artifact_id": artifact_id, "bytes": manifest["bytes"],
                  "manifest_schema_version": manifest["schema_version"],
                  "manifest_canonical_sha256": _hash(_json(manifest)), "registration": "trusted_local_manifest"}
        if manifest.get("round_id") is not None:
            target["round_id"] = _token(manifest["round_id"], "round_id")
        with self._lock():
            state = self._state()
            old = state["targets"].get(digest)
            if old and (old["artifact_id"] != artifact_id or old["bytes"] != manifest["bytes"]):
                raise ExchangeError("target digest already registered with conflicting identity")
            state["targets"][digest] = target
            state["rounds"].setdefault(digest, {"sha256": digest, "artifact_id": artifact_id,
                                               "status": "awaiting_external_report", "report_event_ids": []})
            self._save(state)
        return target

    def scan(self, *, now: float | None = None) -> dict:
        """Observe once; accept only a content-identical second observation."""
        now = time.time() if now is None else float(now)
        with self._lock():
            state = self._state()
            if (self.state_dir / "STOP").exists():
                return {"status": "stopped"}
            try:
                digest, manifest, contents = self._bundle()
            except (ExchangeError, OSError) as exc:
                error = str(exc)[:300]
                signature = _hash(error.encode("utf-8"))
                if state.get("last_rejection") != signature:
                    self._event(state, "intake_rejected", {"status": "rejected", "reason": error})
                state["observed"] = None
                state["last_rejection"] = signature
                self._save(state)
                return {"status": "rejected", "reason": error}
            reports = [name for name in sorted(contents) if name.lower().endswith(".md")
                       and Path(name).name.upper() not in {"AGENTS.MD", "SKILL.MD", "README.MD"}]
            if not reports:
                state["observed"] = None
                self._save(state)
                return {"status": "empty", "reason": "no Markdown report in incoming bundle"}
            if digest in state["ingested"]:
                return {"status": "duplicate", "bundle_sha256": digest,
                        "event_id": state["ingested"][digest]}
            previous = state.get("observed")
            if not previous or previous["bundle_sha256"] != digest or now < previous["first_seen_epoch"]:
                state["observed"] = {"bundle_sha256": digest, "first_seen_epoch": now,
                                     "first_seen_utc": _utc()}
                self._save(state)
                return {"status": "pending_stability", "bundle_sha256": digest}
            if now - previous["first_seen_epoch"] < self.stable_seconds:
                return {"status": "pending_stability", "bundle_sha256": digest}
            # Ensure the entire bundle still has the same content before snapshot.
            try:
                check, _, _ = self._bundle()
            except (ExchangeError, OSError):
                state["observed"] = None
                self._save(state)
                return {"status": "pending_stability", "reason": "bundle changed or became unreadable during final check"}
            if check != digest:
                state["observed"] = None
                self._save(state)
                return {"status": "pending_stability", "reason": "bundle changed during final check"}
            report_records = []
            all_mentioned = set()
            for name in reports:
                hashes = set()
                for match in re.finditer(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", _text(contents[name])):
                    hashes.add(match.group().lower())
                    all_mentioned.add(match.group().lower())
                    if len(all_mentioned) > 256:
                        reason = "report bundle contains more than 256 distinct hash references"
                        signature = _hash(reason.encode("utf-8"))
                        if state.get("last_rejection") != signature:
                            self._event(state, "intake_rejected", {"status": "rejected", "reason": reason})
                        state["last_rejection"] = signature
                        state["observed"] = None
                        self._save(state)
                        return {"status": "rejected", "reason": reason}
                hashes = sorted(hashes)
                targets = [state["targets"][item] for item in hashes if item in state["targets"]]
                report_records.append({"path": name, "sha256": _hash(contents[name]),
                                       "mentioned_sha256": hashes, "registered_targets": targets,
                                       "linkage": "referenced_registered_target" if targets else "unmatched",
                                       "claims": "unverified", "status": "unreviewed"})
            snapshot = self.state_dir / "inbox" / digest
            for name, data in contents.items():
                _write(snapshot / "files" / name, data)
            intake = {"schema_version": 1, "bundle_sha256": digest, "files": manifest,
                      "reports": report_records, "status": "unreviewed", "claims": "unverified",
                      "observed_utc": _utc(), "linkage_caveat": "Mentioning a registered hash is not proof of target execution or report truth."}
            rejected = [item for item in manifest if item.get("disposition") == "rejected_attachment"]
            if rejected:
                intake["rejected_attachments"] = rejected
            _write(snapshot / "manifest.json", _json(intake))
            event = self._event(state, "report_received", {
                "status": "unreviewed", "claims": "unverified", "bundle_sha256": digest,
                "files": manifest, "reports": report_records,
                "snapshot": snapshot.relative_to(self.root).as_posix(),
                "stability": "two content-identical observations plus a final content check",
                **({"rejected_attachments": rejected} if rejected else {})})
            state["ingested"][digest] = event["event_id"]
            for report in report_records:
                for target in report["registered_targets"]:
                    round_state = state["rounds"].setdefault(target["sha256"], {
                        "sha256": target["sha256"], "artifact_id": target["artifact_id"], "report_event_ids": []})
                    round_state["status"] = "report_received_unreviewed"
                    if event["event_id"] not in round_state["report_event_ids"]:
                        round_state["report_event_ids"].append(event["event_id"])
            state["observed"] = None
            state["last_rejection"] = None
            self._save(state)
            return {"status": "unreviewed", "event": event}

    def status(self) -> dict:
        """Read only: no network calls and no creation of state or locks."""
        state = self._state()
        pending = [_strict_json(_read(self.state_dir / "events" / (item["event_id"] + ".json"), 4 * 1024 * 1024))
                   for item in state["events"] if item["kind"] == "report_received" and item["event_id"] not in state["reviews"]]
        return {**state, "pending_reports": pending, "stopped": (self.state_dir / "STOP").exists(),
                "caveat": "Incoming claims are unverified. This protocol performs no attack or gate tests."}

    def mark_reviewed(self, event_id: str, *, review_path, classification: str, notes="") -> dict:
        """Acknowledge a local review without treating received claims as proof.

        This is an idempotent acknowledgement, not an attack verifier. The local
        review document is copied into private evidence and content-hash bound.
        Any later reconsideration needs a new explicit review, not a rescan.
        """
        _token(event_id, "event_id")
        _token(classification, "classification")
        if not isinstance(notes, str) or len(notes) > 8192:
            raise ExchangeError("review notes must be at most 8192 characters")
        review_file = self._trusted(review_path)
        if review_file.suffix.lower() not in {".md", ".txt", ".json"}:
            raise ExchangeError("review document must be local Markdown, text or JSON")
        data = _read(review_file, 1024 * 1024)
        _text(data)
        if review_file.suffix.lower() == ".json":
            _strict_json(data)
        record = {"event_id": event_id, "classification": classification,
                  "review_sha256": _hash(data), "notes": notes, "status": "reviewed",
                  "claims": "not_independently_verified_by_exchange"}
        with self._lock():
            state = self._state()
            if not any(item["event_id"] == event_id and item["kind"] == "report_received" for item in state["events"]):
                raise ExchangeError("review must reference an existing report_received event")
            previous = state["reviews"].get(event_id)
            if previous:
                if all(previous.get(key) == value for key, value in record.items()):
                    return previous
                raise ExchangeError("event already reviewed; do not silently overwrite an acknowledgement")
            document = self.state_dir / "reviews" / event_id / ("review" + review_file.suffix.lower())
            _write(document, data)
            record["reviewed_utc"] = _utc()
            record["document"] = document.relative_to(self.root).as_posix()
            state["reviews"][event_id] = record
            for round_state in state["rounds"].values():
                reports = round_state["report_event_ids"]
                if event_id in reports:
                    round_state["status"] = ("report_received_unreviewed" if any(item not in state["reviews"] for item in reports)
                                             else "reports_reviewed")
            self._event(state, "report_reviewed", {"reviewed_report_event_id": event_id,
                                                  **{key: value for key, value in record.items() if key != "event_id"}})
            self._save(state)
            return record

    def _trusted(self, path) -> Path:
        path = _absolute(path)
        _no_links(path)
        if (not path.is_relative_to(self.root) or path.is_relative_to(self.incoming)
                or path.is_relative_to(self.outbound) or path.is_relative_to(self.state_dir / "inbox")):
            raise ExchangeError("candidate/gate evidence must be explicitly inside the trusted project, outside intake")
        return path

    def _public(self):
        _no_links(self.outbound)
        if not self.outbound.exists():
            return {}
        found = {}
        for path in self.outbound.iterdir():
            _no_links(path)
            if path.name in SYNC_METADATA:
                continue
            if path.name not in PUBLIC_FILES:
                raise ExchangeError("unexpected outbound file; whitelist is app.exe, README.txt, manifest.json")
            found[path.name] = _read(path, self.max_binary_bytes if path.name == "app.exe" else 65536)
        if found and set(found) != set(PUBLIC_FILES):
            raise ExchangeError("existing outbound handoff is incomplete")
        if found:
            manifest = _strict_json(found["manifest.json"])
            if (not isinstance(manifest, dict) or manifest.get("sha256") != _hash(found["app.exe"])
                    or manifest.get("bytes") != len(found["app.exe"]) or manifest.get("filename") != "app.exe"):
                raise ExchangeError("outbound executable does not match its manifest")
            _text(found["README.txt"])
        return found

    def stage_publish(self, candidate, *, expected_sha256: str, round_id: str, gates_path,
                      previous_sha256: str | None, readme_path=None) -> dict:
        """Stage explicit trusted local files; does not write the public folder.

        Gate JSON schema 1 binds candidate_sha256 and requires each of functional,
        protection and performance to have status 'passed'. It is an operator's
        local attestation. The module does not independently execute those tests.
        """
        expected_sha256 = _digest(expected_sha256, "candidate sha256")
        round_id = _token(round_id, "round_id")
        if previous_sha256 is not None:
            _digest(previous_sha256, "previous sha256")
        binary = _read(self._trusted(candidate), self.max_binary_bytes)
        if _hash(binary) != expected_sha256:
            raise ExchangeError("candidate SHA-256 mismatch")
        pe_offset = int.from_bytes(binary[60:64], "little") if len(binary) >= 64 else -1
        if (not binary.startswith(b"MZ") or pe_offset < 64 or binary[pe_offset:pe_offset + 4] != b"PE\0\0"
                or binary[pe_offset + 4:pe_offset + 6] != b"\x64\x86"):
            raise ExchangeError("candidate is not a recognizable x86-64 PE executable")
        gate_bytes = _read(self._trusted(gates_path), 1024 * 1024)
        gates = _strict_json(gate_bytes)
        if (not isinstance(gates, dict) or gates.get("schema_version") != 1 or gates.get("status") != "passed"
                or gates.get("candidate_sha256") != expected_sha256):
            raise ExchangeError("gate attestation must bind schema 1 to the exact candidate SHA-256")
        for gate in ("functional", "protection", "performance"):
            if not isinstance(gates.get(gate), dict) or gates[gate].get("status") != "passed":
                raise ExchangeError(gate + " gate is not passed")
        _digest(gates.get("baseline_sha256"), "baseline sha256")
        _digest(gates.get("previous_sha256"), "validated previous sha256")
        if previous_sha256 is not None and gates["previous_sha256"] != previous_sha256:
            raise ExchangeError("gate previous SHA-256 is not the current public artifact")
        integrity = gates.get("integrity")
        if (not isinstance(integrity, dict) or integrity.get("status") != "passed"
                or not isinstance(integrity.get("before"), dict) or not isinstance(integrity.get("after"), dict)
                or integrity.get("changed") != []):
            raise ExchangeError("gate attestation needs passed before/after artifact integrity")
        for arm in ("candidate", "baseline", "previous"):
            if integrity["before"].get(arm) != gates[arm + "_sha256"] or integrity["after"].get(arm) != gates[arm + "_sha256"]:
                raise ExchangeError("gate artifact integrity does not bind " + arm)
        functional = gates["functional"]
        if (type(functional.get("total")) is not int or functional["total"] < 8192
                or type(functional.get("matched")) is not int or functional["matched"] != functional["total"]
                or type(functional.get("random_unique_cases")) is not int or functional["random_unique_cases"] < 8192
                or functional["random_unique_cases"] > functional["total"]
                or type(functional.get("repeats")) is not int or functional["repeats"] < 2):
            raise ExchangeError("functional gate needs at least 8192 unique random cases, every case matched, and two repeats")
        if not isinstance(gates["protection"].get("evidence"), dict) or not gates["protection"]["evidence"]:
            raise ExchangeError("protection gate needs explicit application evidence")
        performance = gates["performance"]
        def positive(value):
            return type(value) in (int, float) and math.isfinite(value) and value > 0

        if (type(performance.get("warmups")) is not int or performance["warmups"] < 1
                or type(performance.get("measured_batches")) is not int or performance["measured_batches"] < 7):
            raise ExchangeError("performance gate needs a warmup and at least seven measured batches")
        conditions = performance.get("conditions", {})
        if not isinstance(conditions, dict):
            raise ExchangeError("performance conditions must be an object")
        for name in ("baseline", "previous", "candidate"):
            condition = conditions.get(name, {})
            if not isinstance(condition, dict):
                raise ExchangeError("performance condition must be an object: " + name)
            samples = condition.get("samples_seconds")
            if (not isinstance(samples, list) or len(samples) != performance["measured_batches"]
                    or not all(positive(value) for value in samples)
                    or not positive(condition.get("median_seconds"))
                    or not math.isclose(condition["median_seconds"], statistics.median(samples), rel_tol=1e-9)):
                raise ExchangeError("performance gate has missing or inconsistent positive measurements: " + name)
        limits = performance.get("limits", {})
        ratios = performance.get("ratios", {})
        if not isinstance(limits, dict) or not isinstance(ratios, dict):
            raise ExchangeError("performance limits and ratios must be objects")
        for reference, maximum in (("previous", 10.0), ("baseline", 200.0)):
            key = "candidate_vs_" + reference
            expected_ratio = conditions["candidate"]["median_seconds"] / conditions[reference]["median_seconds"]
            if (not positive(limits.get(key)) or limits[key] > maximum or not positive(ratios.get(key))
                    or not math.isclose(ratios[key], expected_ratio, rel_tol=1e-9) or ratios[key] > limits[key]):
                raise ExchangeError("performance ratio exceeds or does not substantiate its gate: " + key)
        if (type(limits.get("candidate_bytes")) is not int or not 1 <= limits["candidate_bytes"] <= 16 * 1024 * 1024
                or len(binary) > limits["candidate_bytes"] or conditions["candidate"].get("bytes") != len(binary)):
            raise ExchangeError("candidate bytes exceed or do not match the performance size gate")
        readme = DEFAULT_README.encode("utf-8") if readme_path is None else _read(self._trusted(readme_path), 65536)
        _text(readme)
        with self._lock():
            state = self._state()
            if (self.state_dir / "STOP").exists():
                raise ExchangeError("STOP marker is present")
            if state["publication_pending"]:
                raise ExchangeError("publication pending; complete recovery before staging another artifact")
            current = self._public()
            current_hash = _hash(current["app.exe"]) if current else None
            if current_hash != previous_sha256:
                raise ExchangeError("previous SHA-256 does not match current public artifact")
            if current_hash == expected_sha256:
                raise ExchangeError("candidate is identical to current artifact; do not create a false new generation")
            manifest = {"schema_version": 2, "artifact_id": "ar-" + round_id + "-" + expected_sha256[:12],
                        "filename": "app.exe", "sha256": expected_sha256, "bytes": len(binary),
                        "generated_utc": _utc(), "round_id": round_id, "previous_sha256": previous_sha256,
                        "platform": "windows-x86_64", "interface": "console-stdin-stdout"}
            stage_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
            files = {"app.exe": binary, "README.txt": readme, "manifest.json": _json(manifest)}
            directory = self.state_dir / "staged" / stage_id
            for name, data in files.items():
                _write(directory / "files" / name, data)
            metadata = {"schema_version": 1, "stage_id": stage_id, "manifest": manifest,
                        "file_sha256": {name: _hash(data) for name, data in files.items()},
                        "gate_attestation_sha256": _hash(gate_bytes),
                        "gate_statuses": {name: gates[name]["status"] for name in ("functional", "protection", "performance")}}
            _write(directory / "gate-attestation.json", gate_bytes)
            _write(directory / "stage.json", _json(metadata))
            self._event(state, "publication_staged", {"status": "staged", **metadata,
                        "caveat": "Local gate attestation accepted; no external defense effectiveness is inferred."})
            self._save(state)
            return metadata

    def commit_publish(self, stage_id: str, *, sync_paused: bool = False) -> dict:
        """Commit a staged bundle while caller keeps synchronization paused.

        Failure leaves publication_pending set and the previous files archived.
        Keep synchronization paused and retry the SAME stage to recover. Do not
        clear the pending marker or resume synchronization after a failed commit.
        """
        _token(stage_id, "stage_id")
        if sync_paused is not True:
            raise ExchangeError("caller must explicitly attest synchronization is paused")
        with self._lock():
            state = self._state()
            if (self.state_dir / "STOP").exists():
                raise ExchangeError("STOP marker is present")
            pending = state["publication_pending"]
            if pending and pending["stage_id"] != stage_id:
                raise ExchangeError("another publication is pending; recover that exact stage")
            directory = self.state_dir / "staged" / stage_id
            metadata = _strict_json(_read(directory / "stage.json", 65536))
            if metadata.get("stage_id") != stage_id or set(metadata.get("file_sha256", {})) != set(PUBLIC_FILES):
                raise ExchangeError("invalid stage metadata")
            files = {name: _read(directory / "files" / name, self.max_binary_bytes if name == "app.exe" else 65536)
                     for name in PUBLIC_FILES}
            if any(_hash(data) != metadata["file_sha256"][name] for name, data in files.items()):
                raise ExchangeError("staged file hash mismatch")
            if _hash(_read(directory / "gate-attestation.json", 1024 * 1024)) != metadata["gate_attestation_sha256"]:
                raise ExchangeError("staged gate attestation changed")
            manifest = _strict_json(files["manifest.json"])
            if manifest != metadata["manifest"] or _hash(files["app.exe"]) != manifest["sha256"]:
                raise ExchangeError("staged manifest mismatch")
            archive = self.state_dir / "archive" / stage_id
            if not pending:
                current = self._public()
                current_hash = _hash(current["app.exe"]) if current else None
                if current_hash != manifest["previous_sha256"]:
                    if current == files and state.get("last_published_stage") == stage_id:
                        return {"status": "already_published", "manifest": manifest}
                    raise ExchangeError("public artifact changed after staging")
                for name, data in current.items():
                    _write(archive / name, data)
                _write(archive / "archive.json", _json({"files": {name: _hash(data) for name, data in current.items()},
                                                       "archived_utc": _utc()}))
                state["publication_pending"] = {"stage_id": stage_id, "started_utc": _utc(),
                                                "instruction": "Keep synchronization paused; retry this stage to recover."}
                self._save(state)
            else:
                # A partial replacement may not match its old manifest. Only
                # allow each current file to be an archived or staged version.
                archived = _strict_json(_read(archive / "archive.json", 65536))["files"]
                _no_links(self.outbound)
                for path in self.outbound.iterdir() if self.outbound.exists() else ():
                    _no_links(path)
                    if path.name in SYNC_METADATA:
                        continue
                    if path.name not in PUBLIC_FILES:
                        raise ExchangeError("unexpected file during publication recovery")
                    digest = _hash(_read(path, self.max_binary_bytes if path.name == "app.exe" else 65536))
                    if digest not in {archived.get(path.name), metadata["file_sha256"][path.name]}:
                        raise ExchangeError("public file changed unexpectedly during recovery")
            _mkdir(self.outbound)
            # Manifest last; synchronizer MUST remain paused throughout.
            for name in PUBLIC_FILES:
                _write(self.outbound / name, files[name])
            if self._public() != files:
                raise ExchangeError("published bytes failed verification; keep synchronization paused")
            target = {"sha256": manifest["sha256"], "artifact_id": manifest["artifact_id"],
                      "bytes": manifest["bytes"], "manifest_schema_version": 2,
                      "manifest_canonical_sha256": _hash(_json(manifest)), "round_id": manifest["round_id"],
                      "registration": "local_publication"}
            state["targets"][manifest["sha256"]] = target
            state["rounds"][manifest["sha256"]] = {"sha256": manifest["sha256"],
                "artifact_id": manifest["artifact_id"], "round_id": manifest["round_id"],
                "status": "awaiting_external_report", "report_event_ids": []}
            event = self._event(state, "artifact_published", {"status": "published", "manifest": manifest,
                        "stage_id": stage_id, "previous_files_archive": archive.relative_to(self.root).as_posix(),
                        "gate_statuses": metadata["gate_statuses"], "external_evaluation": "not_evaluated",
                        "synchronization": "caller attested paused; resume is the caller's responsibility"})
            state["publication_pending"] = None
            state["last_published_stage"] = stage_id
            self._save(state)
            return {"status": "published", "manifest": manifest, "event": event}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--incoming", type=Path)
    parser.add_argument("--outbound", type=Path, required=True)
    parser.add_argument("--project", default="ledger")
    parser.add_argument("--stable-seconds", type=float, default=5)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("scan")
    commands.add_parser("status")
    register = commands.add_parser("register-target")
    register.add_argument("--manifest", required=True, type=Path)
    review = commands.add_parser("review")
    review.add_argument("--event-id", required=True)
    review.add_argument("--review", required=True, type=Path)
    review.add_argument("--classification", required=True)
    review.add_argument("--notes", default="")
    stage = commands.add_parser("stage")
    stage.add_argument("--candidate", required=True, type=Path)
    stage.add_argument("--sha256", required=True)
    stage.add_argument("--round-id", required=True)
    stage.add_argument("--gates", required=True, type=Path)
    stage.add_argument("--readme", type=Path)
    stage.add_argument("--previous-sha256")
    commit = commands.add_parser("commit")
    commit.add_argument("--stage-id", required=True)
    commit.add_argument("--sync-paused", action="store_true")
    args = parser.parse_args(argv)
    try:
        exchange = Exchange(args.root, args.incoming or args.root / "rea-analysis-reports", args.outbound,
                            project=args.project, stable_seconds=args.stable_seconds)
        if args.command == "scan":
            result = exchange.scan()
        elif args.command == "status":
            result = exchange.status()
        elif args.command == "register-target":
            manifest_path = _absolute(args.manifest)
            if manifest_path.is_relative_to(exchange.incoming):
                raise ExchangeError("cannot register target identity from untrusted incoming data")
            result = exchange.register_target(_strict_json(_read(manifest_path, 65536)))
        elif args.command == "stage":
            result = exchange.stage_publish(args.candidate, expected_sha256=args.sha256,
                       round_id=args.round_id, gates_path=args.gates,
                       previous_sha256=args.previous_sha256, readme_path=args.readme)
        elif args.command == "review":
            result = exchange.mark_reviewed(args.event_id, review_path=args.review,
                                           classification=args.classification, notes=args.notes)
        else:
            result = exchange.commit_publish(args.stage_id, sync_paused=args.sync_paused)
    except (ExchangeError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get("status") == "rejected" else 0


if __name__ == "__main__":
    raise SystemExit(main())
