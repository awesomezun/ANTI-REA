"""Publish a validated staged bundle to the already authorized Syncthing peer.

Reads the local API key only into memory. Never copies private build evidence.
The receiver still MUST verify hash and size: sync is not a bundle transaction.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET

from antirea.defense_loop import Controller, ROOT, transaction, utc, write_json


def _load_local_sync_settings() -> dict:
    cfg_path = ROOT / ".runs/defense-loop/local-sync.json"
    if cfg_path.is_file():
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


_LOCAL_SYNC = _load_local_sync_settings()
FOLDER_ID = os.environ.get("ANTIREA_SYNC_FOLDER_ID", _LOCAL_SYNC.get("folder_id", "anti-rea-attackerfolder"))
REMOTE_ID = os.environ.get("ANTIREA_SYNC_REMOTE_ID", _LOCAL_SYNC.get("remote_id", ""))
LOCAL_ID = os.environ.get("ANTIREA_SYNC_LOCAL_ID", _LOCAL_SYNC.get("local_id", ""))
SYNC_CONFIG = Path(os.environ.get("ANTIREA_SYNC_CONFIG", str(Path.home() / "AppData/Local/Syncthing/config.xml")))
EXPECTED_IGNORES = ["!/app.exe", "!/README.txt", "!/manifest.json", "*"]


class Syncthing:
    def __init__(self):
        tree = ET.parse(SYNC_CONFIG)
        self.key = tree.findtext("gui/apikey")
        if not self.key:
            raise ValueError("local Syncthing API key unavailable")

    def request(self, route, method="GET", payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request("http://127.0.0.1:8384/rest/" + route,
                    data=data, method=method,
                    headers={"X-API-Key": self.key, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(4 * 1024 * 1024)
        return json.loads(raw) if raw.strip() else {}

    def check(self, controller):
        folder = self.request("config/folders/" + FOLDER_ID)
        expected_path = controller.exchange.outbound
        if (folder["id"] != FOLDER_ID or folder["type"] != "sendonly"
                or Path(folder["path"]).resolve() != expected_path.resolve()
                or {device["deviceID"] for device in folder["devices"]} != {LOCAL_ID, REMOTE_ID}):
            raise ValueError("outbound folder identity, peers, path or send-only mode changed")
        ignores = self.request("db/ignores?folder=" + FOLDER_ID).get("ignore", [])
        patterns = [line.strip() for line in ignores if line.strip() and not line.lstrip().startswith("//")]
        if patterns != EXPECTED_IGNORES:
            raise ValueError("outbound three-file allowlist changed")
        incoming = self.request("config/folders/rea-analysis-reports")
        if (incoming["type"] != "receiveonly"
                or Path(incoming["path"]).resolve() != controller.exchange.incoming.resolve()
                or {device["deviceID"] for device in incoming["devices"]} != {LOCAL_ID, REMOTE_ID}):
            raise ValueError("incoming report isolation changed")
        return folder


def publish(controller: Controller, owner: str, stage_id: str, sync=None):
    sync = sync or Syncthing()
    with transaction(controller.lock_path):
        state = controller._state()
        controller._require_owner(state, owner)
        folder = sync.check(controller)
        journal_path = controller.directory / "sync-publication.json"
        previous_journal = json.loads(journal_path.read_text(encoding="utf-8")) if journal_path.exists() else {}
        recovering = (previous_journal.get("stage_id") == stage_id
                      and previous_journal.get("status") in {"pausing", "paused", "needs_recovery"})
        if folder.get("paused") and not recovering:
            raise ValueError("folder already paused outside this publication; do not resume it automatically")
        journal = {"stage_id": stage_id, "started_utc": utc(), "status": "pausing"}
        write_json(journal_path, journal)
        try:
            sync.request("config/folders/" + FOLDER_ID, "PATCH", {"paused": True})
            if not sync.request("config/folders/" + FOLDER_ID).get("paused"):
                raise ValueError("synchronizer pause did not take effect")
            journal["status"] = "paused"
            write_json(journal_path, journal)
            result = controller.exchange.commit_publish(stage_id, sync_paused=True)
            if controller.stop_path.exists():
                raise ValueError("STOP requested during publication; keep synchronization paused")
            sync.check(controller)
            if controller.stop_path.exists():
                raise ValueError("STOP requested before synchronization resume")
            sync.request("config/folders/" + FOLDER_ID, "PATCH", {"paused": False})
            if controller.stop_path.exists():
                sync.request("config/folders/" + FOLDER_ID, "PATCH", {"paused": True})
                raise ValueError("STOP arrived during resume; synchronization paused again")
            if sync.request("config/folders/" + FOLDER_ID).get("paused"):
                raise ValueError("synchronizer resume did not take effect")
            sync.request("db/scan?folder=" + FOLDER_ID, "POST")
            journal.update(status="resumed", completed_utc=utc(), sha256=result["manifest"]["sha256"])
            write_json(journal_path, journal)
            return {**result, "synchronization": "resumed; peer completion must be checked separately"}
        except Exception:
            journal.update(status="needs_recovery", failed_utc=utc(),
                           note="Inspect outbound hashes and folder pause state before retrying this same stage.")
            write_json(journal_path, journal)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--stage-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = publish(Controller(), args.owner, args.stage_id)
    except Exception as exc:
        # Never include request objects or headers (API key) in output.
        print(json.dumps({"status": "error", "error_type": type(exc).__name__,
                          "instruction": "Inspect .runs/defense-loop/sync-publication.json; do not force resume."}))
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
