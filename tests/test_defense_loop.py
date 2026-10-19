import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from antirea.defense_loop import Busy, Controller, transaction
from antirea.sync_publish import publish


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.controller = Controller(self.root, self.root / "outgoing")
        self.pending = []
        self.controller.exchange = SimpleNamespace(
            scan=lambda: {"status": "stable"},
            status=lambda: {"pending_reports": self.pending},
        )

    def test_idle_does_not_dispatch(self):
        self.assertEqual(self.controller.precheck()["status"], "idle")
        self.assertIsNone(self.controller._state()["lease"])

    def test_dispatch_claim_and_release(self):
        self.pending.append({"id": "report"})
        self.assertEqual(self.controller.precheck()["status"], "ready")
        self.assertEqual(self.controller.precheck()["status"], "busy")
        self.controller.claim("worker1")
        with self.assertRaises(Busy):
            self.controller.claim("worker2")
        with self.assertRaises(Busy):
            self.controller.release("worker2")
        self.controller.heartbeat("worker1")
        self.pending.clear()
        self.controller.release("worker1")
        self.assertEqual(self.controller.precheck()["status"], "idle")

    def test_expired_lease_recovers(self):
        self.controller.claim("interrupted")
        state = self.controller._state()
        state["lease"]["expires"] = 0
        self.controller._save(state)
        self.controller.claim("replacement")
        self.assertEqual(self.controller._state()["lease"]["owner"], "replacement")

    def test_stop_disables_all_new_work(self):
        self.controller.claim("worker")
        self.controller.stop()
        self.assertEqual(self.controller.precheck()["status"], "stopped")
        with self.assertRaises(Busy):
            self.controller.claim("worker")
        with self.assertRaises(Busy):
            self.controller.heartbeat("worker")
        self.controller.release("worker")
        self.assertEqual(self.controller.status()["status"], "stopped")

    def test_retry_has_backoff(self):
        self.controller.claim("worker")
        self.controller.release("worker", retry=True, summary="temporary tool failure")
        self.assertEqual(self.controller.precheck()["status"], "retry_backoff")
        state = self.controller._state()
        state["retry_after"] = 0
        self.controller._save(state)
        self.assertEqual(self.controller.precheck()["status"], "ready")

    def test_stop_does_not_need_controller_lock(self):
        with transaction(self.controller.lock_path):
            self.assertEqual(self.controller.stop()["status"], "stopped")
            self.assertTrue(self.controller.stop_path.exists())

    def test_abandoned_worker_wakes_without_pending_reports(self):
        self.controller.claim("interrupted")
        state = self.controller._state()
        state["lease"]["expires"] = 0
        self.controller._save(state)
        result = self.controller.precheck()
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["recovery_needed"])

    def test_incomplete_publish_wakes_without_report(self):
        (self.controller.directory / "sync-publication.json").write_text(
            '{"stage_id":"round1","status":"paused"}', encoding="utf-8")
        self.assertEqual(self.controller.precheck()["status"], "ready")

    def test_retry_claim_crash_recovers_after_dispatch_expiry(self):
        self.controller.claim("worker")
        self.controller.release("worker", retry=True)
        state = self.controller._state()
        state["retry_after"] = 0
        self.controller._save(state)
        self.controller.precheck()
        self.controller.claim("retry-worker")
        state = self.controller._state()
        state["lease"]["expires"] = 0
        self.controller._save(state)
        self.assertEqual(self.controller.precheck()["status"], "ready")

    def test_os_lock_released_after_exception(self):
        with self.assertRaises(ValueError):
            with transaction(self.controller.lock_path):
                raise ValueError("interrupted transaction")
        with transaction(self.controller.lock_path):
            pass


class FakeSync:
    def __init__(self, paused=False):
        self.paused = paused
        self.calls = []

    def check(self, _controller):
        return {"paused": self.paused}

    def request(self, route, method="GET", payload=None):
        self.calls.append((route, method, payload))
        if method == "PATCH":
            self.paused = payload["paused"]
        return {"paused": self.paused}


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller = Controller(Path(self.temp.name), Path(self.temp.name) / "outgoing")
        self.controller.claim("worker")

    def test_publish_pauses_then_resumes(self):
        sync = FakeSync()

        def commit(stage_id, *, sync_paused):
            self.assertTrue(sync.paused)
            self.assertTrue(sync_paused)
            return {"status": "published", "manifest": {"sha256": "a" * 64}}

        self.controller.exchange = SimpleNamespace(commit_publish=commit)
        result = publish(self.controller, "worker", "round1", sync)
        self.assertEqual(result["status"], "published")
        self.assertFalse(sync.paused)

    def test_failed_commit_keeps_sync_paused(self):
        sync = FakeSync()

        def commit(*_args, **_kwargs):
            raise ValueError("gate/hash problem")

        self.controller.exchange = SimpleNamespace(commit_publish=commit)
        with self.assertRaises(ValueError):
            publish(self.controller, "worker", "round1", sync)
        self.assertTrue(sync.paused)
        journal = json.loads((self.controller.directory / "sync-publication.json").read_text())
        self.assertEqual(journal["status"], "needs_recovery")

    def test_does_not_resume_manually_paused_folder(self):
        sync = FakeSync(paused=True)
        with self.assertRaises(ValueError):
            publish(self.controller, "worker", "round1", sync)
        self.assertEqual(sync.calls, [])

    def test_wrong_owner_cannot_publish(self):
        with self.assertRaises(Busy):
            publish(self.controller, "wrong", "round1", FakeSync())

    def test_stop_during_commit_prevents_resume(self):
        sync = FakeSync()

        def commit(*args, **kwargs):
            self.controller.stop()
            return {"status": "published", "manifest": {"sha256": "a" * 64}}

        self.controller.exchange = SimpleNamespace(commit_publish=commit)
        with self.assertRaises(ValueError):
            publish(self.controller, "worker", "round1", sync)
        self.assertTrue(sync.paused)


if __name__ == "__main__":
    unittest.main()
