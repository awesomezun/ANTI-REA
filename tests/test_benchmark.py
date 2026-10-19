import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.benchmark_run import benchmark, resolve_builds, summarize_timings


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = {"run_id": "fixture", "builds": {}}
        for name, protection in (("baseline", "none"), ("vm_reference", "vm"), ("protected", "layered")):
            path = self.root / "defender" / name / "app.exe"
            path.parent.mkdir(parents=True)
            data = name.encode()
            path.write_bytes(data)
            self.report["builds"][name] = {"sha256": hashlib.sha256(data).hexdigest(),
                "coverage": {"executable": str(path), "protection": protection}}
        (self.root / "report.json").write_text(json.dumps(self.report), encoding="utf-8")

    def test_statistics(self):
        summary = summarize_timings([3.0, 1.0, 2.0])
        self.assertEqual((summary["median_seconds"], summary["min_seconds"], summary["max_seconds"]), (2, 1, 3))
        with self.assertRaises(ValueError):
            summarize_timings([0])

    def test_all_batches_checked_and_ratios(self):
        seen = []
        seconds = {"baseline": 1.0, "vm_reference": 2.0, "protected": 4.0}
        def runner(path, cases, timeout):
            seen.append((path.parent.name, cases, timeout))
            return {"status": "passed", "outputs": [7] * len(cases),
                    "elapsed_seconds": seconds[path.parent.name]}
        result = benchmark(self.root, count=32, warmups=1, batches=7, runner=runner)
        self.assertEqual(len(seen), 24)
        self.assertTrue(all(row[1] == seen[0][1] for row in seen))
        protected = result["conditions"]["protected"]
        self.assertEqual(protected["median_ratio_vs_baseline"], 4)
        self.assertEqual(protected["median_ratio_vs_vm_reference"], 2)
        self.assertIsNone(protected["median_ratio_vs_core_reference"])
        self.assertEqual(len(protected["samples_seconds"]), 7)
        self.assertEqual(protected["verified_batches"], 8)
        self.assertEqual(result["measured_order"][1][0], "vm_reference")
        self.assertFalse((self.root / "performance.json").exists())

    def test_core_reference_ratio_preserves_existing_vm_ratios(self):
        path = self.root / "defender/core_reference/app.exe"
        path.parent.mkdir(parents=True)
        data = b"core_reference"
        path.write_bytes(data)
        self.report["builds"]["core_reference"] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "coverage": {"executable": str(path), "protection": "core"}}
        (self.root / "report.json").write_text(json.dumps(self.report), encoding="utf-8")
        seconds = {"baseline": 1.0, "vm_reference": 2.0, "core_reference": 3.0, "protected": 6.0}
        def runner(path, cases, timeout):
            return {"status": "passed", "outputs": [7] * len(cases),
                    "elapsed_seconds": seconds[path.parent.name]}
        result = benchmark(self.root, count=32, batches=3, runner=runner)
        protected = result["conditions"]["protected"]
        self.assertEqual(result["core_reference_condition"], "core_reference")
        self.assertEqual(result["vm_reference_condition"], "vm_reference")
        self.assertEqual(protected["median_ratio_vs_baseline"], 6)
        self.assertEqual(protected["median_ratio_vs_vm_reference"], 3)
        self.assertEqual(protected["median_ratio_vs_core_reference"], 2)

    def test_core_reference_detected_from_protection_when_name_differs(self):
        self.report["builds"]["vm_reference"]["coverage"]["protection"] = "core"
        self.report["builds"]["renamed_core"] = self.report["builds"].pop("vm_reference")
        (self.root / "report.json").write_text(json.dumps(self.report), encoding="utf-8")
        def runner(path, cases, timeout):
            return {"status": "passed", "outputs": [7] * len(cases), "elapsed_seconds": 1.0}
        result = benchmark(self.root, count=8, batches=1, runner=runner)
        self.assertEqual(result["core_reference_condition"], "renamed_core")
        self.assertIsNone(result["vm_reference_condition"])
        self.assertEqual(result["conditions"]["protected"]["median_ratio_vs_core_reference"], 1)

    def test_output_mismatch_is_not_a_valid_benchmark(self):
        def runner(path, cases, timeout):
            value = 1 if path.parent.name == "baseline" else 2
            return {"status": "passed", "outputs": [value] * len(cases), "elapsed_seconds": 1}
        with self.assertRaisesRegex(ValueError, "differs from baseline"):
            benchmark(self.root, runner=runner)

    def test_execution_failure_is_not_a_valid_benchmark(self):
        with self.assertRaisesRegex(ValueError, "did not execute successfully"):
            benchmark(self.root, runner=lambda *_: {"status": "timeout"})

    def test_hash_mismatch_rejected(self):
        Path(self.report["builds"]["baseline"]["coverage"]["executable"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            resolve_builds(self.root, self.report)

    def test_outside_run_target_rejected(self):
        self.report["builds"]["baseline"]["coverage"]["executable"] = str(self.root.parent / "app.exe")
        with self.assertRaisesRegex(ValueError, "inside this run"):
            resolve_builds(self.root, self.report)


if __name__ == "__main__":
    unittest.main()
