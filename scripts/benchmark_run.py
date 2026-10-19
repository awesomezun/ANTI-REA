"""Benchmark already-built ANTI-REA fixtures; no model or attack calls.

Usage: python scripts/benchmark_run.py .runs/<run-id>
Writes performance.json only, leaving report.json and all inputs unchanged.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from antirea.judge import _run_binary, generate_cases  # noqa: E402


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def resolve_builds(run_dir: Path, report: dict) -> dict[str, dict]:
    """Only execute run-local binaries whose hash matches the build report."""
    run_dir = run_dir.resolve()
    builds = report.get("builds", {})
    if not isinstance(builds, dict) or "baseline" not in builds:
        raise ValueError("report needs builds.baseline")
    resolved = {}
    for name, build in builds.items():
        coverage = build.get("coverage", {})
        path = Path(coverage.get("executable") or run_dir / "defender" / name / "app.exe")
        if not path.is_absolute():
            path = run_dir / path
        path = path.resolve()
        if not path.is_relative_to(run_dir) or not path.is_file():
            raise ValueError(f"{name}: executable must be an existing file inside this run")
        expected = build.get("sha256") or coverage.get("executable_sha256")
        digest = sha256(path)
        if not expected or digest != str(expected).lower():
            raise ValueError(f"{name}: executable SHA256 differs from the build report")
        resolved[name] = {
            "executable": str(path), "executable_sha256": digest,
            "executable_bytes": path.stat().st_size,
            "protection": coverage.get("protection"),
        }
    return resolved


def summarize_timings(samples: list[float]) -> dict:
    if not samples or any(value <= 0 for value in samples):
        raise ValueError("timings must contain positive measurements")
    return {"samples_seconds": samples, "median_seconds": statistics.median(samples),
            "min_seconds": min(samples), "max_seconds": max(samples)}


def benchmark(run_dir: Path, *, count: int = 4096, warmups: int = 1,
              batches: int = 7, seed: int = 20261018, timeout: float = 30,
              runner=None) -> dict:
    """Check identical outputs in every batch before reporting timing ratios."""
    if not 1 <= warmups <= 10 or not 1 <= batches <= 100:
        raise ValueError("warmups must be 1..10 and batches must be 1..100")
    if not 0 < timeout <= 600:
        raise ValueError("timeout must be greater than zero and at most 600 seconds")
    run_dir = Path(run_dir).resolve()
    source_bytes = (run_dir / "report.json").read_bytes()
    source_report = json.loads(source_bytes.decode("utf-8-sig"))
    builds = resolve_builds(run_dir, source_report)
    cases = generate_cases(count, seed=seed)
    runner = _run_binary if runner is None else runner
    names = ["baseline"] + [name for name in builds if name != "baseline"]
    reference = None
    samples = {name: [] for name in names}
    orders = []
    for phase, repetitions in (("warmup", warmups), ("measured", batches)):
        for batch in range(repetitions):
            # Rotate order so one build is not always measured first/last.
            offset = 0 if phase == "warmup" else batch % len(names)
            order = names[offset:] + names[:offset]
            if phase == "measured":
                orders.append(order)
            for name in order:
                result = runner(Path(builds[name]["executable"]), cases, timeout)
                if result.get("status") != "passed":
                    raise ValueError(f"{name}: {phase} {batch + 1} did not execute successfully ({result.get('status')})")
                outputs = result.get("outputs", [])
                if len(outputs) != len(cases):
                    raise ValueError(f"{name}: output count differs from the case count")
                if reference is None:
                    reference = outputs
                if outputs != reference:
                    raise ValueError(f"{name}: {phase} {batch + 1} differs from baseline output")
                if phase == "measured":
                    samples[name].append(result["elapsed_seconds"])
    for name, build in builds.items():
        if sha256(Path(build["executable"])) != build["executable_sha256"]:
            raise ValueError(f"{name}: executable changed during the benchmark")

    conditions = {name: {**builds[name], **summarize_timings(samples[name]),
                         "output_equivalence": "passed", "verified_batches": warmups + batches}
                  for name in names}
    vm_reference = "vm_reference" if "vm_reference" in conditions else next(
        (name for name in names if builds[name]["protection"] == "vm"), None)
    core_reference = "core_reference" if "core_reference" in conditions else next(
        (name for name in names if builds[name]["protection"] == "core"), None)
    baseline_median = conditions["baseline"]["median_seconds"]
    vm_median = conditions[vm_reference]["median_seconds"] if vm_reference else None
    core_median = conditions[core_reference]["median_seconds"] if core_reference else None
    for result in conditions.values():
        result["median_ratio_vs_baseline"] = result["median_seconds"] / baseline_median
        result["median_ratio_vs_vm_reference"] = result["median_seconds"] / vm_median if vm_median else None
        result["median_ratio_vs_core_reference"] = result["median_seconds"] / core_median if core_median else None
    return {
        "schema_version": 1, "status": "completed", "run_id": source_report.get("run_id", run_dir.name),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "report_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "report_snapshot_status": source_report.get("status"),
        "case_count": len(cases), "case_seed": seed, "warmup_batches": warmups,
        "measured_batches": batches, "timeout_seconds_per_batch": timeout,
        "measured_order": orders, "vm_reference_condition": vm_reference,
        "core_reference_condition": core_reference,
        "conditions": conditions,
        "caveats": [
            "Wall time includes process startup, input serialization, decimal text I/O and process completion; not isolated function CPU time.",
            "One fixed boundary/correlated/random suite is reused across every condition and batch; no model or network calls.",
            "Results describe this synthetic fixture and machine, not general protection-engine overhead or resistance.",
            "Runtime code-generation settings may differ by protection profile; consult each build's coverage and command logs.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--cases", type=int, default=4096)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--batches", type=int, default=7)
    parser.add_argument("--seed", type=int, default=20261018)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--overwrite", action="store_true", help="Replace this run's existing performance.json only")
    args = parser.parse_args(argv)
    output = args.run_dir.resolve() / "performance.json"
    if output.exists() and not args.overwrite:
        parser.error("performance.json already exists; use --overwrite to replace only that benchmark result")
    try:
        result = benchmark(args.run_dir, count=args.cases, warmups=args.warmups,
                           batches=args.batches, seed=args.seed, timeout=args.timeout)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        result = {"schema_version": 1, "status": "error", "error": str(exc),
                  "caveat": "No valid performance comparison was established."}
    try:
        with output.open("w" if args.overwrite else "x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except OSError as exc:
        parser.error(f"cannot write performance.json: {exc}")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
