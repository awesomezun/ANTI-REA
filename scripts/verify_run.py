"""Recheck recorded binaries, submitted code, isolation and fresh functional cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from antirea.attack import TOOL_NAMES
from antirea.judge import differential, generate_cases, judge_candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--cases", type=int, default=4096)
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="Verify artifacts and already-scored submissions without completing missing attacks.")
    args = parser.parse_args()
    run = args.run.resolve()
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    if report["status"] != "completed" and not args.allow_incomplete:
        raise SystemExit("Cannot confirm a completed experiment: report is incomplete.")
    seed = secrets.randbits(256)
    cases = generate_cases(args.cases, seed)
    summary = {"run_id": report["run_id"], "experiment_status": report["status"],
               "scope": "Artifact verification; only already-submitted, scored candidates are rechecked. Missing attacks remain incomplete.",
               "new_hidden_cases": len(cases), "attacks": {}}
    baseline = run / "defender/baseline/app.exe"
    arms = list(report["builds"])
    summary["functional_by_arm"] = {}
    for name in arms:
        if name == "baseline":
            continue
        checked = differential(baseline, run / "defender" / name / "app.exe", cases, 30)
        summary["functional_by_arm"][name] = checked
        if checked["status"] != "passed":
            raise SystemExit(f"{name}: functional equivalence recheck failed.")
    summary["functional"] = summary["functional_by_arm"]["protected"]
    for name in arms:
        binary = run / "defender" / name / "app.exe"
        target = run / "targets" / name / "target.exe"
        expected = report["builds"][name]["sha256"]
        if any(hashlib.sha256(path.read_bytes()).hexdigest() != expected for path in (binary, target)):
            raise SystemExit(f"{name}: binary or attack-target hash changed.")
        attack_dir = Path(report["attacks"][name]["directory"])
        messages = [json.loads(line) for line in (attack_dir / "attacker.stdout.log").read_text(encoding="utf-8").splitlines()]
        init = next(m for m in messages if m.get("type") == "system" and m.get("subtype") == "init")
        allowed = {f"mcp__anti_rea__{tool}" for tool in TOOL_NAMES} | {"StructuredOutput"}
        if not set(init["tools"]).issubset(allowed):
            raise SystemExit(f"{name}: unexpected attacker capability.")
        audit = [json.loads(line) for line in (attack_dir / "bridge-audit.jsonl").read_text(encoding="utf-8").splitlines()]
        successful_rea = sum(bool(item["rea"]) and not item["error"] for item in audit)
        if not successful_rea:
            raise SystemExit(f"{name}: no successful REA use.")
        attempt = report["attacks"][name]
        if (attempt["attack"]["status"] != "candidate_submitted"
                or attempt.get("judge", {}).get("status") not in {"passed", "failed"}):
            summary["attacks"][name] = {"binary_sha256_verified": True,
                                       "unexpected_tools": [], "successful_rea_calls": successful_rea,
                                       "judge": {"status": "not_scored"},
                                       "reason": attempt["attack"]["status"]}
            continue
        candidate = (attack_dir / "candidate.py").read_text(encoding="utf-8")
        final = next(m for m in reversed(messages) if m.get("type") == "result")
        if candidate != final["structured_output"]["code"]:
            raise SystemExit(f"{name}: judged file differs from model's submission.")
        scored = judge_candidate(candidate, baseline, cases, 30)
        summary["attacks"][name] = {"binary_sha256_verified": True, "candidate_matches_transcript": True,
                                   "unexpected_tools": [], "successful_rea_calls": successful_rea,
                                   "judge": scored}
    summary["fresh_seed_defender_only"] = seed
    (run / "verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # The seed stays in the defender-side artifact, not the public console summary.
    print(json.dumps({k: v for k, v in summary.items() if k != "fresh_seed_defender_only"}, indent=2))
    return 0 if all(v["judge"]["status"] == report["attacks"][name]["judge"]["status"]
                    for name, v in summary["attacks"].items() if v["judge"]["status"] != "not_scored") else 2


if __name__ == "__main__":
    raise SystemExit(main())
