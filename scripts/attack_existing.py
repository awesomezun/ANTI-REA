"""Repeat fresh REA attacks on an existing artifact until recovery or STOP.

Never rebuilds or overwrites the historical report. A STOP file in the new
campaign directory cancels the currently owned attacker process tree. No hidden
cases, source, previous candidate or baseline result is sent to the attacker.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from antirea.attack import ATTACK_INTERFACE_VERSION, TOOL_NAMES, run_attack
from antirea.judge import differential, generate_cases, judge_candidate
from antirea.rea import ReaSession


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def complete_score(value, count):
    return (value.get("status") == "passed"
            and value.get("total") == count and value.get("matched") == count)


def submitted_code(attack_dir, attack, expected_hash):
    """Fail closed on incomplete submission, widened tools or wrong REA target."""
    if (attack.get("status") != "candidate_submitted"
            or attack.get("returncode") != 0 or attack.get("timed_out")
            or attack.get("cancelled") or attack.get("unexpected_tools")
            or attack.get("permission_denials") or not attack.get("rea_calls")):
        raise ValueError("No valid, isolated REA submission")
    messages = [json.loads(line) for line in
                (attack_dir / "attacker.stdout.log").read_text(encoding="utf-8").splitlines()]
    init = next(m for m in messages if m.get("type") == "system" and m.get("subtype") == "init")
    allowed = {f"mcp__anti_rea__{tool}" for tool in TOOL_NAMES} | {"StructuredOutput"}
    if not set(init.get("tools", [])).issubset(allowed):
        raise ValueError("Unexpected exposed capability")
    final = next(m for m in reversed(messages) if m.get("type") == "result")
    structured = final.get("structured_output")
    if not structured and isinstance(final.get("result"), str):
        structured = json.loads(final["result"])
    code = (attack_dir / "candidate.py").read_text(encoding="utf-8")
    if (final.get("subtype") != "success" or final.get("is_error")
            or not isinstance(structured, dict) or code != structured.get("code")):
        raise ValueError("Candidate differs from normal final model submission")
    opened = list((attack_dir / "rea").glob("*-open_binary.json"))
    if len(opened) != 1:
        raise ValueError("Missing unique REA target-open evidence")
    record = json.loads(opened[0].read_text(encoding="utf-8"))
    response = record.get("response", {}).get("result", {})
    payload = ReaSession.result_payload(response)
    opened_hash = payload.get("result", {}).get("sha256") if isinstance(payload, dict) else None
    if (record.get("error") or record.get("timeout") or record.get("response", {}).get("error")
            or response.get("isError") or opened_hash != expected_hash):
        raise ValueError("REA target hash does not match fixed artifact")
    return code


def campaign(root, source, destination, *, seconds=600, budget_usd=5.0, once=False):
    source = source.resolve()
    destination = destination.resolve()
    original_report = source / "report.json"
    original = json.loads(original_report.read_text(encoding="utf-8"))
    baseline = source / "defender/baseline/app.exe"
    protected = source / "defender/protected/app.exe"
    expected = {"baseline": original["builds"]["baseline"]["sha256"],
                "protected": original["builds"]["protected"]["sha256"]}
    original_hash = digest(original_report)
    destination.mkdir(parents=True, exist_ok=False)
    stop = destination / "STOP"
    target = destination / "target.exe"
    shutil.copy2(protected, target)
    report = {"schema_version": 1, "kind": "same_artifact_recovery_campaign",
              "campaign_id": destination.name, "source_run_id": original["run_id"],
              "source_report_sha256": original_hash, "started_utc": now(),
              "target": original["target"], "project": "ledger",
              "protection_profile": original["protection_profile"],
              "binary_sha256": expected, "binary_rebuilt": False,
              "prior_attacker_interface_version": original.get("attacker_interface_version"),
              "attacker_interface_version": ATTACK_INTERFACE_VERSION,
              "limits_per_attempt": {"seconds": seconds, "model_budget_usd": budget_usd,
                                     "black_box_pairs": 256, "tool_calls": 100},
              "context_policy": "Fresh sessions; no previous candidate, target source or private cases",
              "status": "preflight", "stop_marker": "STOP", "attempts": [],
              "workflow_sha256": {name: digest(root / name) for name in
                                  ("antirea/attack.py", "antirea/process.py", "antirea/bridge.py",
                                   "antirea/rea.py", "antirea/judge.py", "scripts/attack_existing.py")}}
    private = {"functional_seed": secrets.randbits(256), "attempts": []}
    for name in report["workflow_sha256"]:
        snapshot = destination / "workflow" / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, snapshot)

    def persist():
        report["updated_utc"] = now()
        costs = [item.get("attack", {}).get("cost_usd") for item in report["attempts"]]
        report["reported_cost_usd"] = sum(cost for cost in costs if cost is not None)
        report["unknown_cost_attempts"] = sum(cost is None for cost in costs)
        save(destination / "defender-private.json", private)
        save(destination / "report.json", report)

    def unchanged():
        if (digest(original_report) != original_hash or digest(baseline) != expected["baseline"]
                or digest(protected) != expected["protected"] or digest(target) != expected["protected"]):
            raise ValueError("Historical report or binary changed; refusing to continue")
        if any(digest(root / name) != value for name, value in report["workflow_sha256"].items()):
            raise ValueError("Workflow changed during campaign; refusing to mix versions")

    persist()
    print(json.dumps({"campaign": str(destination), "stop_marker": str(stop)}), flush=True)
    try:
        unchanged()
        report["functional"] = differential(baseline, target,
                                            generate_cases(1024, private["functional_seed"]), 30)
        if not complete_score(report["functional"], 1024):
            raise ValueError("Existing protection failed functional preflight")
        while not stop.exists():
            unchanged()
            number = len(report["attempts"]) + 1
            attack_dir = destination / f"attempt-{number:03d}"
            item = {"number": number, "directory": attack_dir.name, "started_utc": now(),
                    "status": "running", "judge": {"status": "not_scored"},
                    "verification": {"status": "not_scored"}}
            report["attempts"].append(item)
            report.update(status="attacking", current_attempt=number)
            persist()
            print(json.dumps({"attempt": number, "status": "attacking", "started_utc": now()}), flush=True)
            attack = run_attack(root, target, attack_dir, seconds=seconds,
                                budget_usd=budget_usd, cancel_file=stop)
            item.update(attack=attack, status=attack["status"], finished_attack_utc=now())
            unchanged()
            persist()
            if stop.exists() or attack.get("cancelled"):
                report.update(status="user_stopped", stop_reason="STOP marker")
                break
            if attack["status"] == "candidate_submitted":
                code = submitted_code(attack_dir, attack, expected["protected"])
                code_hash = digest(attack_dir / "candidate.py")
                item.update(status="judging", candidate_sha256=code_hash)
                report["status"] = "judging"
                seeds = {"number": number, "judge_seed": secrets.randbits(256)}
                private["attempts"].append(seeds)
                persist()
                item["judge"] = judge_candidate(code, baseline, generate_cases(1024, seeds["judge_seed"]), 30)
                if complete_score(item["judge"], 1024) and not stop.exists():
                    seeds["verification_seed"] = secrets.randbits(256)
                    persist()
                    item["verification"] = judge_candidate(
                        code, baseline, generate_cases(4096, seeds["verification_seed"]), 30)
                unchanged()
                if digest(attack_dir / "candidate.py") != code_hash:
                    raise ValueError("Candidate changed between independent checks")
                recovered = (complete_score(item["judge"], 1024)
                             and complete_score(item["verification"], 4096))
                item["status"] = "recovered" if recovered else "candidate_not_verified"
                if stop.exists():
                    report.update(status="user_stopped", stop_reason="STOP marker during judging")
                    break
                if recovered:
                    report.update(status="recovered", stop_reason="1024 and fresh 4096 private cases passed")
                    break
            if attack["status"] in {"isolation_error", "execution_error", "unevaluated_no_rea"}:
                report.update(status="needs_inspection", stop_reason=attack["status"])
                break
            persist()
            print(json.dumps({"attempt": number, "status": item["status"],
                              "judge": item["judge"], "verification": item["verification"]}), flush=True)
            if once:
                report.update(status="attempt_finished", stop_reason="--once")
                break
        if stop.exists() and report["status"] != "recovered":
            report.update(status="user_stopped", stop_reason="STOP marker")
    except KeyboardInterrupt:
        report.update(status="interrupted", stop_reason="KeyboardInterrupt; inspect partial process logs")
    except Exception as exc:
        report.update(status="needs_inspection", stop_reason=f"{type(exc).__name__}: {exc}")
    finally:
        report["finished_utc"] = now()
        persist()
    print(json.dumps({"status": report["status"], "report": str(destination / "report.json"),
                      "attempts": len(report["attempts"]), "reason": report.get("stop_reason")}), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_run", type=Path)
    parser.add_argument("--campaign-dir", type=Path)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--budget-usd", type=float, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600 or not 0 < args.budget_usd <= 100:
        parser.error("Require seconds 1..3600 and budget-usd >0..100")
    identity = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
    destination = args.campaign_dir or args.source_run / "recovery" / identity
    result = campaign(Path(__file__).resolve().parent.parent, args.source_run, destination,
                      seconds=args.seconds, budget_usd=args.budget_usd, once=args.once)
    return 0 if result["status"] in {"recovered", "user_stopped", "attempt_finished"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
