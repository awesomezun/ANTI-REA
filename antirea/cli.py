"""First Windows C++ -> Kagura -> REA -> independent recovery cycle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

from .attack import ATTACK_INTERFACE_VERSION, run_attack
from .judge import differential, generate_cases, judge_candidate
from .process import run_logged


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_FILES = ("antirea/cli.py", "antirea/attack.py", "antirea/bridge.py",
                  "antirea/judge.py", "antirea/process.py", "antirea/rea.py",
                  "antirea/scope.py", "scripts/build_sample.ps1", "scripts/build_context_sample.ps1")


def profile_arms(profile="vm"):
    """Ordered arms; all receive the same generated fixture and attack caps."""
    if profile == "vm":
        return (("baseline", "none"), ("protected", "vm"))
    if profile == "layered":
        return (("baseline", "none"), ("vm_reference", "vm"), ("protected", "layered"))
    if profile == "scoped":
        return (("baseline", "none"), ("core_reference", "core"), ("protected", "expanded"))
    raise ValueError(f"Unknown protection profile: {profile}")


def fixture_config(root, profile):
    """The scope pilot has real surrounding logic; older pilots stay unchanged."""
    if profile == "scoped":
        return (root / "samples/context_ledger", root / "scripts/build_context_sample.ps1",
                ("core.cpp", "main.cpp", "protection-policy.json", "public/interface.md"))
    return root / "samples/ledger", root / "scripts/build_sample.ps1", ("core.cpp", "main.cpp")


def report_arms(report):
    return profile_arms(report.get("protection_profile", "vm"))


def workflow_hashes(root):
    return {name: digest(root / name) for name in WORKFLOW_FILES if (root / name).is_file()}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def doctor(root=ROOT):
    paths = {"kagura": root / ".tools/kagura-toolchain.json", "rea": root / ".tools/rea/environment.json"}
    from .attack import claude_command
    try:
        attacker = claude_command()
    except RuntimeError:
        attacker = None
    return {"platform": sys.platform, "python": sys.version.split()[0],
            "kagura_ready": paths["kagura"].is_file(), "rea_ready": paths["rea"].is_file(),
            "claude_cli": attacker, "target": "windows-x86_64",
            "note": "Installation manifest checks only; run verifies actual build, protection, behavior and REA."}


def require_resume_limits(report, args):
    profile = getattr(args, "protection", "vm")
    profile_arms(profile)
    if profile != report.get("protection_profile", "vm"):
        raise RuntimeError("Resume must use the original protection profile. Use a fresh run for another profile.")
    limits = report["limits"]
    if (args.attack_seconds != limits["attack_seconds_each"]
            or args.budget_usd != limits["model_budget_usd_each"]
            or args.cases != limits["hidden_cases"]):
        raise RuntimeError("Resume must use the original attack time, cost and case limits. Use a fresh run for different comparison conditions.")


def scored_attempt(attempt):
    return (attempt.get("attack", {}).get("status") == "candidate_submitted"
            and attempt.get("judge", {}).get("status") in {"passed", "failed"})


def comparison_conditions(report):
    """Missing historical metadata cannot silently establish a fair comparison."""
    limits = report.get("limits", {})
    expected = {"seconds": limits.get("attack_seconds_each"),
                "model_budget_usd": limits.get("model_budget_usd_each"),
                "black_box_pairs": limits.get("black_box_pairs_each", 256),
                "tool_calls": limits.get("tool_calls_each", 100)}
    reasons, conditions, models = [], {}, set()
    expected_context_hash = None
    if "public_context" in report:
        from .attack import public_context_hash
        expected_context_hash = public_context_hash(report["public_context"])
    for name, _ in report_arms(report):
        attack = report.get("attacks", {}).get(name, {}).get("attack", {})
        model = attack.get("model")
        interface = attack.get("attacker_interface_version")
        conditions[name] = {"model": model, "attacker_interface_version": interface,
                            "limits": attack.get("limits"),
                            "public_context_sha256": attack.get("public_context_sha256")}
        if not isinstance(model, str) or not model.strip():
            reasons.append(f"{name}: model identity is missing")
        else:
            models.add(model)
        if interface != ATTACK_INTERFACE_VERSION:
            reasons.append(f"{name}: attacker interface is missing or differs from version {ATTACK_INTERFACE_VERSION}")
        if attack.get("limits") != expected:
            reasons.append(f"{name}: recorded attack limits are missing or differ from run limits")
        if expected_context_hash is not None and attack.get("public_context_sha256") != expected_context_hash:
            reasons.append(f"{name}: public context is missing or differs from the shared run context")
    if len(models) > 1:
        reasons.append("Attack models differ between arms")
    return {"comparable": not reasons, "reasons": reasons,
            "expected_limits": expected, "arms": conditions}


def finish_evaluation(report):
    """Separate valid scoring, comparable conditions, and defense interpretation."""
    attempts = {name: report.get("attacks", {}).get(name, {}) for name, _ in report_arms(report)}
    valid = all(scored_attempt(item) for item in attempts.values())
    report["status"] = "completed" if valid else "incomplete"
    comparison = report["comparison"] = comparison_conditions(report)
    protected = attempts["protected"]
    if not valid:
        report["interpretation"] = (
            "No clean evidence of relative defense strength: every arm must submit a valid, independently scored candidate. "
            "Missing or invalid results and exhausted budgets are not defense success.")
    elif protected["judge"]["status"] == "passed":
        report["interpretation"] = (
            "The attacker independently reproduced the protected function on all hidden cases in this pilot. "
            "Protection did not prevent this recovery under its recorded conditions. "
            "No conclusion about other programs or configurations.")
        if not comparison["comparable"]:
            report["interpretation"] += " Comparison conditions are unverified or different; no relative defense or timing claim is supported."
    elif not comparison["comparable"]:
        report["interpretation"] = (
            "No clean evidence of relative defense strength: model, attacker interface or limits are missing or different. "
            "Valid per-arm scores remain recorded; a failed candidate is not attributable to stronger protection.")
    elif (attempts["baseline"]["judge"]["status"] == "passed"
          and protected["attack"].get("tool_errors") == 0
          and protected["attack"].get("incomplete_page_tokens") == []):
        if "core_reference" in attempts and attempts["core_reference"]["judge"]["status"] == "passed":
            finding = "The baseline and core-only reference were recovered, but the expanded-scope candidate failed hidden tests"
        elif "core_reference" in attempts:
            finding = ("The baseline was recovered, but both core-only and expanded-scope candidates failed hidden tests; "
                       "this does not establish an incremental advantage for broader protection scope")
        elif "vm_reference" in attempts and attempts["vm_reference"]["judge"]["status"] == "passed":
            finding = "The baseline and VM-only reference were recovered, but the layered candidate failed hidden tests"
        elif "vm_reference" in attempts:
            finding = ("The baseline was recovered, but both VM-only and layered candidates failed hidden tests; "
                       "this does not establish an incremental advantage for layering")
        else:
            finding = "The baseline was recovered but the protected candidate failed hidden tests"
        report["interpretation"] = (finding + " in this one budgeted pilot. This is limited non-recovery, "
                                    "not proof of unbreakability or a measured general success rate.")
    else:
        report["interpretation"] = (
            "No clean evidence of relative defense strength: inspect baseline recovery, tool errors and unread response pages. "
            "Missing evidence and tool failures are not defense success.")


def require_build_coverage(name, profile, coverage):
    recorded_profile = coverage.get("protection")
    if recorded_profile is not None and recorded_profile != profile:
        raise RuntimeError(f"{name} coverage names a different protection profile.")
    if profile != "none" and not coverage.get("target_virtualized"):
        raise RuntimeError(f"{name}: target was not actually virtualized; refusing protected label.")
    if profile == "none" and coverage.get("target_virtualized"):
        raise RuntimeError("Baseline unexpectedly contains VM protection.")
    if profile in {"core", "expanded"}:
        scope = coverage.get("scope_plan", {})
        selected = coverage.get("selected_functions", [])
        functions = coverage.get("function_coverage", {})
        if (scope.get("status") != "ready" or scope.get("mode") != profile
                or not selected or set(selected) != set(scope.get("selected_functions", []))):
            raise RuntimeError(f"{name}: missing, unresolved or inconsistent protection scope.")
        if any(not functions.get(symbol, {}).get("virtualized") for symbol in selected):
            raise RuntimeError(f"{name}: one or more selected functions were not actually virtualized.")
        if coverage.get("public_boundaries_unvirtualized") is not True:
            raise RuntimeError(f"{name}: public presentation boundary coverage is unverified.")
    if profile == "layered":
        if recorded_profile != "layered" or not {"fla", "sub", "co", "vm"}.issubset(coverage.get("requested_core_passes", [])):
            raise RuntimeError("Layered profile lacks the required recorded pass configuration.")
        for field in ("pre_vm_evidence", "runtime_evidence"):
            evidence = coverage.get(field) or {}
            if (not evidence.get("function_found") or not evidence.get("fla_dispatcher")
                    or evidence.get("substitution_instructions", 0) < 1
                    or evidence.get("constant_obfuscation_instructions", 0) < 1):
                raise RuntimeError(f"Layered profile lacks required {field} structural evidence.")


def tool_versions(root, kagura, rea):
    lock_path = root / ".tools/rea/runtime/package-lock.json"
    return {"kagura_commit": kagura.get("kagura_commit"), "llvm": kagura.get("llvm_version"),
            "rea_version": rea.get("rea_version"), "rea_commit": rea.get("rea_commit"),
            "ghidra": rea.get("ghidra_version") or Path(rea.get("ghidra_install_dir", "")).name,
            "python": sys.version.split()[0], "rea_lock_sha256": digest(lock_path) if lock_path.is_file() else None,
            "kagura_optimizer_sha256": kagura.get("optimizer_sha256"),
            "kagura_runtime_sha256": kagura.get("runtime_sha256")}


def render_report(run_dir, report):
    arms = report_arms(report)
    profiles = dict(arms)
    lines = ["# ANTI-REA first-cycle experiment", "", f"Run: `{report['run_id']}`",
             f"Status: **{report['status']}**", "", "## Scope", "",
             f"Owned synthetic C++ integer computation; Windows x86-64; protection profile `{report.get('protection_profile', 'vm')}`.",
             "Arms: " + ", ".join(f"`{name}` = `{profile}`" for name, profile in arms) + ".",
             "All arms share fresh algorithm constants, functional/hidden test seeds, Kagura seed and attack caps.",
             "Fresh attacker contexts use REA/Ghidra via a target-scoped MCP bridge.",
             "Original C++ and hidden tests are not exposed through attacker tools.",
             "The same public Kagura engine-source access is available to every attacker, including non-VM passes.", "",
             "This is one pilot, not a general security claim or a macOS result.", ""]
    if report.get("protection_profile") == "scoped":
        lines.extend(["## Scope-selection pilot", "",
                      "The baseline, core-only VM and expanded-neighborhood VM arms use the same multi-function CLI fixture.",
                      "Protection strength is held at VM-only; the independent variable is the selected function set.",
                      "Public CLI interface text is available to every attacker. No graphical UI or screenshot analysis is implemented.",
                      "The selector follows declared roots, direct calls and data references in supplied LLVM IR. Reviewed presentation boundaries stop expansion; this is not proof of semantic secrecy.",
                      "Unresolved relevant dependencies and unprotected sensitive global data block the expanded build instead of silently shrinking coverage.", ""])
    versions = report.get("versions", {})
    lines.extend(["## Versions", "", "```json", json.dumps(versions, indent=2), "```", ""])
    if "error" in report:
        lines.extend(["## Execution issue", "", report["error"], ""])
    builds = report.get("builds", {})
    if builds:
        lines.extend(["## Artifacts", "", "| Build | Profile | Core passes | Bytes | SHA-256 | VM applied |",
                      "|---|---|---|---:|---|---|"])
        for name, info in builds.items():
            coverage = info["coverage"]
            passes = coverage.get("requested_core_passes")
            if passes is None:
                passes = ["vm"] if coverage.get("target_virtualized") else []
            elif isinstance(passes, str):
                # Older PowerShell manifests unwrapped singleton arrays.
                passes = [passes]
            lines.append(f"| {name} | {info.get('protection', profiles.get(name, 'unknown'))} | {', '.join(passes) or 'none'} | {info['bytes']} | `{info['sha256']}` | {coverage.get('target_virtualized', False)} |")
        lines.append("")
        for name, info in builds.items():
            coverage = info["coverage"]
            evidence = {key: coverage[key] for key in ("checks", "bytecode_sizes", "pre_vm_evidence", "runtime_evidence",
                                                       "scope_plan", "selected_functions", "function_coverage",
                                                       "public_boundaries_unvirtualized") if key in coverage}
            if evidence:
                lines.extend([f"### {name}: applied-pass evidence", "", "```json", json.dumps(evidence, indent=2), "```", ""])
    if "functional" in report:
        results = report.get("functional_by_arm", {"protected": report["functional"]})
        lines.extend(["## Functional equivalence", "", "Each protected arm is compared with the same baseline cases.",
                      "Batch timings include process startup and text I/O; they are not isolated kernel throughput.", ""])
        for name, result in results.items():
            lines.extend([f"`{name}`: {result['status']}; {result['matched']}/{result['total']} matching outputs.",
                          "```json", json.dumps(result, indent=2), "```", ""])
    lines.extend(["## Mandatory REA attacks", "", "| Target | Attack | Independent hidden tests | REA calls | Seconds | Model cost (USD) |",
                  "|---|---|---|---:|---:|---:|"])
    for name, _ in arms:
        attempt = report.get("attacks", {}).get(name, {})
        attack, judge = attempt.get("attack", {}), attempt.get("judge", {})
        score = (f"{judge['status']} {judge.get('matched', 0)}/{judge.get('total', 0)}" if scored_attempt(attempt)
                 else "not scored" + (f" ({judge['status']})" if judge.get("status") else ""))
        lines.append(f"| {name} | {attack.get('status', 'not run')} | {score} | {attack.get('rea_calls', 0)} | {attack.get('seconds', '')} | {attack.get('cost_usd', '')} |")
    if "comparison" in report:
        lines.extend(["", "## Comparison conditions", "", "```json", json.dumps(report["comparison"], indent=2), "```"])
    lines.extend(["", "## Interpretation", "", report.get("interpretation", "Evaluation has not completed."), "",
                  "Timeouts, missing tools, broken builds, invalid candidates and execution errors are not defense success.",
                  "Timing includes tool startup/import. One run per build cannot establish a success rate.",
                  "No performance threshold, held-out-program validation, advanced dynamic tracing or other OS was evaluated.", "",
                  "Full evidence: report.json; " + "; ".join(f"defender/{name}/coverage.json and IR" for name, _ in arms)
                  + "; attack/*/REA request logs, tool audit and transcript.", ""])
    (run_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    write_json(run_dir / "report.json", report)


def run_cycle(args):
    if os.name != "nt":
        raise RuntimeError("First implemented build adapter is Windows x86-64. macOS is not yet verified.")
    profile = getattr(args, "protection", "vm")
    arms = profile_arms(profile)
    fixture, build_script, fixture_files = fixture_config(ROOT, profile)
    public_context = None
    if profile == "scoped":
        public_context = {"kind": "cli_text", "title": "Public scoring application interface",
                          "description": (fixture / "public/interface.md").read_text(encoding="utf-8")}
    if args.resume:
        run_dir = Path(args.resume).resolve()
        report = read_json(run_dir / "report.json")
        private = read_json(run_dir / "defender/private.json")
        require_resume_limits(report, args)
        if report.get("status") == "completed":
            print(f"Already completed: {run_dir / 'report.md'}")
            return 0
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        run_dir = ROOT / ".runs" / run_id
        (run_dir / "defender").mkdir(parents=True)
        private = {"constants": [secrets.randbits(32) | 1 for _ in range(4)],
                   "functional_seed": secrets.randbits(256), "attack_test_seed": secrets.randbits(256),
                   "cases": args.cases, "kagura_seed": secrets.randbelow(2147483646) + 1}
        write_json(run_dir / "defender/private.json", private)
        config = "#pragma once\n" + "".join(f"#define ANTI_REA_K{i} 0x{value:08x}u\n" for i, value in enumerate(private["constants"]))
        (run_dir / "defender/generated_config.h").write_text(config, encoding="ascii")
        report = {"schema_version": 2, "run_id": run_id, "status": "running", "target": "windows-x86_64",
                  "protection_profile": profile, "arm_profiles": dict(arms),
                  "attacker_interface_version": ATTACK_INTERFACE_VERSION,
                  "started_utc": datetime.now(timezone.utc).isoformat(), "builds": {}, "attacks": {},
                  "limits": {"attack_seconds_each": args.attack_seconds, "model_budget_usd_each": args.budget_usd,
                             "black_box_pairs_each": 256, "tool_calls_each": 100, "hidden_cases": args.cases},
                  "fixture": fixture.name,
                  "source_hashes": {name: digest(fixture / name) for name in fixture_files},
                  "workflow_hashes": workflow_hashes(ROOT)}
        if public_context is not None:
            report["public_context"] = public_context
    report.setdefault("protection_profile", profile)
    report.setdefault("arm_profiles", dict(arms))
    render_report(run_dir, report)
    print(f"Run: {run_dir}", flush=True)
    try:
        tools = doctor()
        if not tools["kagura_ready"] or not tools["rea_ready"] or not tools["claude_cli"]:
            raise RuntimeError(f"Prerequisites missing: {tools}. Run python -m antirea bootstrap.")
        kagura = read_json(ROOT / ".tools/kagura-toolchain.json")
        rea = read_json(ROOT / ".tools/rea/environment.json")
        versions = tool_versions(ROOT, kagura, rea)
        if args.resume and report.get("versions") != versions:
            raise RuntimeError("Toolchain provenance changed since this run; create a fresh run.")
        if args.resume and "workflow_hashes" in report and report["workflow_hashes"] != workflow_hashes(ROOT):
            raise RuntimeError("Runner, build or evaluation implementation changed since this run; create a fresh run.")
        report["versions"] = versions
        if any(digest(fixture / name) != value for name, value in report["source_hashes"].items()):
            raise RuntimeError("Fixture source changed since this run; create a fresh run.")
        for name, arm_profile in arms:
            destination = run_dir / "defender" / name
            if name in report["builds"]:
                existing = report["builds"][name]
                if digest(destination / "app.exe") != existing["sha256"]:
                    raise RuntimeError("Previously recorded binary changed; create a fresh run.")
                if existing.get("coverage_sha256") and digest(destination / "coverage.json") != existing["coverage_sha256"]:
                    raise RuntimeError("Previously recorded protection evidence changed; create a fresh run.")
                require_build_coverage(name, arm_profile, existing["coverage"])
                continue
            print(f"Building {name} ({arm_profile})...", flush=True)
            cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                   str(build_script), "-SourceDir", str(fixture),
                   "-OutputDir", str(destination), "-ConfigInclude", str(run_dir / "defender"),
                   "-Protection", arm_profile, "-Seed", str(private["kagura_seed"])]
            built = run_logged(cmd, ROOT, run_dir / "defender" / f"build-{name}", 600)
            if built["returncode"] != 0 or built["timed_out"]:
                raise RuntimeError(f"{name} build failed; see {built['stderr']} and {built['stdout']}.")
            coverage = read_json(destination / "coverage.json")
            require_build_coverage(name, arm_profile, coverage)
            binary = destination / "app.exe"
            report["builds"][name] = {"sha256": digest(binary), "bytes": binary.stat().st_size,
                                      "protection": arm_profile, "coverage": coverage,
                                      "coverage_sha256": digest(destination / "coverage.json")}
            render_report(run_dir, report)
        baseline = run_dir / "defender/baseline/app.exe"
        cases = generate_cases(private["cases"], private["functional_seed"])
        report["functional_by_arm"] = {}
        for name, arm_profile in arms:
            if arm_profile == "none":
                continue
            binary = run_dir / "defender" / name / "app.exe"
            report["functional_by_arm"][name] = differential(baseline, binary, cases, timeout_seconds=30)
            if name == "protected":
                report["functional"] = report["functional_by_arm"][name]
            render_report(run_dir, report)
        if any(result["status"] != "passed" for result in report["functional_by_arm"].values()):
            raise RuntimeError("Protection did not pass functional equivalence; no defense claim and no valid attack comparison.")
        print(f"Functional equivalence: {len(cases)}/{len(cases)}. Starting mandatory REA attacks.", flush=True)
        private_tests = generate_cases(private["cases"], private["attack_test_seed"])
        for name, _ in arms:
            binary = run_dir / "defender" / name / "app.exe"
            previous = report["attacks"].get(name, {})
            if scored_attempt(previous):
                continue
            attempt_id = len(list((run_dir / "attack").glob(f"{name}-*"))) + 1
            attack_dir = run_dir / "attack" / f"{name}-{attempt_id}"
            # Target-only copy: no PDB, source, IR, build headers or judge data.
            public_dir = run_dir / "targets" / name
            public_dir.mkdir(parents=True, exist_ok=True)
            target = public_dir / "target.exe"
            shutil.copy2(binary, target)
            print(f"REA attack: {name}, attempt {attempt_id}, {args.attack_seconds}s cap...", flush=True)
            context_args = {"public_context": public_context} if public_context is not None else {}
            attack = run_attack(ROOT, target, attack_dir, seconds=args.attack_seconds,
                                budget_usd=args.budget_usd, **context_args)
            attempt = {"directory": str(attack_dir), "attack": attack}
            if attack["status"] == "candidate_submitted":
                attempt["judge"] = judge_candidate((attack_dir / "candidate.py").read_text(encoding="utf-8"),
                                                     baseline, private_tests, timeout_seconds=30)
            report["attacks"][name] = attempt
            render_report(run_dir, report)
            print(f"{name}: {attack['status']}; judge={attempt.get('judge', {}).get('status', 'not scored')}", flush=True)
        finish_evaluation(report)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        report.pop("error", None)
    except Exception as exc:
        report["status"] = "incomplete"
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["interpretation"] = "Execution is incomplete; this is not a defense success. Fix the recorded issue and resume or create a fresh run."
    render_report(run_dir, report)
    print(f"{report['status']}: {run_dir / 'report.md'}", flush=True)
    return 0 if report["status"] == "completed" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check local installation manifests and attacker CLI.")
    commands.add_parser("bootstrap", help="Install pinned portable Kagura/REA dependencies inside .tools (Windows).")
    scope_parser = commands.add_parser("scope", help="Explain a conservative function protection scope from supplied LLVM IR and reviewed policy.")
    scope_parser.add_argument("--ir", action="append", type=Path, required=True)
    scope_parser.add_argument("--policy", type=Path, required=True)
    scope_parser.add_argument("--mode", choices=("core", "expanded"), default="expanded")
    scope_parser.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run", help="Build, protect, verify, REA-attack all profile arms, independently judge and report.")
    run.add_argument("--protection", choices=("vm", "layered", "scoped"), default="vm",
                     help="vm: two arms; layered: VM-strength comparison; scoped: baseline/core-only/expanded function scope.")
    run.add_argument("--attack-seconds", type=int, default=600)
    run.add_argument("--budget-usd", type=float, default=5.0)
    run.add_argument("--cases", type=int, default=1024)
    run.add_argument("--resume", type=Path, help="Continue an incomplete run without sharing prior attack context.")
    args = parser.parse_args()
    if args.command == "scope":
        from .scope import analyze_scope
        try:
            manifest = analyze_scope(args.ir, read_json(args.policy), mode=args.mode)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.output, manifest)
            print(json.dumps({"status": manifest["status"], "selected_functions": manifest["selected_functions"],
                              "manifest": str(args.output.resolve())}, indent=2))
            return 0 if manifest["status"] == "ready" else 2
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Cannot select scope: {exc}", file=sys.stderr)
            return 2
    if args.command == "doctor":
        print(json.dumps(doctor(), indent=2))
        return 0
    if args.command == "bootstrap":
        if os.name != "nt":
            parser.error("The first bootstrap adapter supports Windows only.")
        for name in ("kagura", "rea"):
            proc = run_logged(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                               str(ROOT / f"scripts/bootstrap_{name}.ps1")], ROOT, ROOT / ".tools" / f"bootstrap-{name}", 1800)
            if proc["returncode"] != 0 or proc["timed_out"]:
                print(json.dumps(proc, indent=2))
                return 2
        return 0
    if not 30 <= args.attack_seconds <= 3600 or not 0 < args.budget_usd <= 50 or not 300 <= args.cases <= 100000:
        parser.error("Use 30..3600 attack seconds, 0<budget<=50 USD per attack, and 300..100000 cases.")
    try:
        return run_cycle(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Cannot start experiment: {exc}", file=sys.stderr)
        return 2
