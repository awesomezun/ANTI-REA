"""Validate trusted defender-built ledger binaries; never attack or publish.

All output is defender-private. This executes only explicitly selected local
builds, not incoming reports or attacker-submitted programs. Passing establishes
sampled functional preservation and declared engineering limits, not resistance.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import re
import secrets
import statistics
import stat

from .judge import U32_MAX, U64_MAX, _run_binary, generate_cases


EXPECTED_BASELINE_SHA256 = "52b83cd0cdb6f5943738652dbe989be54efbbe7509b5f3d39b2a2210e33deea2"
EXPECTED_PREVIOUS_SHA256 = "d03fc9b1f95b00f4d7bd217e5d6fa9351a861259e170596b72a5665de4dd2bc8"
MIN_RANDOM_CASES = 8192
REPEATS = 2
WARMUPS = 1
MEASURED_BATCHES = 7
LIMITS = {"candidate_vs_previous": 10.0, "candidate_vs_baseline": 200.0,
          "candidate_bytes": 16 * 1024 * 1024}
ARMS = ("baseline", "previous", "candidate")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def private_cases(random_count: int = MIN_RANDOM_CASES) -> dict:
    if type(random_count) is not int or not MIN_RANDOM_CASES <= random_count <= 99_000:
        raise ValueError("random_count must be 8192..99000")
    seed, edge_seed = secrets.randbits(256), secrets.randbits(256)
    # generate_cases starts with all 13*13 boundary pairs and 64 correlated pairs
    # of each kind (x,x and x,~x). Keep those separate from fresh random samples.
    edges = list(dict.fromkeys(generate_cases(297, seed=edge_seed)))
    seen = set(edges)
    rng = random.Random(seed)
    pairs = []
    while len(pairs) < random_count:
        pair = (rng.getrandbits(32), rng.getrandbits(32))
        if pair not in seen:
            pairs.append(pair)
            seen.add(pair)
    return {"classification": "DEFENDER PRIVATE: never publish or sync",
            "random_seed": seed, "edge_seed": edge_seed,
            "random_pairs": pairs, "edge_correlated_pairs": edges}


def _positive_int(value, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _trusted_previous_manifest(value: Path) -> Path:
    """Read only a caller-selected local manifest, never incoming peer material."""
    path = Path(value).absolute()
    if "rea-analysis-reports" in {part.lower() for part in path.parts}:
        raise ValueError("previous manifest must not come from the incoming reports folder")
    for entry in (path, *path.parents):
        attributes = entry.lstat()
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, "st_file_attributes", 0) & 0x400:
            raise ValueError("previous manifest must not traverse a symlink or reparse point")
    if not path.is_file() or not 0 < path.stat().st_size <= 65_536:
        raise ValueError("previous manifest must be a local JSON file of at most 64KiB")
    return path.resolve()


def _previous_identity(path: Path) -> tuple[str, int]:
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sha256"), str):
        raise ValueError("previous manifest needs sha256 and bytes")
    digest = manifest["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("previous manifest sha256 must be lowercase 64-digit hex")
    return digest, _positive_int(manifest.get("bytes"), "previous manifest bytes")


def _local_artifact(value, directory: Path, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} needs an explicit path")
    path = Path(value)
    if not path.is_absolute():
        path = directory / path
    if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
        raise ValueError(f"{label} must be a non-link artifact inside the candidate build")
    if not path.is_file():
        raise ValueError(f"{label} artifact is missing")
    return path.resolve()


def _function_body(text: str, symbol: str) -> str:
    match = re.search(r"(?ms)^define\s+[^\r\n]*@" + re.escape(symbol)
                      + r"\([^\r\n]*\)[^\r\n]*\{\r?\n(.*?)^\}", text)
    if not match:
        raise ValueError(f"IR definition missing for {symbol}")
    return match.group(1)


def _ir_bytes(text: str, name: str) -> bytes:
    name = name.removeprefix("@")
    if not re.fullmatch(r"[A-Za-z0-9_.$-]+", name):
        raise ValueError("invalid bytecode global name")
    match = re.search(r"(?m)^@" + re.escape(name)
                      + r'\s*=\s*[^\r\n]*?constant\s+\[(\d+) x i8\]\s+c"([^"\r\n]*)"', text)
    if not match:
        raise ValueError(f"bytecode constant missing: {name}")
    encoded = match.group(2)
    data = bytearray()
    offset = 0
    while offset < len(encoded):
        if encoded[offset] == "\\":
            escape = encoded[offset + 1:offset + 3]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", escape):
                raise ValueError("unsupported LLVM byte string escape")
            data.append(int(escape, 16))
            offset += 3
        else:
            if ord(encoded[offset]) > 127:
                raise ValueError("non-ASCII LLVM byte string")
            data.append(ord(encoded[offset]))
            offset += 1
    if len(data) != int(match.group(1)) or not data:
        raise ValueError("LLVM bytecode length mismatch")
    return bytes(data)


def protection_gate(coverage_path: Path, candidate: Path, candidate_hash: str) -> dict:
    """Validate concrete local artifacts, not a producer's status-only assertion."""
    coverage = json.loads(coverage_path.read_text(encoding="utf-8-sig"))
    if not isinstance(coverage, dict):
        raise ValueError("coverage must be an object")
    if (coverage.get("protection") != "diversified-layered"
            or coverage.get("target_function") != "antirea_score"
            or coverage.get("target_virtualized") is not True
            or coverage.get("nonempty_bytecode") is not True
            or coverage.get("executable_sha256") != candidate_hash):
        raise ValueError("coverage does not bind a diversified protected target to this executable")
    directory = candidate.resolve().parent
    executable = _local_artifact(coverage.get("executable"), directory, "executable")
    if executable != candidate.resolve():
        raise ValueError("coverage executable path differs from candidate")
    _positive_int(coverage.get("vm_call_count"), "vm_call_count")
    _positive_int(coverage.get("bytecode_blob_count"), "bytecode_blob_count")
    manifest_path = _local_artifact(coverage.get("diversification_manifest"), directory, "diversification_manifest")
    manifest_hash = sha256(manifest_path)
    if manifest_hash != coverage.get("diversification_sha256"):
        raise ValueError("diversification manifest hash mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest != coverage.get("diversification") or not isinstance(manifest, dict):
        raise ValueError("embedded diversification differs from the manifest")
    if (manifest.get("format_version") not in (1, 2) or manifest.get("opcode_bits") != 16
            or manifest.get("operand_byte_order") != "big"
            or manifest.get("stock_format_directly_compatible") is not False):
        raise ValueError("diversification format contract is missing")
    dispatcher = manifest.get("dispatcher_symbol")
    if not isinstance(dispatcher, str) or not re.fullmatch(r"antirea_dispatch_[0-9a-fA-F]+", dispatcher):
        raise ValueError("unexpected generated dispatcher symbol")
    runtime_evidence = coverage.get("runtime_evidence", {})
    if not isinstance(runtime_evidence, dict):
        raise ValueError("runtime evidence must be an object")
    artifacts = {
        "after_ir": (coverage.get("after_ir"), manifest.get("output_ir_sha256")),
        "generated_runtime": (coverage.get("generated_runtime"), manifest.get("generated_runtime_sha256")),
        "runtime_after_ir": (runtime_evidence.get("ir"), coverage.get("runtime_after_ir_sha256")),
    }
    paths, artifact_hashes = {}, {}
    for label, (value, expected) in artifacts.items():
        paths[label] = _local_artifact(value, directory, label)
        digest = sha256(paths[label])
        if digest != expected:
            raise ValueError(f"{label} hash mismatch")
        artifact_hashes[label] = digest
    ir = paths["after_ir"].read_text(encoding="utf-8")
    body = _function_body(ir, "antirea_score")
    calls = len(re.findall(r"\bcall\s+i64\s+@" + re.escape(dispatcher) + r"\(", body))
    if calls < 1 or calls != coverage["vm_call_count"]:
        raise ValueError("target wrapper does not call the claimed dispatcher")
    blobs = manifest.get("blobs")
    if not isinstance(blobs, list) or not blobs or len(blobs) != coverage["bytecode_blob_count"]:
        raise ValueError("bytecode manifest count mismatch")
    checked_blobs = []
    names = set()
    for blob in blobs:
        if not isinstance(blob, dict) or not isinstance(blob.get("global"), str):
            raise ValueError("invalid bytecode record")
        name = blob["global"].removeprefix("@")
        if name in names:
            raise ValueError("duplicate bytecode global")
        names.add(name)
        payload = _ir_bytes(ir, name)
        for field in ("original_bytes", "encoded_bytes", "original_instructions", "emitted_instructions",
                      "fused_groups", "absorbed_dispatches"):
            _positive_int(blob.get(field), field)
        if (len(payload) != blob["encoded_bytes"]
                or hashlib.sha256(payload).hexdigest() != blob.get("encoded_sha256")
                or blob.get("stock_first_opcode_after_original_xor") != 254
                or not re.search(r"@" + re.escape(name) + r"\b", body)):
            raise ValueError("encoded blob evidence does not match target IR")
        checked_blobs.append({"global": name, "bytes": len(payload),
                              "sha256": blob["encoded_sha256"], "fused_groups": blob["fused_groups"],
                              "absorbed_dispatches": blob["absorbed_dispatches"]})
    runtime_ir = paths["runtime_after_ir"].read_text(encoding="utf-8")
    runtime_body = _function_body(runtime_ir, dispatcher)
    sub_count = len(re.findall(r"(?m)^\s+%sub\.[^\r\n]*=", runtime_body))
    co_count = len(re.findall(r"(?m)^\s+%co\.[^\r\n]*=", runtime_body))
    operand_evidence = None
    helper_evidence = None
    chain_evidence = None
    if manifest["format_version"] == 2:
        runtime_source = paths["generated_runtime"].read_text(encoding="utf-8")
        if (manifest.get("fetch_inlined_in_dispatcher") is not True
                or manifest.get("operand_encoding") != "instruction-position/opcode/key context with plaintext feedback; resets at every instruction"
                or "uint32_t operand_state;" not in runtime_source
                or "uint16_t op = bc_opcode(&f);" not in runtime_source
                or "f->operand_state=rotated*" not in runtime_source
                or re.search(r"(?m)^define[^\n]*@bc_(?:raw8|opcode|u8|u16|u32|u64)\(", runtime_ir)
                or re.search(r"\bcall\b[^\n]*@bc_(?:raw8|opcode|u8|u16|u32|u64)\(", runtime_body)):
            raise ValueError("v2 operand context or dispatcher fetch inlining evidence missing")
        operand_evidence = {"instruction_context": True, "plaintext_feedback": True,
                            "fetch_reader_definitions_after_passes": 0,
                            "fetch_reader_calls_in_dispatcher": 0}
    if "semantic_helpers_inlined_in_dispatcher" in manifest:
        claim = manifest["semantic_helpers_inlined_in_dispatcher"]
        known = {"push", "pop", "peek", "width", "mask", "zext", "sext", "shamt"}
        if claim is True:
            claimed = sorted(known)
        elif (isinstance(claim, list) and claim
              and all(isinstance(name, str) and name in known for name in claim)
              and len(set(claim)) == len(claim)):
            claimed = claim
        else:
            raise ValueError("semantic helper integration claim must name supported unique helpers")
        helpers = r"vm_(?:" + "|".join(claimed) + r")"
        if (re.search(r"(?m)^define[^\n]*@" + helpers + r"\(", runtime_ir)
                or re.search(r"\b(?:call|invoke)\b[^\n]*@" + helpers + r"\(", runtime_body)):
            raise ValueError("semantic helper integration evidence missing")
        helper_evidence = {"separate_definitions_after_passes": 0,
                           "calls_in_dispatcher": 0, "claimed_helpers": claimed}
    if "chained_register_fusion" in manifest:
        claim = manifest['chained_register_fusion']
        if (not isinstance(claim, dict) or type(claim.get('groups')) is not int
                or claim['groups'] < 1 or claim.get('operations_per_group') != 2
                or type(claim.get('operations_per_group')) is not int
                or claim.get('semantics') != 'sequential direct expressions with both intermediate register writes retained'):
            raise ValueError('invalid chained register fusion claim')
        counts = {}
        for blob in blobs:
            fusion_counts = blob.get('fusion_counts')
            if not isinstance(fusion_counts, dict):
                raise ValueError('chained register fusion counts missing')
            for name, count in fusion_counts.items():
                if name.startswith('F_CHAIN_'):
                    if not re.fullmatch(r'F_CHAIN_R[RI]_[A-Z]+__R[RI]_[A-Z]+', name):
                        raise ValueError('invalid chained register handler name')
                    _positive_int(count, 'chained handler count')
                    counts[name] = counts.get(name, 0) + count
        if sum(counts.values()) != claim['groups']:
            raise ValueError('chained register fusion count mismatch')
        source = paths['generated_runtime'].read_text(encoding='utf-8')
        for name in counts:
            handler = re.search(r'(?m)^\s*case ' + re.escape(name) + r': ([^\n]+)$', source)
            if (not handler or handler[1].count('f.regs[d]=') != 2
                    or handler[1].count('unsigned w=vm_width(&f);') != 2
                    or any(word in handler[1] for word in ('bc_opcode', 'vm_push', 'vm_pop', 'switch'))):
                raise ValueError('chained register direct-expression evidence missing')
        chain_evidence = {'groups': claim['groups'], 'distinct_handlers': len(counts),
                          'operations_per_group': 2, 'intermediate_register_writes': 'retained'}
    if (runtime_evidence.get("function") != dispatcher
            or runtime_evidence.get("fla_dispatcher") is not True
            or set(runtime_evidence.get("requested_passes", [])) != {"fla", "sub", "co"}
            or runtime_evidence.get("nested_vm") is not False
            or "kagura.loop:" not in runtime_body or "switch i32" not in runtime_body
            or sub_count < 1 or co_count < 1
            or runtime_evidence.get("substitution_instructions") != sub_count
            or runtime_evidence.get("constant_obfuscation_instructions") != co_count):
        raise ValueError("runtime FLA/SUB/CO structural evidence mismatch")
    return {"status": "passed", "evidence": {
        "coverage_sha256": sha256(coverage_path), "manifest_sha256": manifest_hash,
        "artifact_hashes": artifact_hashes, "target_vm_calls": calls,
        "artifact_paths": {label: str(path) for label, path in paths.items()},
        "manifest_path": str(manifest_path),
        "dispatcher": dispatcher, "blobs": checked_blobs,
        "semantic_helper_integration": helper_evidence,
        "chained_register_fusion": chain_evidence,
        "operand_context": operand_evidence,
        "runtime_substitution_instructions": sub_count,
        "runtime_constant_obfuscation_instructions": co_count,
        "qualification": "Artifact consistency and IR structure only; transformation counts and format guard are not resistance proof."}}


class ExecutionFailure(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status if status in {"timeout", "error", "failed"} else "error"


def _execute(path: Path, cases, timeout: float, runner, record, log_path: Path) -> dict:
    try:
        result = runner(path, cases, timeout)
    except Exception as exc:
        result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    if not isinstance(result, dict):
        result = {"status": "error", "error": "runner returned no valid result"}
    if result.get("status") == "passed":
        outputs = result.get("outputs")
        elapsed = result.get("elapsed_seconds")
        if (not isinstance(outputs, list) or len(outputs) != len(cases)
                or any(type(v) is not int or not 0 <= v <= U64_MAX for v in outputs)
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0):
            result = {"status": "error", "error": "invalid outputs or timing from binary runner"}
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({**record, **{k: v for k, v in result.items() if k != "outputs"}},
                                allow_nan=False) + "\n")
    if result.get("status") != "passed":
        raise ExecutionFailure(result.get("status", "error"),
                               f"{record['arm']}: {result.get('error', 'execution incomplete')}")
    return result


def functional_gate(paths: dict, cases, timeout, runner, log_path: Path) -> tuple[dict, list[int]]:
    reference = None
    checks = []
    for repeat in range(REPEATS):
        for arm in ARMS:
            result = _execute(paths[arm], cases, timeout, runner,
                              {"phase": "functional", "repeat": repeat + 1, "arm": arm}, log_path)
            if reference is None:
                reference = result["outputs"]
            matched = sum(a == b for a, b in zip(reference, result["outputs"]))
            checks.append({"arm": arm, "repeat": repeat + 1, "matched": matched,
                           "total": len(cases), "seconds": result["elapsed_seconds"]})
            if matched != len(cases):
                return ({"status": "failed", "total": len(cases), "matched": matched,
                         "repeats": repeat + 1, "checks": checks,
                         "error": f"{arm} output mismatch or non-determinism"}, reference)
    return ({"status": "passed", "total": len(cases), "matched": len(cases),
             "repeats": REPEATS, "checks": checks}, reference)


def performance_gate(paths: dict, cases, reference, timeout, runner, log_path: Path) -> dict:
    samples = {arm: [] for arm in ARMS}
    orders = []
    for phase, count in (("warmup", WARMUPS), ("measured", MEASURED_BATCHES)):
        for batch in range(count):
            offset = batch % len(ARMS)
            order = ARMS[offset:] + ARMS[:offset]
            if phase == "measured":
                orders.append(list(order))
            for arm in order:
                result = _execute(paths[arm], cases, timeout, runner,
                                  {"phase": phase, "batch": batch + 1, "arm": arm}, log_path)
                if result["outputs"] != reference:
                    raise ExecutionFailure("failed", f"{arm}: benchmark output mismatch or non-determinism")
                if phase == "measured":
                    samples[arm].append(result["elapsed_seconds"])
    conditions = {arm: {"samples_seconds": times, "median_seconds": statistics.median(times),
                         "min_seconds": min(times), "max_seconds": max(times),
                         "bytes": paths[arm].stat().st_size} for arm, times in samples.items()}
    candidate = conditions["candidate"]
    ratios = {"candidate_vs_previous": candidate["median_seconds"] / conditions["previous"]["median_seconds"],
              "candidate_vs_baseline": candidate["median_seconds"] / conditions["baseline"]["median_seconds"]}
    passed = (all(value <= LIMITS[name] for name, value in ratios.items())
              and candidate["bytes"] <= LIMITS["candidate_bytes"])
    return {"status": "passed" if passed else "failed", "conditions": conditions,
            "ratios": ratios, "limits": dict(LIMITS), "orders": orders,
            "warmups": WARMUPS, "measured_batches": MEASURED_BATCHES,
            "case_count": len(cases),
            "measurement": "Wall-clock end-to-end process startup, input serialization, decimal I/O and completion; not isolated function CPU time."}


def _markdown(report: dict) -> str:
    lines = ["# Defender validation", "", f"Status: {report['status']}", "",
             "This report is defender-private. Passing is not an external attack result.", "",
             f"Candidate SHA-256: `{report.get('candidate_sha256')}`", "",
             "| Gate | Status |", "|---|---|"]
    for name in ("functional", "protection", "performance", "integrity"):
        lines.append(f"| {name} | {report.get(name, {}).get('status', 'not_run')} |")
    lines += ["", "Predeclared limits: candidate/previous <= 10x; candidate/baseline <= 200x; candidate <= 16 MiB.",
              "", "Functional suite: at least 8,192 unique fresh random pairs plus separate boundaries/correlated pairs, repeated twice.",
              "", "Timing: one warmup and seven rotated batches, including process startup and decimal I/O.",
              "", "No publication or attack was performed. Errors/timeouts are not passes."]
    if report.get("error"):
        lines += ["", f"Error: {report['error']}"]
    return "\n".join(lines) + "\n"


def validate(baseline: Path, previous: Path, candidate: Path, coverage: Path, output_dir: Path,
             *, random_count: int = MIN_RANDOM_CASES, timeout_seconds: float = 120,
             previous_manifest: Path | None = None, runner=None) -> dict:
    """Create a NEW private validation directory; refuse to overwrite history."""
    output_dir = Path(output_dir).resolve()
    if {part.lower() for part in output_dir.parts} & {"attackerfolder", "rea-analysis-reports"}:
        raise ValueError("validation output must not be inside known synchronization folders")
    output_dir.mkdir(parents=True, exist_ok=False)
    paths = {"baseline": Path(baseline).resolve(), "previous": Path(previous).resolve(),
             "candidate": Path(candidate).resolve(), "coverage": Path(coverage).resolve()}
    report = {"schema_version": 1, "status": "running", "started_utc": now(),
              "baseline_sha256": None, "previous_sha256": None, "candidate_sha256": None,
              "limits": dict(LIMITS),
              "timeout_seconds_per_execution": timeout_seconds if type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds) else None,
              "functional": {"status": "not_run", "total": None, "matched": None, "repeats": 0},
              "protection": {"status": "not_run", "evidence": {}},
              "performance": {"status": "not_run"}, "integrity": {"status": "not_run"},
              "external_evaluation": "not_performed", "published": False}
    before = {}
    phase = "preflight"
    try:
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be finite and within 0..600")
        if any("rea-analysis-reports" in {part.lower() for part in path.parts} for path in paths.values()):
            raise ValueError("execution and coverage inputs must not come from incoming reports")
        if previous_manifest is not None:
            paths["previous_manifest"] = _trusted_previous_manifest(previous_manifest)
        before = {name: sha256(path) for name, path in paths.items()}
        report.update({f"{arm}_sha256": before[arm] for arm in ARMS})
        if before["baseline"] != EXPECTED_BASELINE_SHA256:
            raise ValueError("baseline differs from fixed original ledger artifact")
        if previous_manifest is None:
            expected_previous, previous_size = EXPECTED_PREVIOUS_SHA256, None
            report["previous_identity"] = {"source": "fixed_original_layered_artifact", "sha256": expected_previous}
        else:
            expected_previous, previous_size = _previous_identity(paths["previous_manifest"])
            report["previous_identity"] = {"source": "trusted_local_manifest",
                "manifest_sha256": before["previous_manifest"], "sha256": expected_previous, "bytes": previous_size}
        if before["previous"] != expected_previous or (previous_size is not None and paths["previous"].stat().st_size != previous_size):
            raise ValueError("previous differs from the pinned original artifact or trusted manifest hash/size")
        if len({paths[arm] for arm in ARMS}) != 3:
            raise ValueError("baseline, previous and candidate must be distinct paths")
        if paths["candidate"].stat().st_size > LIMITS["candidate_bytes"]:
            report["performance"] = {"status": "failed", "error": "candidate exceeds 16MiB", "limits": dict(LIMITS)}
            raise ValueError("candidate exceeds the predeclared size limit")
        write_json(output_dir / "validation.json", report)
        phase = "protection"
        report[phase] = protection_gate(paths["coverage"], paths["candidate"], before["candidate"])
        evidence = report[phase]["evidence"]
        for label, filename in {**evidence["artifact_paths"], "manifest": evidence["manifest_path"]}.items():
            key = "protection_" + label
            paths[key] = Path(filename)
            expected = evidence["manifest_sha256"] if label == "manifest" else evidence["artifact_hashes"][label]
            if sha256(paths[key]) != expected:
                raise ValueError("Protection evidence changed immediately after inspection")
            before[key] = expected
        suite = private_cases(random_count)
        write_json(output_dir / "private-cases.json", suite)
        cases = suite["edge_correlated_pairs"] + suite["random_pairs"]
        metadata = {"random_unique_cases": len(suite["random_pairs"]),
                    "edge_correlated_cases": len(suite["edge_correlated_pairs"])}
        report["private_cases_sha256"] = sha256(output_dir / "private-cases.json")
        phase = "functional"
        report[phase].update(total=len(cases), **metadata)
        checked, reference = functional_gate(paths, cases, timeout_seconds, runner or _run_binary,
                                             output_dir / "executions.jsonl")
        report[phase] = {**checked, **metadata}
        if checked["status"] == "passed":
            phase = "performance"
            report[phase] = performance_gate(paths, cases, reference, timeout_seconds, runner or _run_binary,
                                             output_dir / "executions.jsonl")
        report["status"] = "passed" if all(report[name]["status"] == "passed"
                                            for name in ("protection", "functional", "performance")) else "failed"
    except (Exception, KeyboardInterrupt) as exc:
        status = exc.status if isinstance(exc, ExecutionFailure) else ("interrupted" if isinstance(exc, KeyboardInterrupt) else "error")
        report.update(status=status, error=f"{phase}: {type(exc).__name__}: {exc}")
        if phase in ("protection", "functional", "performance"):
            report[phase].update(status=status, error=str(exc))
            if phase == "functional":
                report[phase]["matched"] = None
    finally:
        try:
            after = {name: sha256(paths[name]) for name in before}
            changed = [name for name in before if before[name] != after[name]]
            report["integrity"] = {"status": "passed" if before and not changed else "error",
                                   "before": before, "after": after, "changed": changed}
            if changed:
                report.update(status="error", error="Input artifact changed during validation")
        except Exception as exc:
            report["integrity"] = {"status": "error", "error": str(exc)}
            report.update(status="error", error="Cannot establish final input integrity")
        report["finished_utc"] = now()
        write_json(output_dir / "validation.json", report)
        (output_dir / "validation.md").write_text(_markdown(report), encoding="utf-8")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "previous", "candidate", "coverage", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--random-cases", type=int, default=MIN_RANDOM_CASES)
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument("--previous-manifest", type=Path,
                        help="Trusted current-publication manifest binding previous SHA-256 and bytes; default pins the original layered artifact")
    args = parser.parse_args(argv)
    try:
        result = validate(args.baseline, args.previous, args.candidate, args.coverage, args.output_dir,
                          random_count=args.random_cases, timeout_seconds=args.timeout_seconds,
                          previous_manifest=args.previous_manifest)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps({"status": result["status"], "report": str(args.output_dir / "validation.json"),
                      "candidate_sha256": result["candidate_sha256"]}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
