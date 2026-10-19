from pathlib import Path
import hashlib
import json
import math
import tempfile
import unittest
from unittest.mock import patch

from antirea import defense_validate as dv


class DefenseValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = {name: self.root / f"{name}.exe" for name in dv.ARMS}
        for name, path in self.paths.items():
            path.write_bytes(name.encode())
        self.coverage = self.make_coverage()
        self.addCleanup(patch.stopall)
        patch.object(dv, "EXPECTED_BASELINE_SHA256", dv.sha256(self.paths["baseline"])).start()
        patch.object(dv, "EXPECTED_PREVIOUS_SHA256", dv.sha256(self.paths["previous"])).start()

    def make_coverage(self):
        dispatcher = "antirea_dispatch_abcd"
        ir = self.root / "core.diversified.ll"
        ir.write_text('@bytecode = private constant [3 x i8] c"\\01\\02\\03"\n'
                      'define i64 @antirea_score(i32 %x, i32 %y) {\n'
                      f'  %v = call i64 @{dispatcher}(ptr @bytecode)\n'
                      '  ret i64 %v\n}\n', encoding="utf-8")
        generated = self.root / "generated.c"
        generated.write_text("/* trusted generated runtime fixture */", encoding="utf-8")
        runtime = self.root / "runtime.after.ll"
        runtime.write_text(f'define i64 @{dispatcher}(ptr %x) {{\n'
                           'kagura.loop:\n  switch i32 1, label %end [ ]\n'
                           '  %sub.x = add i32 1, 2\n  %co.x = xor i32 3, 4\n'
                           '  ret i64 0\n}\n', encoding="utf-8")
        manifest = {"format_version": 1, "opcode_bits": 16, "operand_byte_order": "big",
                    "stock_format_directly_compatible": False, "dispatcher_symbol": dispatcher,
                    "output_ir_sha256": dv.sha256(ir), "generated_runtime_sha256": dv.sha256(generated),
                    "blobs": [{"global": "bytecode", "original_bytes": 4, "encoded_bytes": 3,
                               "original_instructions": 2, "emitted_instructions": 1,
                               "fused_groups": 1, "absorbed_dispatches": 1,
                               "stock_first_opcode_after_original_xor": 254,
                               "encoded_sha256": hashlib.sha256(b"\x01\x02\x03").hexdigest()}]}
        manifest_path = self.root / "diversification.json"
        dv.write_json(manifest_path, manifest)
        coverage = {"protection": "diversified-layered", "target_function": "antirea_score",
                    "target_virtualized": True, "nonempty_bytecode": True,
                    "vm_call_count": 1, "bytecode_blob_count": 1,
                    "executable": str(self.paths["candidate"]),
                    "executable_sha256": dv.sha256(self.paths["candidate"]),
                    "diversification_manifest": str(manifest_path),
                    "diversification_sha256": dv.sha256(manifest_path), "diversification": manifest,
                    "after_ir": str(ir), "generated_runtime": str(generated),
                    "runtime_after_ir_sha256": dv.sha256(runtime),
                    "runtime_evidence": {"function": dispatcher, "ir": str(runtime),
                        "fla_dispatcher": True, "substitution_instructions": 1,
                        "constant_obfuscation_instructions": 1,
                        "requested_passes": ["fla", "sub", "co"], "nested_vm": False}}
        path = self.root / "coverage.json"
        dv.write_json(path, coverage)
        return path

    def runner(self, path, cases, timeout):
        elapsed = {"baseline": .01, "previous": .1, "candidate": .2}[path.stem]
        return {"status": "passed", "outputs": [x + y for x, y in cases], "elapsed_seconds": elapsed}

    def validate(self, runner=None, **kwargs):
        return dv.validate(self.paths["baseline"], self.paths["previous"], self.paths["candidate"],
                           self.coverage, self.root / "validation", runner=runner or self.runner, **kwargs)

    def test_private_cases_have_8192_unique_fresh_pairs_and_separate_edges(self):
        cases = dv.private_cases()
        random_pairs, edges = cases["random_pairs"], cases["edge_correlated_pairs"]
        self.assertEqual(len(random_pairs), 8192)
        self.assertEqual(len(set(random_pairs)), 8192)
        self.assertFalse(set(random_pairs) & set(edges))
        self.assertEqual(len(edges), 297)
        self.assertIn((0, dv.U32_MAX), edges)
        self.assertNotEqual(random_pairs, dv.private_cases()["random_pairs"])
        for count in (8191, 100_000, True):
            with self.assertRaises(ValueError):
                dv.private_cases(count)

    def test_complete_gate_passes_and_records_private_cases_and_raw_timings(self):
        result = self.validate()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["functional"]["total"], 8489)
        self.assertEqual(result["functional"]["matched"], 8489)
        self.assertEqual(result["functional"]["repeats"], 2)
        self.assertEqual(result["functional"]["random_unique_cases"], 8192)
        self.assertEqual(result["performance"]["ratios"]["candidate_vs_previous"], 2)
        self.assertEqual(result["performance"]["ratios"]["candidate_vs_baseline"], 20)
        for arm in dv.ARMS:
            self.assertEqual(len(result["performance"]["conditions"][arm]["samples_seconds"]), 7)
        self.assertEqual(result["integrity"]["status"], "passed")
        output = self.root / "validation"
        self.assertTrue((output / "validation.md").is_file())
        self.assertEqual(len((output / "executions.jsonl").read_text().splitlines()), 30)
        private = json.loads((output / "private-cases.json").read_text())
        self.assertIn("random_seed", private)
        self.assertNotIn("random_seed", json.dumps(result))
        self.assertEqual(result["external_evaluation"], "not_performed")
        self.assertIs(result["published"], False)

    def test_wrong_baseline_refuses_execution_and_writes_error_report(self):
        self.paths["baseline"].write_bytes(b"wrong")
        with patch.object(dv, "_run_binary") as run:
            result = self.validate(runner=run)
            run.assert_not_called()
        self.assertEqual(result["status"], "error")
        self.assertIn("fixed original ledger", result["error"])
        self.assertTrue((self.root / "validation/validation.json").is_file())

    def test_chain_claim_requires_matching_counts_and_two_direct_writes(self):
        from antirea import diversify as d
        coverage = json.loads(self.coverage.read_text(encoding='utf-8'))
        manifest = coverage['diversification']
        name = 'F_CHAIN_RR_ADD__RI_XOR'
        generated = Path(coverage['generated_runtime'])
        manifest['chained_register_fusion'] = {
            'groups': 1, 'operations_per_group': 2,
            'semantics': 'sequential direct expressions with both intermediate register writes retained'}
        manifest['blobs'][0]['fusion_counts'] = {name: 1}
        generated.write_text(d.fused_handler(name), encoding='utf-8')
        def check():
            manifest['generated_runtime_sha256'] = dv.sha256(generated)
            path = Path(coverage['diversification_manifest'])
            dv.write_json(path, manifest)
            coverage['diversification_sha256'] = dv.sha256(path)
            dv.write_json(self.coverage, coverage)
            return dv.protection_gate(self.coverage, self.paths['candidate'], dv.sha256(self.paths['candidate']))
        self.assertEqual(check()['evidence']['chained_register_fusion']['groups'], 1)
        manifest['chained_register_fusion']['groups'] = 2
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            check()
        manifest['chained_register_fusion']['groups'] = 1
        generated.write_text(d.fused_handler('F_RR_ADD').replace('F_RR_ADD:', name + ':'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'direct-expression'):
            check()
        manifest['chained_register_fusion']['operations_per_group'] = True
        with self.assertRaisesRegex(ValueError, 'invalid chained'):
            check()

    def test_wrong_previous_refuses_execution(self):
        self.paths["previous"].write_bytes(b"wrong")
        result = self.validate()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["functional"]["status"], "not_run")

    def test_trusted_previous_manifest_allows_next_generation_and_is_hash_bound(self):
        self.paths["previous"].write_bytes(b"next-generation")
        manifest = self.root / "published-manifest.json"
        dv.write_json(manifest, {"sha256": dv.sha256(self.paths["previous"]),
                                 "bytes": self.paths["previous"].stat().st_size})
        result = self.validate(previous_manifest=manifest)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["previous_identity"]["source"], "trusted_local_manifest")
        self.assertEqual(result["integrity"]["before"]["previous_manifest"], dv.sha256(manifest))
        self.assertEqual(result["baseline_sha256"], dv.EXPECTED_BASELINE_SHA256)

    def test_previous_manifest_wrong_hash_and_size_rejected(self):
        manifest = self.root / "published-manifest.json"
        for digest, size in (("0" * 64, 8), (dv.sha256(self.paths["previous"]), 999)):
            with self.subTest(digest=digest, size=size):
                dv.write_json(manifest, {"sha256": digest, "bytes": size})
                with patch.object(dv, "_run_binary") as runner:
                    result = dv.validate(*[self.paths[a] for a in dv.ARMS], self.coverage,
                                         self.root / f"validation-{size}", previous_manifest=manifest, runner=runner)
                    runner.assert_not_called()
                self.assertEqual(result["status"], "error")
                self.assertIn("manifest hash/size", result["error"])

    def test_incoming_previous_manifest_and_reparse_are_rejected(self):
        incoming = self.root / "rea-analysis-reports"
        incoming.mkdir()
        manifest = incoming / "manifest.json"
        dv.write_json(manifest, {"sha256": dv.sha256(self.paths["previous"]), "bytes": 8})
        with self.assertRaisesRegex(ValueError, "incoming"):
            dv._trusted_previous_manifest(manifest)
        from types import SimpleNamespace
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0, st_file_attributes=0x400)):
            with self.assertRaisesRegex(ValueError, "reparse"):
                dv._trusted_previous_manifest(self.root / "manifest.json")

    def test_changed_previous_manifest_invalidates_result(self):
        manifest = self.root / "published-manifest.json"
        dv.write_json(manifest, {"sha256": dv.sha256(self.paths["previous"]), "bytes": 8})
        def changing(path, cases, timeout):
            manifest.write_text('{}')
            return self.runner(path, cases, timeout)
        result = self.validate(previous_manifest=manifest, runner=changing)
        self.assertEqual(result["status"], "error")
        self.assertIn("previous_manifest", result["integrity"]["changed"])

    def test_v2_requires_operand_context_and_removal_of_fetch_helpers(self):
        coverage = json.loads(self.coverage.read_text(encoding="utf-8"))
        manifest = coverage["diversification"]
        manifest.update(format_version=2, fetch_inlined_in_dispatcher=True,
                        operand_encoding="instruction-position/opcode/key context with plaintext feedback; resets at every instruction")
        generated = Path(coverage["generated_runtime"])
        runtime = Path(coverage["runtime_evidence"]["ir"])
        original_ir = runtime.read_text(encoding="utf-8")

        def bind_artifacts():
            manifest["generated_runtime_sha256"] = dv.sha256(generated)
            manifest_path = Path(coverage["diversification_manifest"])
            dv.write_json(manifest_path, manifest)
            coverage["diversification_sha256"] = dv.sha256(manifest_path)
            coverage["runtime_after_ir_sha256"] = dv.sha256(runtime)
            dv.write_json(self.coverage, coverage)

        bind_artifacts()
        with self.assertRaisesRegex(ValueError, "v2 operand context"):
            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))
        generated.write_text("uint32_t operand_state;\nuint16_t op = bc_opcode(&f);\n"
                             "f->operand_state=rotated*3u;\n", encoding="utf-8")
        bind_artifacts()
        evidence = dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))
        self.assertTrue(evidence["evidence"]["operand_context"]["plaintext_feedback"])
        runtime.write_text(original_ir + "define internal i8 @bc_u8(ptr %f) {\n  ret i8 0\n}\n",
                           encoding="utf-8")
        bind_artifacts()
        with self.assertRaisesRegex(ValueError, "v2 operand context"):
            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_semantic_helper_claim_rejects_separate_definitions_and_calls(self):
        coverage = json.loads(self.coverage.read_text(encoding="utf-8"))
        manifest = coverage["diversification"]
        runtime = Path(coverage["runtime_evidence"]["ir"])
        original_ir = runtime.read_text(encoding="utf-8")
        for helper in ("push", "pop", "peek", "width", "mask", "zext", "sext", "shamt"):
            for mode in ("definition", "call", "clean", "false_claim"):
                with self.subTest(helper=helper, mode=mode):
                    manifest["semantic_helpers_inlined_in_dispatcher"] = mode != "false_claim"
                    text = original_ir
                    if mode == "definition":
                        text += f"define internal i64 @vm_{helper}(ptr %f) {{\n ret i64 0\n}}\n"
                    elif mode == "call":
                        text = text.replace("  ret i64 0", f"  %v = call i64 @vm_{helper}(ptr %x)\n  ret i64 0")
                    runtime.write_text(text, encoding="utf-8")
                    manifest_path = Path(coverage["diversification_manifest"])
                    dv.write_json(manifest_path, manifest)
                    coverage["diversification_sha256"] = dv.sha256(manifest_path)
                    coverage["runtime_after_ir_sha256"] = dv.sha256(runtime)
                    dv.write_json(self.coverage, coverage)
                    if mode == "clean":
                        result = dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))
                        self.assertEqual(result["evidence"]["semantic_helper_integration"]["calls_in_dispatcher"], 0)
                    else:
                        with self.assertRaisesRegex(ValueError, "semantic helper integration"):
                            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_selective_helper_claim_checks_only_named_helpers_and_rejects_invalid_lists(self):
        coverage = json.loads(self.coverage.read_text(encoding="utf-8"))
        manifest = coverage["diversification"]
        runtime = Path(coverage["runtime_evidence"]["ir"])
        original_ir = runtime.read_text(encoding="utf-8")
        cases = ((["pop"], "width", True), (["pop"], "pop", False),
                 ([], "width", False), (["pop", "pop"], "width", False),
                 (["unknown"], "width", False), ([1], "width", False))
        for claim, helper, passes in cases:
            with self.subTest(claim=claim, helper=helper):
                manifest["semantic_helpers_inlined_in_dispatcher"] = claim
                runtime.write_text(original_ir + f"define internal i64 @vm_{helper}(ptr %f) {{\n ret i64 0\n}}\n", encoding="utf-8")
                manifest_path = Path(coverage["diversification_manifest"])
                dv.write_json(manifest_path, manifest)
                coverage["diversification_sha256"] = dv.sha256(manifest_path)
                coverage["runtime_after_ir_sha256"] = dv.sha256(runtime)
                dv.write_json(self.coverage, coverage)
                if passes:
                    evidence = dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))
                    self.assertEqual(evidence["evidence"]["semantic_helper_integration"]["claimed_helpers"], claim)
                else:
                    with self.assertRaisesRegex(ValueError, "semantic helper integration"):
                        dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_status_only_coverage_is_rejected(self):
        dv.write_json(self.coverage, {"status": "passed"})
        result = self.validate()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["protection"]["status"], "error")

    def test_manifest_hash_or_structural_evidence_tampering_rejected(self):
        (self.root / "core.diversified.ll").write_text("modified")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_matching_status_and_hash_but_no_dispatcher_is_rejected(self):
        coverage = json.loads(self.coverage.read_text())
        ir = self.root / "core.diversified.ll"
        ir.write_text(ir.read_text().replace("call i64", "notcall i64"))
        coverage["diversification"]["output_ir_sha256"] = dv.sha256(ir)
        manifest = self.root / "diversification.json"
        dv.write_json(manifest, coverage["diversification"])
        coverage["diversification_sha256"] = dv.sha256(manifest)
        dv.write_json(self.coverage, coverage)
        with self.assertRaisesRegex(ValueError, "wrapper"):
            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_wrong_encoded_blob_hash_rejected_even_with_manifest_rehashed(self):
        coverage = json.loads(self.coverage.read_text())
        coverage["diversification"]["blobs"][0]["encoded_sha256"] = "0" * 64
        manifest = self.root / "diversification.json"
        dv.write_json(manifest, coverage["diversification"])
        coverage["diversification_sha256"] = dv.sha256(manifest)
        dv.write_json(self.coverage, coverage)
        with self.assertRaisesRegex(ValueError, "blob evidence"):
            dv.protection_gate(self.coverage, self.paths["candidate"], dv.sha256(self.paths["candidate"]))

    def test_timeout_is_unknown_not_zero_score_or_pass(self):
        result = self.validate(runner=lambda *args: {"status": "timeout", "error": "bounded timeout"})
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["functional"]["status"], "timeout")
        self.assertIsNone(result["functional"]["matched"])
        self.assertEqual(result["performance"]["status"], "not_run")

    def test_output_mismatch_is_functional_failure(self):
        def wrong(path, cases, timeout):
            result = self.runner(path, cases, timeout)
            if path == self.paths["candidate"]:
                result["outputs"][0] += 1
            return result
        result = self.validate(runner=wrong)
        self.assertEqual(result["functional"]["status"], "failed")
        self.assertEqual(result["functional"]["matched"], result["functional"]["total"] - 1)
        self.assertEqual(result["performance"]["status"], "not_run")

    def test_repeat_detects_nondeterminism(self):
        calls = 0
        def unstable(path, cases, timeout):
            nonlocal calls
            result = self.runner(path, cases, timeout)
            if path == self.paths["candidate"]:
                calls += 1
                if calls == 2:
                    result["outputs"][0] += 1
            return result
        result = self.validate(runner=unstable)
        self.assertEqual(result["functional"]["status"], "failed")
        self.assertEqual(result["functional"]["repeats"], 2)

    def test_performance_limits_are_enforced(self):
        def slow(path, cases, timeout):
            result = self.runner(path, cases, timeout)
            if path == self.paths["candidate"]:
                result["elapsed_seconds"] = 3
            return result
        result = self.validate(runner=slow)
        self.assertEqual(result["functional"]["status"], "passed")
        self.assertEqual(result["performance"]["status"], "failed")
        self.assertEqual(result["status"], "failed")

    def test_malformed_output_and_nonfinite_time_never_pass(self):
        for change in ({"outputs": []}, {"elapsed_seconds": math.nan}, {"outputs": [True]}):
            with self.subTest(change=change):
                def invalid(path, cases, timeout):
                    return {**self.runner(path, cases, timeout), **change}
                with self.assertRaises(dv.ExecutionFailure):
                    dv._execute(self.paths["candidate"], [(0, 0)], 5, invalid,
                                {"arm": "candidate"}, self.root / "invalid.jsonl")

    def test_changed_executable_or_evidence_invalidates_whole_gate(self):
        calls = 0
        def modifying(path, cases, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                (self.root / "generated.c").write_text("mutated during execution")
            return self.runner(path, cases, timeout)
        result = self.validate(runner=modifying)
        self.assertEqual(result["functional"]["status"], "passed")
        self.assertEqual(result["status"], "error")
        self.assertIn("protection_generated_runtime", result["integrity"]["changed"])

    def test_invalid_timeout_is_json_serializable_failure(self):
        result = self.validate(timeout_seconds=math.nan)
        self.assertEqual(result["status"], "error")
        self.assertTrue((self.root / "validation/validation.json").is_file())

    def test_existing_output_and_sync_output_are_refused(self):
        (self.root / "validation").mkdir()
        with self.assertRaises(FileExistsError):
            self.validate()
        with self.assertRaisesRegex(ValueError, "synchronization"):
            dv.validate(*[self.paths[a] for a in dv.ARMS], self.coverage,
                        self.root / "attackerfolder" / "validation")

    def test_cli_rejects_less_than8192_random_without_binary_execution(self):
        with patch.object(dv, "_run_binary") as runner:
            status = dv.main(["--baseline", str(self.paths["baseline"]), "--previous", str(self.paths["previous"]),
                              "--candidate", str(self.paths["candidate"]), "--coverage", str(self.coverage),
                              "--output-dir", str(self.root / "validation"), "--random-cases", "4"])
            runner.assert_not_called()
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
