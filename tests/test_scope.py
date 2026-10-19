"""Textual scope checks only: no compiler, models, network or target execution."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from antirea.scope import analyze_scope, main


def function(name, body, params="i32 %x, i32 %y", result="i32"):
    return f"define {result} @{name}({params}) {{\n{body}\n}}\n"


CORE = function("core", "  %v = add i32 %x, %y\n  ret i32 %v")
HELPER = function("prepare", "  %v = xor i32 %x, 31337\n  ret i32 %v")
ENTRY = function("entry", "  %v = call i32 @prepare(i32 %x, i32 %y)\n  %r = call i32 @core(i32 %v, i32 %y)\n  ret i32 %r")
PUBLIC = function("ui", "  %r = tail call i32 @entry(i32 %x, i32 %y) #1\n  ret i32 %r")


class ScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="antirea-scope-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def analyze(self, ir, policy=None, mode="expanded"):
        path = self.directory / "module.ll"
        path.write_text(ir, encoding="utf-8")
        return analyze_scope([path], policy or {"core_roots": ["core"]}, mode)

    def test_expansion_discovers_callers_then_their_other_callees(self):
        result = self.analyze(CORE + HELPER + ENTRY + PUBLIC,
                              {"core_roots": ["core"], "public_presentation": {"ui": "Reviewed direct public forwarding wrapper."}})
        self.assertEqual(result["status"], "ready", result["unresolved"])
        self.assertEqual(result["selected_functions"], ["core", "entry", "prepare"])
        self.assertIn("caller_of:core", result["reasons"]["entry"])
        self.assertIn("callee_of:entry", result["reasons"]["prepare"])
        self.assertTrue(result["boundary_functions"]["ui"]["reached"])
        self.assertEqual(result["boundary_functions"]["ui"]["issues"], [])

    def test_core_comparison_records_deliberately_omitted_neighbors(self):
        result = self.analyze(CORE + HELPER + ENTRY, {"core_roots": ["core"], "sensitive_functions": ["prepare"]}, "core")
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertEqual(result["deliberately_unselected_neighbors"], ["entry", "prepare"])
        self.assertEqual(result["unselected_sensitive_functions"], ["prepare"])
        self.assertEqual(result["reasons"]["core"], ["policy:core_root"])

    def test_sensitive_function_overrides_public_label_and_seeds_expansion(self):
        sensitive_ui = function("login_ui", "  %v = icmp eq i32 %x, 1234\n  %r = zext i1 %v to i32\n  ret i32 %r")
        result = self.analyze(CORE + sensitive_ui, {"core_roots": ["core"], "sensitive_functions": ["login_ui"],
                                                  "public_presentation": {"login_ui": "UI display name does not exempt authorization logic."}})
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["selected_functions"], ["core", "login_ui"])
        self.assertTrue(result["boundary_functions"]["login_ui"]["overridden_by_sensitive_or_core"])

    def test_shared_globals_expand_transitively_but_require_data_review(self):
        ir = "@table = constant i32 99\n@pointer = global ptr @table\n"
        ir += function("core", "  %v = load i32, ptr @table\n  ret i32 %v")
        ir += function("consumer", "  %p = load ptr, ptr @pointer\n  ret i32 %x")
        ir += function("caller", "  %v = call i32 @consumer(i32 %x, i32 %y)\n  ret i32 %v")
        result = self.analyze(ir)
        self.assertEqual(result["selected_functions"], ["caller", "consumer", "core"])
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(result["data_risks"])
        self.assertEqual(result["graph"]["shared_globals"]["table"], ["consumer", "core"])
        public_result = self.analyze(ir, {"core_roots": ["core"], "public_globals": {"table": "Documented public table", "pointer": "Public table address"}})
        self.assertEqual(public_result["status"], "ready")

    def test_sensitive_data_overrides_public_global_annotation(self):
        result = self.analyze("@secret = constant i32 7\n" + function("core", "  %v = load i32, ptr @secret\n  ret i32 %v"),
                              {"core_roots": ["core"], "sensitive_globals": ["secret"], "public_globals": {"secret": "Incorrect public claim"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["data_risks"][0]["global"], "secret")

    def test_public_boundary_touching_sensitive_global_is_not_exempt(self):
        ui = function("ui", "  %a = load i32, ptr @secret\n  %r = call i32 @core(i32 %a, i32 %y)\n  ret i32 %r")
        result = self.analyze("@secret = constant i32 9\n" + CORE + ui,
                              {"core_roots": ["core"], "public_presentation": {"ui": "Reviewed UI label"}, "sensitive_globals": ["secret"]})
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(any("sensitive global:secret" in item for item in result["boundary_functions"]["ui"]["issues"]))

    def test_boundary_cannot_hide_preprocessing_helper(self):
        ui = function("ui", "  %p = call i32 @prepare(i32 %x, i32 %y)\n  %r = call i32 @core(i32 %p, i32 %y)\n  ret i32 %r")
        result = self.analyze(CORE + HELPER + ui, {"core_roots": ["core"], "public_presentation": {"ui": "Not automatically safe"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("calls unprotected helper:prepare", result["boundary_functions"]["ui"]["issues"])

    def test_forwarder_cannot_inject_literal_or_reorder_arguments(self):
        for arguments in ("i32 %x, i32 31337", "i32 %y, i32 %x"):
            result = self.analyze(CORE + function("ui", f"  %r = call i32 @core({arguments})\n  ret i32 %r"),
                                  {"core_roots": ["core"], "public_presentation": {"ui": "Claimed forwarding wrapper"}})
            self.assertEqual(result["status"], "needs_review")
            self.assertTrue(any("unchanged ordered" in item for item in result["boundary_functions"]["ui"]["issues"]))

    def test_forwarder_cannot_hide_literal_in_call_operand_bundle(self):
        ui = function("ui", '  %r = call i32 @core(i32 %x, i32 %y) [ "deopt"(i32 31337) ]\n  ret i32 %r')
        result = self.analyze(CORE + ui, {"core_roots": ["core"],
                                         "public_presentation": {"ui": "Claimed unchanged forwarding wrapper"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue(any("operand bundle" in issue for issue in result["boundary_functions"]["ui"]["issues"]))
        self.assertEqual(result["selected_functions"], ["core"])

    def test_forwarder_string_attribute_is_not_an_operand_bundle_or_assembly(self):
        ui = function("ui", '  %r = call i32 @core(i32 %x, i32 %y) "note"="[ asm @fake() ]"\n  ret i32 %r')
        result = self.analyze(CORE + ui, {"core_roots": ["core"],
                                         "public_presentation": {"ui": "Reviewed direct forwarding wrapper"}})
        self.assertEqual(result["status"], "ready", result["unresolved"])
        self.assertEqual(result["boundary_functions"]["ui"]["issues"], [])

    def test_public_literal_leaf_is_explicit_review_not_semantic_ui_classifier(self):
        core = function("core", "  %tag = call i32 @public_tag()\n  %v = add i32 %x, %tag\n  ret i32 %v")
        result = self.analyze(core + function("public_tag", "  ret i32 7", params=""),
                              {"core_roots": ["core"], "public_presentation": {"public_tag": "Documented public format version 7"}})
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertTrue(any("human policy assertions" in item for item in result["limitations"]))

    def test_missing_policy_symbol_blocks(self):
        for key, value in (("core_roots", ["missing"]), ("sensitive_functions", ["missing"]),
                           ("public_presentation", {"missing": "Reviewed"}), ("entry_points", ["missing"]),
                           ("sensitive_globals", ["missing"]), ("public_globals", {"missing": "Reviewed"})):
            policy = {"core_roots": ["core"], key: value}
            result = self.analyze(CORE, policy)
            self.assertEqual(result["status"], "needs_review", key)

    def test_cap_blocks_without_truncating_selection(self):
        result = self.analyze(CORE + HELPER + ENTRY, {"core_roots": ["core"], "max_functions": 1})
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["selected_functions"], ["core", "entry", "prepare"])
        self.assertTrue(any(item["kind"] == "max_functions_exceeded" for item in result["unresolved"]))

    def test_indirect_calls_and_callbacks_are_explicit_review_items(self):
        ir = "@callback = global ptr @core\n" + function("core", "  %v = call i32 %fp(i32 %x)\n  ret i32 %v", params="ptr %fp, i32 %x")
        result = self.analyze(ir)
        kinds = {item["kind"] for item in result["unresolved"] if item["relevant"]}
        self.assertEqual(result["status"], "needs_review")
        self.assertTrue({"indirect_call", "address_taken_function"}.issubset(kinds))

    def test_public_callback_global_does_not_make_unresolved_helper_irrelevant(self):
        core = function("core", "  %p = load ptr, ptr @dispatch\n  ret ptr %p", result="ptr")
        result = self.analyze("@dispatch = global ptr @prepare\n" + core + HELPER,
                              {"core_roots": ["core"], "public_globals": {"dispatch": "Public callback table, not reviewed helper code"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertEqual(result["data_risks"], [])
        self.assertTrue(any(item["kind"] == "address_taken_function" and item["symbol"] == "prepare" and item["relevant"]
                            for item in result["unresolved"]))

    def test_transitively_consumed_callback_global_requires_review(self):
        core = function("core", "  %p = load ptr, ptr @outer\n  ret ptr %p", result="ptr")
        ir = "@outer = global ptr @dispatch\n@dispatch = global ptr @prepare\n" + core + HELPER
        result = self.analyze(ir, {"core_roots": ["core"],
                                   "public_globals": {"outer": "Public table pointer", "dispatch": "Public callback table"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertEqual(result["graph"]["function_globals"]["core"], ["dispatch", "outer"])
        self.assertTrue(any(item["kind"] == "address_taken_function" and item["relevant"] for item in result["unresolved"]))

    def test_callback_global_consumed_by_reached_public_boundary_is_relevant(self):
        ui = function("ui", "  %p = load ptr, ptr @dispatch\n  %r = call i32 @core(i32 %x, i32 %y)\n  ret i32 %r")
        result = self.analyze("@dispatch = global ptr @prepare\n" + CORE + HELPER + ui,
                              {"core_roots": ["core"], "public_globals": {"dispatch": "Public callback table"},
                               "public_presentation": {"ui": "Claimed public wrapper"}})
        self.assertTrue(result["boundary_functions"]["ui"]["reached"])
        self.assertTrue(any(item["kind"] == "address_taken_function" and item["symbol"] == "prepare" and item["relevant"]
                            for item in result["unresolved"]))
        self.assertNotIn("prepare", result["selected_functions"])

    def test_unconsumed_callback_global_remains_an_explicit_limitation(self):
        result = self.analyze("@dispatch = global ptr @prepare\n" + CORE + HELPER)
        self.assertEqual(result["status"], "ready", result["unresolved"])
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertTrue(any(item["kind"] == "address_taken_function" and not item["relevant"] for item in result["unresolved"]))

    def test_consumed_global_external_callback_requires_review(self):
        declaration = "declare i32 @external_cb(i32, i32)\n@dispatch = global ptr @external_cb\n"
        for transitive in (False, True):
            with self.subTest(transitive=transitive):
                global_name = "outer" if transitive else "dispatch"
                ir = declaration + ("@outer = global ptr @dispatch\n" if transitive else "")
                ir += function("core", f"  %p = load ptr, ptr @{global_name}\n  ret ptr %p", result="ptr")
                public_globals = {"dispatch": "Public table, not external callback semantics"}
                if transitive:
                    public_globals["outer"] = "Public table pointer"
                result = self.analyze(ir, {"core_roots": ["core"], "public_globals": public_globals})
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["selected_functions"], ["core"])
                self.assertEqual(result["data_risks"], [])
                self.assertTrue(any(item["kind"] == "external_function_reference" and item["relevant"]
                                    and "external_cb" in item["detail"] for item in result["unresolved"]))

    def test_unconsumed_global_external_callback_is_an_explicit_limitation(self):
        result = self.analyze("declare i32 @external_cb(i32, i32)\n@dispatch = global ptr @external_cb\n" + CORE)
        self.assertEqual(result["status"], "ready", result["unresolved"])
        self.assertTrue(any(item["kind"] == "external_function_reference" and not item["relevant"]
                            and "external_cb" in item["detail"] for item in result["unresolved"]))

    def test_inline_assembly_cannot_spoof_a_public_forwarding_edge(self):
        core = function("core", "  %r = xor i64 %x, 999\n  ret i64 %r", params="i64 %x", result="i64")
        ui = function("ui", '  %r = call i64 asm "movq $$777, $0 # @core(i64 %x)", "=r,r"(i64 %x)\n  ret i64 %r',
                      params="i64 %x", result="i64")
        result = self.analyze(core + ui, {"core_roots": ["core"],
                                         "public_presentation": {"ui": "Claimed unchanged forwarding wrapper"}})
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["graph"]["calls"]["ui"], [])
        self.assertFalse(result["boundary_functions"]["ui"]["reached"])
        self.assertTrue(any(item["kind"] == "inline_assembly" and item["symbol"] == "ui" and item["relevant"]
                            for item in result["unresolved"]))

    def test_inline_assembly_blocks_selected_and_disconnected_functions(self):
        assembly = '  %r = call i64 asm "movq $$777, $0", "=r"()\n  ret i64 %r'
        for name in ("core", "other"):
            with self.subTest(name=name):
                ir = (CORE if name != "core" else "") + function(name, assembly, result="i64")
                result = self.analyze(ir)
                self.assertEqual(result["status"], "needs_review")
                self.assertEqual(result["graph"]["calls"][name], [])
                self.assertTrue(any(item["kind"] == "inline_assembly" and item["relevant"] for item in result["unresolved"]))

    def test_function_names_containing_asm_are_not_inline_assembly(self):
        for spelling, name in (("asm", "asm"), ('"asm"', "asm"), ('"asm call"', "asm call")):
            with self.subTest(spelling=spelling):
                core = function("core", f"  %r = call i32 @{spelling}(i32 %x, i32 %y)\n  ret i32 %r")
                result = self.analyze(core + function(spelling, "  ret i32 %x"))
                self.assertEqual(result["status"], "ready", result["unresolved"])
                self.assertEqual(result["graph"]["calls"]["core"], [name])

    def test_alias_call_cannot_be_silently_treated_as_owned_definition(self):
        ir = "@alias = alias i32 (i32, i32), ptr @core\n" + CORE + function("caller", "  %v = call i32 @alias(i32 %x, i32 %y)\n  ret i32 %v")
        result = self.analyze(ir)
        self.assertEqual(result["status"], "needs_review")
        self.assertNotIn("alias", result["selected_functions"])
        self.assertTrue(any(item["kind"] == "alias_definition" for item in result["unresolved"]))

    def test_selected_external_call_blocks_but_unrelated_external_call_is_reported(self):
        external = "declare i32 @library(i32, i32)\n"
        unrelated = function("other", "  %v = call i32 @library(i32 %x, i32 %y)\n  ret i32 %v")
        result = self.analyze(external + CORE + unrelated)
        self.assertEqual(result["status"], "ready")
        self.assertTrue(any(item["kind"] == "external_call" and not item["relevant"] for item in result["unresolved"]))
        result = self.analyze(external + function("core", "  %v = call i32 @library(i32 %x, i32 %y)\n  ret i32 %v"))
        self.assertEqual(result["status"], "needs_review")

    def test_multiple_modules_and_input_hashes(self):
        first, second = self.directory / "first.ll", self.directory / "second.ll"
        first.write_text(CORE, encoding="utf-8")
        second.write_text(HELPER + ENTRY, encoding="utf-8")
        result = analyze_scope([first, second], {"core_roots": ["core"]})
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["selected_functions"], ["core", "entry", "prepare"])
        self.assertEqual(len(result["input_hashes"]), 2)
        self.assertTrue(all(len(value) == 64 for value in result["input_hashes"].values()))
        first_hash = result["input_hashes"][str(first.resolve())]
        first.write_text(CORE + "\n", encoding="utf-8")
        self.assertNotEqual(first_hash, analyze_scope([first, second], {"core_roots": ["core"]})["input_hashes"][str(first.resolve())])

    def test_duplicate_definition_and_invalid_input_fail_closed(self):
        result = self.analyze(CORE + CORE)
        self.assertEqual(result["status"], "needs_review")
        result = analyze_scope([self.directory / "absent.ll"], {"core_roots": ["core"]})
        self.assertEqual(result["status"], "needs_review")
        result = self.analyze("define i32 @core() { ret i32 0 }\n")
        self.assertEqual(result["status"], "needs_review")

    def test_comments_and_string_literals_do_not_invent_edges(self):
        ir = '@public_text = constant [17 x i8] c"hello @not_a_ref\00"\n' + CORE.replace("  ret", "  ; call i32 @fake()\n  ret")
        result = self.analyze(ir)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["graph"]["calls"]["core"], [])
        self.assertNotIn("not_a_ref", result["globals"])

    def test_cli_writes_manifest_and_fails_nonzero_for_review(self):
        ir, policy, output = self.directory / "input.ll", self.directory / "policy.json", self.directory / "output.json"
        ir.write_text(CORE, encoding="utf-8")
        policy.write_text(json.dumps({"core_roots": ["core"]}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--ir", str(ir), "--policy", str(policy), "--output", str(output)]), 0)
            policy.write_text(json.dumps({"core_roots": ["missing"]}), encoding="utf-8")
            self.assertEqual(main(["--ir", str(ir), "--policy", str(policy), "--output", str(output)]), 2)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "needs_review")

    def test_public_reason_and_unknown_policy_fields_are_not_silently_ignored(self):
        for policy in ({"core_roots": ["core"], "public_presentation": {"ui": ""}},
                       {"core_roots": ["core"], "sensitive_function": ["ui"]}):
            self.assertEqual(self.analyze(CORE + PUBLIC, policy)["status"], "needs_review")

    def test_entry_points_only_validate_presence_without_promising_coverage(self):
        disconnected = function("outside_entry", "  ret i32 %x")
        result = self.analyze(CORE + disconnected, {"core_roots": ["core"], "entry_points": ["outside_entry"]})
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["selected_functions"], ["core"])
        self.assertIn("presence", result["entry_point_semantics"])
        self.assertTrue(any("does not seed selection" in item for item in result["limitations"]))


if __name__ == "__main__":
    unittest.main()
