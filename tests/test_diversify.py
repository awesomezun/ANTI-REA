"""Private build-format transformation tests; no attacks or model execution."""

import unittest

from antirea import diversify as d


TABLE = {0x02: "OP_PUSH_IMM32", 0x04: "OP_PUSH_REG", 0x05: "OP_POP_REG",
         0x10: "OP_ADD", 0x40: "OP_JMP", 0x44: "OP_RET", 0x60: "OP_ZEXT",
         0x70: "OP_LOAD_ARG", 0xff: "OP_NOP"}
KEY = 0x0123456789abcdef


def stock(data, key=KEY):
    return bytes(value ^ ((key >> (8 * (i & 7))) & 255) for i, value in enumerate(data))


def decode_generated_fetch(data, key, params):
    """Test inverse of the byte codec only, not a VM/target reimplementation."""
    result = bytearray()
    for position, byte in enumerate(data[4:], 4):
        mixed = (position * params["multiply"] + params["add"]) & 0xffffffff
        mixed ^= mixed >> 13
        mixed = (mixed * params["mix"]) & 0xffffffff
        mixed ^= mixed >> 17
        mask = (mixed ^ (key >> (8 * (position & 7)))) & 255
        r = ((position + params["rotate"]) % 7) + 1
        value = byte ^ ((mixed >> 8) & 255)
        value = ((value >> r) | (value << (8 - r))) & 255
        result.append((value - mask) & 255)
    return bytes(result)


def ir_fixture(data, key=KEY):
    return (f'@kagura_vm_bc_1 = private constant [{len(data)} x i8] c"{d.llvm_string(data)}"\n'
            f'@kagura_vm_key_1 = private constant i64 {key}\n'
            'define i64 @antirea_score(i32 %a, i32 %b) {\n'
            f'  %r = call i64 @kagura_vm_execute(ptr @kagura_vm_bc_1, i32 {len(data)}, ptr null, i32 0, ptr null, i32 0, i64 %key)\n'
            '  ret i64 %r\n}\n'
            'declare i64 @kagura_vm_execute(ptr, i32, ptr, i32, ptr, i32, i64)\n')


def read_instruction_operands(decoded, offset, widths, key, params):
    """Read one codec record in isolation, including a direct branch entry."""
    token = int.from_bytes(decoded[offset - 4:offset - 2], "big")
    state = ((offset * params["operand_multiply"]) ^ token ^ key ^ (key >> 32)
             ^ params["operand_add"]) & 0xffffffff
    cursor = offset - 2
    values = []
    for width in widths:
        value = 0
        for _ in range(width):
            byte = decoded[cursor] ^ ((state ^ (state >> 11) ^ (state >> 23)) & 255)
            value = (value << 8) | byte
            state = (((((state << 5) | (state >> 27)) & 0xffffffff)
                      * params["operand_multiply"]) + byte + params["operand_add"]) & 0xffffffff
            cursor += 1
        values.append(value)
    return tuple(values)


class DiversificationTests(unittest.TestCase):
    RR = bytes([0x04, 0, 0x04, 1, 0x10, 64, 0x05, 2, 0x04, 2, 0x44])

    def test_llvm_escape_roundtrip_all_bytes_and_rejects_bad_escape(self):
        data = bytes(range(256))
        self.assertEqual(d.llvm_bytes(d.llvm_string(data)), data)
        self.assertEqual(d.llvm_bytes('a\\00\\22'), b'a\0"')
        self.assertEqual(d.llvm_bytes(r'\\\1A'), b'\\\x1a')
        for text in ('\\', '\\A', '\\XX', '한'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                d.llvm_bytes(text)

    def test_decode_rejects_unknown_truncated_width_and_bad_branch_boundary(self):
        for plain in (b'\xfe', b'\x02\x01', b'\x10\x00', b'\x10\x41',
                      b'\x40\x01\x00\x00\x00\x44'):
            with self.subTest(plain=plain), self.assertRaises(ValueError):
                d.decode_stock(stock(plain), KEY, TABLE)

    def test_real_arithmetic_fusion_removes_three_dispatches(self):
        before = d.decode_stock(stock(self.RR), KEY, TABLE)
        after = d.fuse(before)
        self.assertEqual([item.name for item in after], ["F_RR_ADD", "OP_PUSH_REG", "OP_RET"])
        self.assertEqual(after[0].values, (2, 0, 64, 1))
        self.assertEqual(after[0].originals, 4)
        handler = d.fused_handler("F_RR_ADD")
        self.assertIn("f.regs[d]=vm_zext(a + b,w)", handler)
        self.assertNotIn("vm_push", handler)
        self.assertNotIn("vm_pop", handler)

    def test_immediate_fusion_preserves_unsigned_immediate_and_operand_order(self):
        plain = bytes([4, 9, 2]) + (0xffffffff).to_bytes(4, "little") + bytes([0x10, 32, 5, 7, 4, 7, 0x44])
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertEqual(fused[0].name, "F_RI_ADD")
        self.assertEqual(fused[0].values, (7, 9, 32, 0xffffffff))
        self.assertEqual(fused[0].widths, (1, 1, 1, 8))

    def test_argument_zext_and_move_fusions_are_direct(self):
        plain = bytes([0x70, 1, 0x60, 5, 9, 4, 9, 5, 10, 4, 10, 0x44])
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertEqual([x.name for x in fused[:2]], ["F_ARG", "F_MOV"])
        self.assertEqual(fused[0].values, (9, 1))
        self.assertEqual(fused[0].originals, 3)

    def test_never_fuses_across_a_branch_target(self):
        # Jump enters ADD inside an otherwise fusible four-instruction group.
        plain = b'\x40' + (9).to_bytes(4, "little") + self.RR
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        self.assertFalse(any(x.name == "F_RR_ADD" for x in fused))
        self.assertIn(9, [x.offset for x in fused])

    def test_chain_preserves_aliasing_write_order_and_branch_entry(self):
        # First writes reg 2; second reads/writes reg 2 and uses it again as RHS.
        plain = self.RR[:8] + bytes([4, 2, 4, 2, 0x10, 32, 5, 2, 4, 2, 0x44])
        items = d.decode_stock(stock(plain), KEY, TABLE)
        paired = d.fuse(items)
        self.assertEqual(paired[0].name, 'F_CHAIN_RR_ADD__RR_ADD')
        self.assertEqual(paired[0].originals, 8)
        self.assertEqual(paired[0].values, (2, 0, 64, 1, 2, 2, 32, 2))
        handler = d.fused_handler(paired[0].name)
        self.assertEqual(handler.count('f.regs[d]='), 2)
        self.assertEqual(handler.count('{ uint8_t d='), 2)
        self.assertNotIn('bc_opcode', handler)
        # The second group remains independently reachable when a branch enters it.
        jumped = b'\x40' + (13).to_bytes(4, 'little') + plain
        separate = d.fuse(d.decode_stock(stock(jumped), KEY, TABLE))
        self.assertFalse(any(x.name.startswith('F_CHAIN_') for x in separate))
        self.assertIn(13, [x.offset for x in separate])

    def test_chain_codec_and_metadata_bind_both_operand_sequences(self):
        plain = self.RR[:8] * 2 + bytes([4, 2, 0x44])
        items = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        params = d.parameters(17, {x.name for x in items})
        encoded, mapping = d.emit(items, KEY, params)
        decoded = decode_generated_fetch(encoded, KEY, params)
        self.assertEqual(read_instruction_operands(decoded, mapping[0], items[0].widths, KEY, params),
                         items[0].values)
        _, manifest = d.transform_ir(ir_fixture(stock(plain)), TABLE, 17)
        self.assertEqual(manifest['chained_register_fusion']['groups'], 1)
        self.assertEqual(manifest['blobs'][0]['absorbed_dispatches'], 7)

    def test_branch_to_first_fused_instruction_is_relocated_exactly(self):
        plain = b'\x40' + (5).to_bytes(4, "little") + self.RR
        fused = d.fuse(d.decode_stock(stock(plain), KEY, TABLE))
        params = d.parameters(1729, {x.name for x in fused})
        encoded, mapping = d.emit(fused, KEY, params)
        decoded = decode_generated_fetch(encoded, KEY, params)
        self.assertEqual(mapping[0], 4)
        self.assertEqual(mapping[5], 10)
        self.assertEqual(read_instruction_operands(decoded, 4, (4,), KEY, params), (mapping[5],))
        self.assertEqual(int.from_bytes(decoded[6:8], "big"), params["tokens"]["F_RR_ADD"])
        self.assertEqual(read_instruction_operands(decoded, mapping[5], (1, 1, 1, 1), KEY, params),
                         fused[1].values)

    def test_operand_context_resets_for_back_edges_and_all_operand_widths(self):
        # Codec records only: no target algorithm or VM execution.
        items = [d.Instruction(0, "F_CONST", (17, 0xffffffffffffffff), (1, 8)),
                 d.Instruction(10, "OP_PUSH_IMM16", (0xabcd,), (2,)),
                 d.Instruction(13, "OP_JMP", (0,), (4,))]
        for seed in (1, 7, 1729, 0x7fffffff):
            params = d.parameters(seed, {item.name for item in items})
            encoded, mapping = d.emit(items, KEY, params)
            decoded = decode_generated_fetch(encoded, KEY, params)
            for item in reversed(items):
                expected = (mapping[0],) if item.name == "OP_JMP" else item.values
                self.assertEqual(read_instruction_operands(decoded, mapping[item.offset], item.widths,
                                                           KEY, params), expected)
            # Same instruction can be re-entered after another record without stale state.
            self.assertEqual(read_instruction_operands(decoded, mapping[0], items[0].widths,
                                                       KEY, params), items[0].values)

    def test_position_codec_roundtrips_and_header_is_only_format_guard(self):
        params = d.parameters(123, {"OP_RET"})
        plain = bytes(range(256)) * 3
        encoded = bytes([(KEY & 255) ^ 0xfe] + params["header"]) + d.encode_fetch(plain, KEY, params)
        self.assertEqual(decode_generated_fetch(encoded, KEY, params), plain)
        self.assertEqual(encoded[0] ^ (KEY & 255), 0xfe)
        self.assertNotEqual(encoded[4:260], encoded[260:516])

    def test_seed_changes_contract_but_same_seed_is_reproducible(self):
        ir = ir_fixture(stock(self.RR))
        one, first = d.transform_ir(ir, TABLE, 7)
        repeated, second = d.transform_ir(ir, TABLE, 7)
        other, third = d.transform_ir(ir, TABLE, 8)
        self.assertEqual(one, repeated)
        self.assertEqual(first, second)
        self.assertNotEqual(one, other)
        self.assertNotEqual(first["parameters"]["tokens"], third["parameters"]["tokens"])
        self.assertNotIn("@kagura_vm_execute", one)
        self.assertIn("@" + first["dispatcher_symbol"], one)
        self.assertEqual(first["blobs"][0]["absorbed_dispatches"], 3)
        self.assertEqual(first["external_attack_evaluation"], "not_evaluated")

    def test_no_fusion_empty_blob_and_unsupported_key_fail_closed(self):
        for ir in (ir_fixture(stock(bytes([0x70, 0, 0x44]))), "",
                   ir_fixture(stock(self.RR)).replace("private constant i64", "private global i64")):
            with self.subTest(ir=ir[:60]), self.assertRaises(ValueError):
                d.transform_ir(ir, TABLE, 1)

    def test_duplicate_or_reserved_stock_opcode_table_is_rejected(self):
        for source in ("", "KAGURA_VM_OP(OP_ONE, 0xfe)",
                       "KAGURA_VM_OP(OP_ONE, 0x01)\nKAGURA_VM_OP(OP_TWO, 0x01)"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                d.opcode_table(source)

    def test_multiple_blobs_rewrite_all_sizes_and_calls_without_offset_drift(self):
        first = ir_fixture(stock(self.RR))
        second = ir_fixture(stock(self.RR, 3), key=3).replace("_bc_1", "_bc_22").replace("_key_1", "_key_22")
        second = second.replace("@antirea_score", "@antirea_other")
        second = second[:second.index("declare i64")]
        transformed, manifest = d.transform_ir(first + second, TABLE, 71)
        self.assertEqual([x["global"] for x in manifest["blobs"]], ["kagura_vm_bc_1", "kagura_vm_bc_22"])
        self.assertEqual(transformed.count("call i64 @" + manifest["dispatcher_symbol"]), 2)
        for record in manifest["blobs"]:
            self.assertIn(f'@{record["global"]} = private constant [{record["encoded_bytes"]} x i8]', transformed)
            self.assertIn(f'ptr @{record["global"]}, i32 {record["encoded_bytes"]}', transformed)

    def test_missing_or_duplicate_wrapper_call_refuses_to_transform(self):
        original = ir_fixture(stock(self.RR))
        call = next(line for line in original.splitlines() if "call i64" in line)
        for value in (original.replace(call, ""), original.replace(call, call + "\n" + call)):
            with self.subTest(value=value[:50]), self.assertRaises(ValueError):
                d.transform_ir(value, TABLE, 17)

    def test_runtime_specialization_prunes_unused_base_handlers(self):
        source = '''#include "../internal.h"
enum vm_opcode {
#include "kagura/VMOpcodes.def"
};
#define KAGURA_VM_LIMIT(CppName, CName, Value) CName = Value,
enum vm_limit {
#include "kagura/VMOpcodes.def"
};
typedef struct {
    uint32_t pc;
} VMFrame;
static inline uint8_t bc_u8(VMFrame *f) { return 0; }
/* ── Width helpers */
static inline void vm_push(VMFrame *f, uint64_t v) { }
static inline uint64_t vm_pop(VMFrame *f) { return 0; }
static inline uint64_t vm_peek(VMFrame *f) { return 0; }
static inline unsigned vm_width(VMFrame *f) { return 64; }
static inline uint64_t vm_mask(unsigned w) { return 0; }
static inline uint64_t vm_zext(uint64_t v, unsigned w) { return v; }
static inline int64_t vm_sext(uint64_t v, unsigned w) { return v; }
static inline unsigned vm_shamt(uint64_t v, unsigned w) { return 0; }
uint64_t kagura_vm_execute(void) {
    VMFrame f;
    f.pc      = 0;
    uint8_t op = bc_u8(&f);
        switch (op) {
        case OP_PUSH_REG: vm_push(&f, f.regs[bc_u8(&f)]); break;
        case OP_RET: return vm_pop(&f);
        case OP_NOP: break;
        default: abort();
        }
}
'''
        params = d.parameters(7, {"F_RR_ADD", "OP_RET"})
        generated = d.specialize_runtime(source, params, "antirea_test")
        self.assertIn("uint64_t antirea_test(", generated)
        self.assertIn("uint16_t op = bc_opcode(&f)", generated)
        self.assertIn("uint32_t operand_state;", generated)
        self.assertIn("always_inline", generated)
        self.assertIn("case F_RR_ADD:", generated)
        self.assertIn("case OP_RET:", generated)
        self.assertNotIn("case OP_PUSH_REG:", generated)
        self.assertNotIn("case OP_NOP:", generated)
        self.assertNotIn('#include "kagura/VMOpcodes.def"', generated)
        self.assertIn("f.pc      = 4;", generated)
        self.assertIn("static inline unsigned vm_width(", generated)
        for name in d.INTEGRATED_HELPERS:
            self.assertRegex(generated, r"always_inline\)\) inline \w+ vm_" + name + r"\(")
        self.assertEqual(generated.count("static __attribute__((always_inline)) inline "), 9)


if __name__ == "__main__":
    unittest.main()
