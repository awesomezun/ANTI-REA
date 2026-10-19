"""Defense-only build-time VM format diversification for pinned Kagura IR.

This translates already-protected private build IR, not an attack artifact. It
does not recover a target algorithm or evaluate reverse-engineering resistance.
The generated ISA, fused handlers and fetch encoding are recoverable from the
delivered executable: this is diversification, not cryptographic secrecy.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import re


PINNED_COMMIT = "ac2136ee0408677cf7cdee55307e9b16edd5f4d5"
RUNTIME_SHA256 = "0b4040ce1354d59173a20f655e18919e40b6217af602db1f8c935cfb4c23fcca"
OPCODES_SHA256 = "64b6555b693ae6797561f83b31e6595615bc16eaa71de44b1031d3c65c573aec"
FORMAT_VERSION = 2
HEADER_SIZE = 4
INTEGRATED_HELPERS = ("push", "pop", "peek")

OPERANDS = {
    "OP_PUSH_IMM8": (1,), "OP_PUSH_IMM16": (2,), "OP_PUSH_IMM32": (4,),
    "OP_PUSH_IMM64": (8,), "OP_PUSH_REG": (1,), "OP_POP_REG": (1,),
    "OP_PUSH_POOL": (2,), "OP_PUSH_FRAME": (2,), "OP_JMP": (4,),
    "OP_JZ": (4,), "OP_JNZ": (4,), "OP_CALL": (1, 1),
    "OP_SEXT": (1,), "OP_TRUNC": (1,), "OP_LOAD_ARG": (1,),
}
WIDTH_OPS = {
    "OP_ADD", "OP_SUB", "OP_MUL", "OP_UDIV", "OP_SDIV", "OP_UREM", "OP_SREM",
    "OP_AND", "OP_OR", "OP_XOR", "OP_NOT", "OP_SHL", "OP_LSHR", "OP_ASHR",
    "OP_ICMP_EQ", "OP_ICMP_NE", "OP_ICMP_ULT", "OP_ICMP_ULE", "OP_ICMP_UGT",
    "OP_ICMP_UGE", "OP_ICMP_SLT", "OP_ICMP_SLE", "OP_ICMP_SGT", "OP_ICMP_SGE",
}
OPERANDS.update({name: (1,) for name in WIDTH_OPS})
JUMPS = {"OP_JMP", "OP_JZ", "OP_JNZ"}
IMMEDIATES = {"OP_PUSH_IMM8", "OP_PUSH_IMM16", "OP_PUSH_IMM32", "OP_PUSH_IMM64"}
FUSED_EXPRESSIONS = {
    "OP_ADD": "a + b", "OP_SUB": "a - b", "OP_MUL": "a * b",
    "OP_AND": "a & b", "OP_OR": "a | b", "OP_XOR": "a ^ b",
    "OP_SHL": "a << vm_shamt(b, w)",
    "OP_LSHR": "vm_zext(a, w) >> vm_shamt(b, w)",
    "OP_ASHR": "(uint64_t)(vm_sext(a, w) >> vm_shamt(b, w))",
}


@dataclass(frozen=True)
class Instruction:
    offset: int
    name: str
    values: tuple[int, ...]
    widths: tuple[int, ...]
    originals: int = 1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def opcode_table(text: str) -> dict[int, str]:
    entries = re.findall(r"^KAGURA_VM_OP\((OP_\w+),\s*(0x[0-9A-Fa-f]+)\)", text, re.M)
    table = {int(value, 16): name for name, value in entries}
    if not entries or len(table) != len(entries) or len(set(table.values())) != len(table):
        raise ValueError("Missing or duplicate stock opcodes")
    if 0xfe in table:
        raise ValueError("Format guard requires stock opcode 0xfe to be undefined")
    return table


def llvm_bytes(text: str) -> bytes:
    values = bytearray()
    i = 0
    while i < len(text):
        if text[i] == "\\":
            if text[i:i + 2] == "\\\\":
                values.append(0x5c)
                i += 2
                continue
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", text[i + 1:i + 3]):
                raise ValueError("Unsupported LLVM byte-string escape")
            values.append(int(text[i + 1:i + 3], 16))
            i += 3
        else:
            if ord(text[i]) > 127:
                raise ValueError("Non-ASCII unescaped LLVM byte")
            values.append(ord(text[i]))
            i += 1
    return bytes(values)


def llvm_string(data: bytes) -> str:
    return "".join(f"\\{byte:02X}" for byte in data)


def decode_stock(data: bytes, key: int, table: dict[int, str]) -> list[Instruction]:
    """Read the pinned compiler's private build output, validating boundaries."""
    plain = bytes(value ^ ((key >> (8 * (i & 7))) & 255) for i, value in enumerate(data))
    result = []
    offset = 0
    while offset < len(plain):
        start = offset
        name = table.get(plain[offset])
        if name is None:
            raise ValueError(f"Unknown stock opcode at {offset}")
        offset += 1
        widths = OPERANDS.get(name, ())
        values = []
        for width in widths:
            if offset + width > len(plain):
                raise ValueError("Truncated stock operand")
            values.append(int.from_bytes(plain[offset:offset + width], "little"))
            offset += width
        if name in WIDTH_OPS | {"OP_SEXT", "OP_TRUNC"} and not 1 <= values[0] <= 64:
            raise ValueError("Invalid operand width")
        if name == "OP_CALL" and (values[0] > 8 or values[1] > 64):
            raise ValueError("Invalid native-call operands")
        result.append(Instruction(start, name, tuple(values), widths))
    boundaries = {item.offset for item in result}
    if any(item.values[0] not in boundaries for item in result if item.name in JUMPS):
        raise ValueError("Branch target is not an instruction boundary")
    return result


def fuse(instructions: list[Instruction]) -> list[Instruction]:
    """Fuse straight-line dataflow; never absorb a branch destination."""
    targets = {item.values[0] for item in instructions if item.name in JUMPS}
    result = []
    i = 0
    while i < len(instructions):
        tail = instructions[i:]
        candidate = None
        count = 1
        if (len(tail) >= 4 and tail[0].name == "OP_PUSH_REG"
                and tail[1].name in IMMEDIATES | {"OP_PUSH_REG"}
                and tail[2].name in FUSED_EXPRESSIONS and tail[3].name == "OP_POP_REG"):
            reg = tail[1].name == "OP_PUSH_REG"
            mode = "RR" if reg else "RI"
            values = (tail[3].values[0], tail[0].values[0], tail[2].values[0], tail[1].values[0])
            candidate = Instruction(tail[0].offset, f"F_{mode}_{tail[2].name[3:]}",
                                    values, (1, 1, 1, 1 if reg else 8), 4)
            count = 4
        elif (len(tail) >= 3 and tail[0].name == "OP_LOAD_ARG"
              and tail[1].name == "OP_ZEXT" and tail[2].name == "OP_POP_REG"):
            candidate = Instruction(tail[0].offset, "F_ARG", (tail[2].values[0], tail[0].values[0]), (1, 1), 3)
            count = 3
        elif len(tail) >= 2 and tail[1].name == "OP_POP_REG":
            if tail[0].name in {"OP_PUSH_REG", "OP_LOAD_ARG"}:
                name = "F_MOV" if tail[0].name == "OP_PUSH_REG" else "F_ARG"
                candidate = Instruction(tail[0].offset, name, (tail[1].values[0], tail[0].values[0]), (1, 1), 2)
                count = 2
            elif tail[0].name in IMMEDIATES:
                candidate = Instruction(tail[0].offset, "F_CONST", (tail[1].values[0], tail[0].values[0]), (1, 8), 2)
                count = 2
        if candidate is not None and not any(item.offset in targets for item in tail[1:count]):
            result.append(candidate)
            i += count
        else:
            result.append(tail[0])
            i += 1
    return fuse_chains(result, targets)


def fuse_chains(instructions: list[Instruction], targets: set[int]) -> list[Instruction]:
    """Pair direct register expressions without losing intermediate writes/entries."""
    result = []
    index = 0
    while index < len(instructions):
        first = instructions[index]
        second = instructions[index + 1] if index + 1 < len(instructions) else None
        if (second is not None and second.offset not in targets
                and first.name.startswith(("F_RR_", "F_RI_"))
                and second.name.startswith(("F_RR_", "F_RI_"))):
            result.append(Instruction(first.offset,
                                      "F_CHAIN_" + first.name[2:] + "__" + second.name[2:],
                                      first.values + second.values, first.widths + second.widths,
                                      first.originals + second.originals))
            index += 2
        else:
            result.append(first)
            index += 1
    return result


def parameters(seed: int, names: set[str]) -> dict:
    rng = random.Random(seed)
    tokens = rng.sample(range(0x100, 0xffff), len(names))
    return {"tokens": dict(zip(sorted(names), tokens)), "multiply": rng.getrandbits(32) | 1,
            "add": rng.getrandbits(32), "mix": rng.getrandbits(32) | 1,
            "rotate": rng.randrange(7), "header": [rng.randrange(256) for _ in range(3)],
            "operand_multiply": rng.getrandbits(32) | 1, "operand_add": rng.getrandbits(32)}


def operand_context(position: int, token: int, key: int, params: dict) -> int:
    return ((position * params["operand_multiply"]) ^ token ^ key ^ (key >> 32)
            ^ params["operand_add"]) & 0xffffffff


def operand_step(state: int, plain: int, params: dict) -> int:
    rotated = ((state << 5) | (state >> 27)) & 0xffffffff
    return (rotated * params["operand_multiply"] + plain + params["operand_add"]) & 0xffffffff


def encode_fetch(plain: bytes, key: int, params: dict, start=HEADER_SIZE) -> bytes:
    result = bytearray()
    for position, byte in enumerate(plain, start):
        mixed = (position * params["multiply"] + params["add"]) & 0xffffffff
        mixed ^= mixed >> 13
        mixed = (mixed * params["mix"]) & 0xffffffff
        mixed ^= mixed >> 17
        mask = (mixed ^ (key >> (8 * (position & 7)))) & 255
        rotation = ((position + params["rotate"]) % 7) + 1
        value = (byte + mask) & 255
        result.append((((value << rotation) | (value >> (8 - rotation))) & 255) ^ ((mixed >> 8) & 255))
    return bytes(result)


def emit(instructions: list[Instruction], key: int, params: dict) -> tuple[bytes, dict[int, int]]:
    relocations = {}
    length = HEADER_SIZE
    for item in instructions:
        relocations[item.offset] = length
        length += 2 + sum(item.widths)
    data = bytearray()
    for item in instructions:
        token = params["tokens"][item.name]
        state = operand_context(relocations[item.offset], token, key, params)
        data.extend(token.to_bytes(2, "big"))
        values = (relocations[item.values[0]],) if item.name in JUMPS else item.values
        for value, width in zip(values, item.widths):
            for byte in value.to_bytes(width, "big"):
                mask = (state ^ (state >> 11) ^ (state >> 23)) & 255
                data.append(byte ^ mask)
                state = operand_step(state, byte, params)
    header = bytes([(key & 255) ^ 0xfe] + params["header"])
    return header + encode_fetch(bytes(data), key, params), relocations


def fused_body(name: str) -> str:
    if name.startswith("F_CHAIN_"):
        parts = name.removeprefix("F_CHAIN_").split("__")
        if len(parts) != 2 or any(not re.fullmatch(r"R[RI]_[A-Z]+", part) for part in parts):
            raise ValueError("Invalid chained register handler")
        # Keep the scopes and writes sequential: a second read may alias the first destination.
        return " ".join("{ " + fused_body("F_" + part) + " }" for part in parts)
    if name == "F_MOV":
        body = "uint8_t d=bc_u8(&f), s=bc_u8(&f); f.regs[d]=f.regs[s];"
    elif name == "F_ARG":
        body = "uint8_t d=bc_u8(&f), s=bc_u8(&f); f.regs[d]=(s<f.nargs)?f.args[s]:0;"
    elif name == "F_CONST":
        body = "uint8_t d=bc_u8(&f); f.regs[d]=bc_u64(&f);"
    else:
        mode, operation = name[2:].split("_", 1)
        expression = FUSED_EXPRESSIONS["OP_" + operation]
        rhs = "f.regs[bc_u8(&f)]" if mode == "RR" else "bc_u64(&f)"
        body = (f"uint8_t d=bc_u8(&f), s=bc_u8(&f); unsigned w=vm_width(&f); "
                f"uint64_t a=f.regs[s], b={rhs}; f.regs[d]=vm_zext({expression},w);")
    return body


def fused_handler(name: str) -> str:
    return f"        case {name}: {{ {fused_body(name)} break; }}\n"


def specialize_runtime(source: str, params: dict, symbol: str) -> str:
    """Specialize pinned source, retaining semantics of unfused handlers."""
    source = source.replace('#include "../internal.h"', '/* Standalone generated runtime; original internal declarations are unnecessary. */')
    enum = "enum vm_opcode {\n" + "".join(f"    {name} = {token},\n" for name, token in params["tokens"].items()) + "};"
    source, count = re.subn(r"enum vm_opcode \{.*?\};", lambda _: enum, source, count=1, flags=re.S)
    if count != 1:
        raise ValueError("Pinned runtime opcode declaration not found")
    source, count = re.subn(r"#define KAGURA_VM_LIMIT\([^\n]+\n.*?enum vm_limit \{.*?\};",
                            "enum vm_limit { VM_NUM_REGS=256, VM_STACK_SIZE=128, VM_FRAME_SIZE=1024, VM_MAX_CALL_ARGS=8 };",
                            source, count=1, flags=re.S)
    if count != 1:
        raise ValueError("Pinned runtime limits not found")
    source, count = re.subn(r"(?m)^(\s*)uint32_t pc;", r"\1uint32_t operand_state;\n\1uint32_t pc;", source, count=1)
    if count != 1:
        raise ValueError("Pinned runtime frame pc field not found")
    fetch = f"""static __attribute__((always_inline)) inline uint8_t bc_raw8(VMFrame *f) {{
    uint32_t p=f->pc;
    if (__builtin_expect(p >= f->bc_size, 0)) abort();
    f->pc=p+1;
    uint32_t t=p*{params['multiply']}u+{params['add']}u;
    t ^= t >> 13; t *= {params['mix']}u; t ^= t >> 17;
    uint8_t m=(uint8_t)(t ^ (f->key >> (8u*(p&7u))));
    unsigned r=((p+{params['rotate']}u)%7u)+1u;
    uint8_t v=(uint8_t)(f->bc[p] ^ (uint8_t)(t >> 8));
    v=(uint8_t)((v >> r) | ((unsigned)v << (8u-r)));
    return (uint8_t)(v-m);
}}

static __attribute__((always_inline)) inline uint16_t bc_opcode(VMFrame *f) {{
    uint32_t start=f->pc;
    uint16_t hi=bc_raw8(f);
    uint16_t op=(uint16_t)((hi << 8) | bc_raw8(f));
    f->operand_state=(start*{params['operand_multiply']}u) ^ op ^ (uint32_t)f->key
                     ^ (uint32_t)(f->key >> 32) ^ {params['operand_add']}u;
    return op;
}}

static __attribute__((always_inline)) inline uint8_t bc_u8(VMFrame *f) {{
    uint32_t s=f->operand_state;
    uint8_t v=(uint8_t)(bc_raw8(f) ^ (uint8_t)(s ^ (s >> 11) ^ (s >> 23)));
    uint32_t rotated=(s << 5) | (s >> 27);
    f->operand_state=rotated*{params['operand_multiply']}u+v+{params['operand_add']}u;
    return v;
}}

static __attribute__((always_inline)) inline uint16_t bc_u16(VMFrame *f) {{
    uint16_t hi=bc_u8(f); return (uint16_t)((hi << 8) | bc_u8(f));
}}
static __attribute__((always_inline)) inline uint32_t bc_u32(VMFrame *f) {{
    uint32_t hi=bc_u16(f); return (hi << 16) | bc_u16(f);
}}
static __attribute__((always_inline)) inline uint64_t bc_u64(VMFrame *f) {{
    uint64_t hi=bc_u32(f); return (hi << 32) | bc_u32(f);
}}
"""
    start = source.index("static inline uint8_t bc_u8")
    end = source.index("/* ── Width helpers", start)
    source = source[:start] + fetch + "\n" + source[end:]
    source = source.replace("uint64_t kagura_vm_execute(", f"uint64_t {symbol}(")
    source = source.replace("    VMFrame f;", (
        "    /* A format-version guard, not an authenticity or secrecy claim. */\n"
        f"    if (bc_size<4 || bytecode[0]!=(uint8_t)(key^0xfeu) || bytecode[1]!={params['header'][0]}u"
        f" || bytecode[2]!={params['header'][1]}u || bytecode[3]!={params['header'][2]}u) abort();\n    VMFrame f;"))
    source = source.replace("f.pc      = 0;", "f.pc      = 4;")
    source = source.replace("uint8_t op = bc_u8(&f);", "uint16_t op = bc_opcode(&f);")
    loop = source.index("        switch (op) {")
    end = source.index("        default: abort();", loop)
    section = source[loop:end]
    cases = list(re.finditer(r"(?m)^        case (OP_\w+):", section))
    found = {match.group(1) for match in cases}
    wanted = {name for name in params["tokens"] if name.startswith("OP_")}
    if not wanted.issubset(found):
        raise ValueError("Missing runtime handlers")
    kept = "        switch (op) {\n"
    for index, match in enumerate(cases):
        if match.group(1) in wanted:
            stop = cases[index + 1].start() if index + 1 < len(cases) else len(section)
            kept += section[match.start():stop]
    kept += "".join(fused_handler(name) for name in sorted(params["tokens"]) if name.startswith("F_"))
    source = source[:loop] + kept + source[end:]
    # Put semantic primitives inside the dispatcher before its protection passes.
    # Native-call thunks remain separate; this changes no VM value semantics.
    source = re.sub(
        r"(?m)^static inline (?=(?:void|unsigned|u?int64_t) vm_(?:" + "|".join(INTEGRATED_HELPERS) + r")\()",
        "static __attribute__((always_inline)) inline ", source)
    return ("/* Generated private build artifact: diversified VM v2.\n"
            " * Based on pinned Kagura runtime; opcode/fetch contract below supersedes\n"
            " * the upstream descriptive comments. Not cryptographic secrecy. */\n" + source)


def transform_ir(ir: str, table: dict[int, str], seed: int) -> tuple[str, dict]:
    blobs = list(re.finditer(r'^@(kagura_vm_bc_(\d+)) = private constant \[(\d+) x i8\] c"([^"\n]*)"', ir, re.M))
    if not blobs:
        raise ValueError("No supported Kagura bytecode globals")
    plans = []
    for match in blobs:
        name, suffix, size, text = match.groups()
        data = llvm_bytes(text)
        if len(data) != int(size):
            raise ValueError("Bytecode size does not match LLVM declaration")
        key_match = re.search(r"^@kagura_vm_key_" + suffix + r" = private constant i64 (-?\d+)$", ir, re.M)
        if key_match is None:
            raise ValueError("Unsupported key expression")
        key = int(key_match.group(1)) & 0xffffffffffffffff
        instructions = decode_stock(data, key, table)
        fused = fuse(instructions)
        plans.append((match, data, key, instructions, fused))
    names = {item.name for _, _, _, _, items in plans for item in items}
    params = parameters(seed, names)
    symbol = f"antirea_dispatch_{seed & 0xffffffffffffffff:016x}"
    records = []
    for match, data, key, instructions, fused in reversed(plans):
        encoded, relocations = emit(fused, key, params)
        name = match.group(1)
        replacement = f'@{name} = private constant [{len(encoded)} x i8] c"{llvm_string(encoded)}"'
        ir = ir[:match.start()] + replacement + ir[match.end():]
        call_pattern = r"(@kagura_vm_execute\(ptr @" + name + r", i32 )" + str(len(data)) + r"\b"
        ir, calls = re.subn(call_pattern, lambda m: m.group(1) + str(len(encoded)), ir)
        if calls != 1:
            raise ValueError("Each bytecode blob must have exactly one supported wrapper call")
        counts = Counter(item.name for item in fused if item.originals > 1)
        records.append({"global": name, "original_bytes": len(data), "encoded_bytes": len(encoded),
                        "original_instructions": len(instructions), "emitted_instructions": len(fused),
                        "fused_groups": sum(counts.values()), "fusion_counts": dict(sorted(counts.items())),
                        "absorbed_dispatches": sum(item.originals - 1 for item in fused),
                        "original_sha256": sha256(data), "encoded_sha256": sha256(encoded),
                        "relocated_branch_targets": sum(item.name in JUMPS for item in fused),
                        "stock_first_opcode_after_original_xor": encoded[0] ^ (key & 255)})
    if not any(record["fused_groups"] for record in records):
        raise ValueError("No meaningful fusion applied; refusing diversification claim")
    ir = ir.replace("@kagura_vm_execute", "@" + symbol)
    manifest = {"schema_version": 1, "format_version": FORMAT_VERSION, "seed": seed,
                "dispatcher_symbol": symbol, "parameters": params, "blobs": list(reversed(records)),
                "opcode_bits": 16, "operand_byte_order": "big", "header_bytes": HEADER_SIZE,
                "used_handlers": sorted(names), "stock_format_directly_compatible": False,
                "instruction_fusion": "direct register operations, not replay of original stack opcodes",
                "fetch_encoding": "position/key-dependent rotate/add/xor; reversible, not encryption security",
                "operand_encoding": "instruction-position/opcode/key context with plaintext feedback; resets at every instruction",
                "fetch_inlined_in_dispatcher": True,
                "semantic_helpers_inlined_in_dispatcher": list(INTEGRATED_HELPERS),
                "external_attack_evaluation": "not_evaluated",
                "limitations": ["Generated ISA and decoder remain present in the delivered executable.",
                                "No cryptographic secrecy, anti-analysis guarantee or resistance result is claimed.",
                                "Only the pinned supported Kagura IR/bytecode format is accepted."]}
    chains = sum(count for record in records for name, count in record['fusion_counts'].items()
                 if name.startswith('F_CHAIN_'))
    if chains:
        manifest['chained_register_fusion'] = {
            'groups': chains, 'operations_per_group': 2,
            'semantics': 'sequential direct expressions with both intermediate register writes retained'}
    return ir, manifest


def generate(input_ir: Path, runtime_source: Path, opcode_source: Path, output_dir: Path, seed: int) -> dict:
    runtime_bytes, opcode_bytes = runtime_source.read_bytes(), opcode_source.read_bytes()
    if sha256(runtime_bytes) != RUNTIME_SHA256 or sha256(opcode_bytes) != OPCODES_SHA256:
        raise ValueError("Upstream runtime/opcode source does not match pinned build input")
    ir_bytes = input_ir.read_bytes()
    ir, manifest = transform_ir(ir_bytes.decode("utf-8-sig"), opcode_table(opcode_bytes.decode("utf-8")), seed)
    runtime = specialize_runtime(runtime_bytes.decode("utf-8"), manifest["parameters"], manifest["dispatcher_symbol"])
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = [output_dir / name for name in ("core.diversified.ll", "runtime.generated.c", "diversification.json")]
    if any(path.exists() for path in paths):
        raise ValueError("Refusing to overwrite generated artifacts")
    manifest.update(kagura_commit=PINNED_COMMIT, input_ir_sha256=sha256(ir_bytes),
                    upstream_runtime_sha256=sha256(runtime_bytes), upstream_opcodes_sha256=sha256(opcode_bytes),
                    output_ir_sha256=sha256(ir.encode()), generated_runtime_sha256=sha256(runtime.encode()))
    paths[0].write_text(ir, encoding="utf-8", newline="\n")
    paths[1].write_text(runtime, encoding="utf-8", newline="\n")
    paths[2].write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-ir", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--opcode-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    result = generate(args.input_ir, args.runtime_source, args.opcode_source, args.output_dir, args.seed)
    print(json.dumps({key: result[key] for key in ("dispatcher_symbol", "blobs", "external_attack_evaluation")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
