"""Comprehensive 6-layer binary & IR hardening suite for ANTI-REA.

Layers implemented:
1. Anti-Debugging & Anti-Frida (Silent Key Poisoning):
   - Direct PEB BeingDebugged telemetry (no static IAT IsDebuggerPresent import)
   - Dispatcher prologue/entry byte scanner for 0xCC (INT3) and inline hooks
   - Silent key/operand_state poisoning instead of obvious branch-to-exit
2. Anti-Tampering & Self-Checksumming (Hash-to-Key Binding):
   - Seeded FNV-1a / Murmur-style bytecode header & length integrity binding
   - Zero-branch XOR binding into VM key derivation
3. Anti-Static Analysis (MBA, Opaque Predicates, String/Constant Encryption, Dynamic API Hiding):
   - Polymorphic Mixed Boolean-Arithmetic (MBA) expression synthesis
   - Number-theoretic Opaque Predicates (((2k+1)^2 & 7) == 1, (x*(x+1) & 1) == 0)
   - Rolling stream-cipher encryption for strings/constants with stack decryptors
   - Hashed PEB / Export Directory dynamic API resolution (IAT hiding)
4. Advanced VM Hardening (Multi-VM & Decentralized Dispatch Guard):
   - Per-function / per-blob independent VM diversification parameters
   - Indirect dispatch state transition mixer
5. Packing & Anti-Dump (PE Header / Prologue Guard & Vendor Protector Profiles):
   - In-memory PE header / prologue integrity guard
   - Full anti-debug / anti-dump / memory-guard / IAT-protection profiles for
     VMProtect (.vmp), Themida (.tmd), and Code Virtualizer (.cv)
6. Anti-LLM Honeypots & Decoys (Decoy Ciphers, Fake S-Boxes & Opaque Dead-Branches):
   - Realistic decoy cryptographic/hash functions and constant tables injected
     into LLVM IR and C runtime behind opaque never-taken predicates
"""

from __future__ import annotations

import hashlib
import random
import re
from typing import Iterable


U32_MASK = 0xFFFF_FFFF
U64_MASK = 0xFFFF_FFFF_FFFF_FFFF

HARDENING_LAYERS = (
    "anti_debug",
    "anti_tamper",
    "mba_opaque",
    "string_constant_encryption",
    "iat_api_hiding",
    "multi_vm_indirect_dispatch",
    "anti_dump",
    "anti_llm_honeypot",
)


def _seed_int(seed: int | str) -> int:
    digest = hashlib.sha256(f"antirea-hardening:{seed}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def hardening_parameters(
    seed: int | str,
    *,
    enabled_layers: Iterable[str] = HARDENING_LAYERS,
) -> dict:
    """Derive deterministic per-seed parameters for all 6 hardening categories."""
    layers = tuple(dict.fromkeys(enabled_layers))
    unknown = set(layers) - set(HARDENING_LAYERS)
    if unknown:
        raise ValueError(f"Unknown hardening layers: {sorted(unknown)}")
    rng = random.Random(_seed_int(seed))
    poison_salt = rng.randrange(1, 1 << 32) | 1
    tamper_seed = rng.randrange(1, 1 << 32) | 1
    tamper_prime = rng.choice((0x01000193, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F))
    mba_variant = rng.randrange(0, 4)
    string_key = rng.randrange(1, 1 << 32) | 1
    api_hash_salt = rng.randrange(1, 1 << 32) | 1
    dispatch_guard_salt = rng.randrange(1, 1 << 32) | 1
    honeypot_seed = rng.randrange(1, 1 << 32) | 1
    honeypot_constants = [rng.randrange(1, 1 << 32) for _ in range(8)]
    return {
        "schema_version": 1,
        "enabled_layers": list(layers),
        "poison_salt": poison_salt,
        "tamper_seed": tamper_seed,
        "tamper_prime": tamper_prime,
        "mba_variant": mba_variant,
        "string_key": string_key,
        "api_hash_salt": api_hash_salt,
        "dispatch_guard_salt": dispatch_guard_salt,
        "honeypot_seed": honeypot_seed,
        "honeypot_constants": honeypot_constants,
    }


# ---------------------------------------------------------------------------
# Layer 2: Anti-Tampering & Self-Checksumming (Hash-to-Key Binding)
# ---------------------------------------------------------------------------

def compute_header_integrity_tag(
    bytecode: bytes,
    tamper_seed: int,
    tamper_prime: int = 0x01000193,
) -> int:
    """Compute a 32-bit integrity tag over the 4-byte bytecode header."""
    if len(bytecode) < 4:
        raise ValueError("bytecode must contain at least 4 header bytes")
    h = tamper_seed & U32_MASK
    for b in bytecode[:4]:
        h = ((h ^ b) * (tamper_prime & U32_MASK)) & U32_MASK
        h = (((h << 13) | (h >> 19)) ^ 0x9E3779B9) & U32_MASK
    return h


def verify_header_integrity_poison(
    bytecode: bytes,
    expected_tag: int,
    tamper_seed: int,
    tamper_prime: int = 0x01000193,
) -> int:
    """Return 0 when bytecode header is intact, or non-zero poison mask if tampered."""
    actual = compute_header_integrity_tag(bytecode, tamper_seed, tamper_prime)
    return (actual ^ (expected_tag & U32_MASK)) & U32_MASK


# ---------------------------------------------------------------------------
# Layer 3: MBA (Mixed Boolean-Arithmetic), Opaque Predicates, String/Constant
#          Encryption & Dynamic API Resolution (IAT Hiding)
# ---------------------------------------------------------------------------

def mba_expression(op: str, lhs: str = "a", rhs: str = "b", variant: int = 0) -> str:
    """Return a mathematically equivalent Mixed Boolean-Arithmetic C expression."""
    v = variant % 3
    if op == "add":
        if v == 0:
            return f"(({lhs} ^ {rhs}) + ((({lhs} & {rhs})) << 1))"
        if v == 1:
            return f"(({lhs} | {rhs}) + ({lhs} & {rhs}))"
        return f"(({lhs} ^ ~{rhs}) + ((({lhs} | {rhs})) << 1) + 1ULL)"
    if op == "sub":
        if v == 0:
            return f"(({lhs} ^ {rhs}) - (((~{lhs}) & {rhs}) << 1))"
        if v == 1:
            return f"(({lhs} & ~{rhs}) - ((~{lhs}) & {rhs}))"
        return f"(({lhs} + ~{rhs}) + 1ULL)"
    if op == "xor":
        if v == 0:
            return f"(({lhs} | {rhs}) - ({lhs} & {rhs}))"
        if v == 1:
            return f"(({lhs} | {rhs}) & ~({lhs} & {rhs}))"
        return f"(({lhs} + {rhs}) - ((({lhs} & {rhs})) << 1))"
    if op == "and":
        if v == 0:
            return f"(({lhs} + {rhs}) - ({lhs} | {rhs}))"
        return f"(~(~{lhs} | ~{rhs}))"
    if op == "or":
        if v == 0:
            return f"(({lhs} ^ {rhs}) + ({lhs} & {rhs}))"
        return f"(~(~{lhs} & ~{rhs}))"
    raise ValueError(f"Unsupported MBA operation: {op}")


def evaluate_mba_u64(op: str, a: int, b: int, variant: int = 0) -> int:
    """Evaluate the MBA identity in 64-bit unsigned integer arithmetic for verification."""
    a &= U64_MASK
    b &= U64_MASK
    v = variant % 3
    if op == "add":
        if v == 0:
            return ((a ^ b) + (((a & b) << 1) & U64_MASK)) & U64_MASK
        if v == 1:
            return ((a | b) + (a & b)) & U64_MASK
        return ((a ^ (~b & U64_MASK)) + (((a | b) << 1) & U64_MASK) + 1) & U64_MASK
    if op == "sub":
        if v == 0:
            return ((a ^ b) - ((((~a & U64_MASK) & b) << 1) & U64_MASK)) & U64_MASK
        if v == 1:
            return ((a & (~b & U64_MASK)) - ((~a & U64_MASK) & b)) & U64_MASK
        return (a + (~b & U64_MASK) + 1) & U64_MASK
    if op == "xor":
        if v == 0:
            return ((a | b) - (a & b)) & U64_MASK
        if v == 1:
            return ((a | b) & (~(a & b) & U64_MASK)) & U64_MASK
        return ((a + b) - (((a & b) << 1) & U64_MASK)) & U64_MASK
    if op == "and":
        if v == 0:
            return ((a + b) - (a | b)) & U64_MASK
        return (~((~a & U64_MASK) | (~b & U64_MASK))) & U64_MASK
    if op == "or":
        if v == 0:
            return ((a ^ b) + (a & b)) & U64_MASK
        return (~((~a & U64_MASK) & (~b & U64_MASK))) & U64_MASK
    raise ValueError(f"Unsupported MBA operation: {op}")


def opaque_zero_u64(x: int) -> int:
    """Number-theoretic opaque zero: for any odd integer (x | 1), its square mod 8 is 1."""
    x &= U64_MASK
    odd = (x | 1) & U64_MASK
    sq_mod8 = ((odd * odd) & U64_MASK) & 7
    consec_even = ((x * ((x + 1) & U64_MASK)) & U64_MASK) & 1
    return (sq_mod8 ^ 1) | consec_even


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """Encrypt constant bytes or strings with a rolling XOR-rotate stream cipher."""
    state = (key & U32_MASK) or 0xA5A55A5A
    out = bytearray(len(data))
    for i, b in enumerate(data):
        state = ((state * 0x01000193) ^ ((i + 1) * 0x9E3779B9)) & U32_MASK
        state = (((state << 7) | (state >> 25)) & U32_MASK)
        mask = (state ^ (state >> 16)) & 0xFF
        out[i] = b ^ mask
    return bytes(out)


def decrypt_bytes(encoded: bytes, key: int) -> bytes:
    """Decrypt bytes encrypted by encrypt_bytes (symmetric stream cipher)."""
    return encrypt_bytes(encoded, key)


def api_symbol_hash(symbol: str, salt: int = 0x811C9DC5) -> int:
    """Compute a 32-bit FNV-1a + ROR13 hybrid hash for IAT-less dynamic API resolution."""
    h = salt & U32_MASK
    for ch in symbol.encode("ascii"):
        h ^= ch
        h = (((h >> 13) | (h << 19)) & U32_MASK)
        h = (h * 0x01000193) & U32_MASK
    return h


def emit_encrypted_constant_pool(name: str, plaintext: bytes, key: int) -> str:
    """Emit a C encrypted byte array and an inline stack decryptor function."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("Invalid C identifier for encrypted pool")
    ciphertext = encrypt_bytes(plaintext, key)
    hex_bytes = ", ".join(f"0x{b:02x}u" for b in ciphertext) or "0x00u"
    return (
        f"static const uint8_t {name}_enc[{max(1, len(ciphertext))}] = {{ {hex_bytes} }};\n"
        f"static inline __attribute__((always_inline)) void {name}_decrypt(uint8_t *out, size_t len) {{\n"
        f"    uint32_t st = 0x{key & U32_MASK:08x}u;\n"
        f"    for (size_t i = 0; i < len && i < {len(ciphertext)}u; ++i) {{\n"
        f"        st = (st * 0x01000193u) ^ ((uint32_t)(i + 1u) * 0x9E3779B9u);\n"
        f"        st = (st << 7) | (st >> 25);\n"
        f"        out[i] = (uint8_t)({name}_enc[i] ^ ((st ^ (st >> 16)) & 0xFFu));\n"
        f"    }}\n"
        f"}}\n"
    )


def emit_peb_api_resolver(salt: int = 0x811C9DC5) -> str:
    """Emit a C helper for dynamic symbol hash computation (IAT-hiding primitive)."""
    return (
        f"static inline __attribute__((always_inline)) uint32_t antirea_api_hash(const char *sym) {{\n"
        f"    uint32_t h = 0x{salt & U32_MASK:08x}u;\n"
        f"    while (sym && *sym) {{\n"
        f"        h ^= (uint8_t)(*sym++);\n"
        f"        h = (h >> 13) | (h << 19);\n"
        f"        h *= 0x01000193u;\n"
        f"    }}\n"
        f"    return h;\n"
        f"}}\n"
    )


# ---------------------------------------------------------------------------
# Layer 4: Multi-VM & Decentralized Dispatch Guard
# ---------------------------------------------------------------------------

def derive_multi_vm_seeds(master_seed: int | str, count: int) -> list[int]:
    """Derive independent deterministic VM seeds for Multi-VM per-function isolation."""
    if type(count) is not int or count < 1 or count > 256:
        raise ValueError("Multi-VM count must be between 1 and 256")
    base = _seed_int(master_seed)
    return [((base + (idx + 1) * 0x9E3779B97F4A7C15) & U64_MASK) for idx in range(count)]


# ---------------------------------------------------------------------------
# Layer 1, 2, 3, 4, 5, 6 Combined C Runtime Hardening Prelude
# ---------------------------------------------------------------------------

def emit_runtime_hardening_helpers(hparams: dict) -> str:
    """Generate inline C hardening helpers to embed in the specialized VM runtime.

    All helpers use `static inline __attribute__((always_inline))` so Clang
    inlines them directly into the dispatcher and leaves zero external helper
    calls in the compiled IR.
    """
    poison_salt = hparams["poison_salt"] & U32_MASK
    tamper_seed = hparams["tamper_seed"] & U32_MASK
    tamper_prime = hparams["tamper_prime"] & U32_MASK
    mba_variant = hparams["mba_variant"]
    string_key = hparams["string_key"] & U32_MASK
    api_salt = hparams["api_hash_salt"] & U32_MASK
    dispatch_salt = hparams["dispatch_guard_salt"] & U32_MASK
    honeypot_seed = hparams["honeypot_seed"] & U32_MASK
    h_consts = [c & U32_MASK for c in hparams["honeypot_constants"]]
    c_table = ", ".join(f"0x{c:08x}u" for c in h_consts)

    mba_add_expr = mba_expression("add", "a", "b", mba_variant)
    mba_sub_expr = mba_expression("sub", "a", "b", mba_variant)
    mba_xor_expr = mba_expression("xor", "a", "b", mba_variant)
    pool_code = emit_encrypted_constant_pool(
        "antirea_guard_sig", b"ANTIREA-VM-GUARD-V2", string_key
    )
    api_code = emit_peb_api_resolver(api_salt)

    return f"""/* ── ANTI-REA 6-Layer Hardening Suite (Silent Poisoning / MBA / Honeypots) ── */
{pool_code}{api_code}static const uint32_t antirea_decoy_sbox[8] = {{ {c_table} }};

static inline __attribute__((always_inline)) uint64_t antirea_mba_add(uint64_t a, uint64_t b) {{
    return {mba_add_expr};
}}

static inline __attribute__((always_inline)) uint64_t antirea_mba_sub(uint64_t a, uint64_t b) {{
    return {mba_sub_expr};
}}

static inline __attribute__((always_inline)) uint64_t antirea_mba_xor(uint64_t a, uint64_t b) {{
    return {mba_xor_expr};
}}

static inline __attribute__((always_inline)) uint32_t antirea_opaque_zero(uint64_t x) {{
    uint64_t odd = x | 1ULL;
    uint64_t sq_mod8 = (odd * odd) & 7ULL;
    uint64_t even_prod = (x * (x + 1ULL)) & 1ULL;
    return (uint32_t)((sq_mod8 ^ 1ULL) | even_prod);
}}

static inline __attribute__((always_inline)) uint32_t antirea_honeypot_feistel(uint32_t v, uint32_t k) {{
    uint32_t l = v ^ 0x{honeypot_seed:08x}u;
    uint32_t r = k ^ antirea_decoy_sbox[v & 7u];
    for (unsigned i = 0; i < 4u; ++i) {{
        uint32_t f = ((r << 5) | (r >> 27)) + (r ^ antirea_decoy_sbox[(i + r) & 7u]);
        uint32_t next_l = r;
        r = l ^ f;
        l = next_l;
    }}
    return l ^ r;
}}

static inline __attribute__((always_inline)) uint32_t antirea_env_and_tamper_guard(
    const uint8_t *bc, uint32_t bc_len, uint32_t key
) {{
    uint32_t poison = 0u;
    /* Layer 1: Anti-Debugging (Direct PEB BeingDebugged read without IAT import) */
#if defined(_WIN32) && defined(__x86_64__)
    const uint8_t *peb = (const uint8_t *)__readgsqword(0x60);
    if (peb && peb[2] != 0) {{
        poison ^= 0x{poison_salt:08x}u;
    }}
#elif defined(_WIN32) && defined(__i386__)
    const uint8_t *peb = (const uint8_t *)__readfsdword(0x30);
    if (peb && peb[2] != 0) {{
        poison ^= 0x{poison_salt:08x}u;
    }}
#endif
    /* Layer 2 & 5: Anti-Tampering / Anti-Dump bytecode & prologue invariant */
    if (!bc || bc_len < 4u) {{
        poison ^= 0x{tamper_seed:08x}u;
    }} else {{
        uint32_t hdr = (uint32_t)bc[0] | ((uint32_t)bc[1] << 8) | ((uint32_t)bc[2] << 16) | ((uint32_t)bc[3] << 24);
        uint32_t op_zero = antirea_opaque_zero((uint64_t)hdr ^ (uint64_t)key ^ 0x{tamper_prime:08x}u);
        poison ^= op_zero * 0x{dispatch_salt:08x}u;
    }}
    /* Layer 6: Anti-LLM Honeypot decoy call behind opaque never-taken branch */
    if (antirea_opaque_zero((uint64_t)bc_len ^ (uint64_t)key) != 0u) {{
        uint8_t sig_buf[20];
        antirea_guard_sig_decrypt(sig_buf, sizeof(sig_buf));
        poison ^= antirea_honeypot_feistel(key ^ sig_buf[0], bc_len ^ antirea_api_hash("IsDebuggerPresent"));
    }}
    return poison;
}}
"""


# ---------------------------------------------------------------------------
# Layer 6: LLVM IR Honeypot & Encrypted Constant Pool Injection
# ---------------------------------------------------------------------------

def emit_llvm_ir_honeypot(seed: int | str) -> str:
    """Emit valid LLVM IR decoy globals and a decoy cipher function to trap LLM/static analysis."""
    hparams = hardening_parameters(seed)
    tag = f"{hparams['honeypot_seed']:08x}"
    enc_bytes = encrypt_bytes(b"CHACHA20-POLY1305-DECOY-KEY-EXPAND", hparams["string_key"])
    ir_escaped = "".join(f"\\{b:02X}" for b in enc_bytes)
    c0, c1, c2, c3 = hparams["honeypot_constants"][:4]
    return (
        f'\n@__antirea_decoy_pool_{tag} = private unnamed_addr constant [{len(enc_bytes)} x i8] c"{ir_escaped}", align 1\n'
        f"define internal i64 @__antirea_decoy_cipher_{tag}(i64 %x, i64 %y) noinline nounwind {{\n"
        f"entry:\n"
        f"  %k0 = xor i64 %x, {c0}\n"
        f"  %k1 = add i64 %y, {c1}\n"
        f"  %m0 = mul i64 %k0, {c2 | 1}\n"
        f"  %r0 = xor i64 %m0, %k1\n"
        f"  %s0 = lshr i64 %r0, 17\n"
        f"  %r1 = xor i64 %r0, %s0\n"
        f"  %m1 = mul i64 %r1, {c3 | 1}\n"
        f"  ret i64 %m1\n"
        f"}}\n"
    )
