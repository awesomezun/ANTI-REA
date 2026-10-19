from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

import antirea.diversify as d
import antirea.hardening as h
from antirea.protectors import Service


def _sample_pe64() -> bytes:
    mz = bytearray(256)
    mz[0:2] = b"MZ"
    mz[60:64] = (64).to_bytes(4, "little")
    mz[64:68] = b"PE\x00\x00"
    mz[68:70] = (0x8664).to_bytes(2, "little")
    mz[84:86] = (112).to_bytes(2, "little")
    mz[88:90] = (0x20B).to_bytes(2, "little")
    mz.extend(b"\x00antirea_score\x00antirea_mix\x00antirea_verify\x00main\x00")
    return bytes(mz)


class HardeningSuiteTests(unittest.TestCase):
    def test_all_six_hardening_categories_present_in_parameters(self):
        params = h.hardening_parameters(42)
        self.assertEqual(set(params["enabled_layers"]), set(h.HARDENING_LAYERS))
        self.assertEqual(len(params["honeypot_constants"]), 8)
        self.assertTrue(params["poison_salt"] & 1)
        self.assertTrue(params["tamper_seed"] & 1)

    def test_anti_tamper_header_integrity_tag_and_silent_poison(self):
        blob = bytes([0xFE, 0x12, 0x34, 0x56, 0xAA, 0xBB])
        tag = h.compute_header_integrity_tag(blob, 0x13579BDF, 0x01000193)
        self.assertEqual(h.verify_header_integrity_poison(blob, tag, 0x13579BDF, 0x01000193), 0)
        for idx in range(4):
            tampered = bytearray(blob)
            tampered[idx] ^= 0x01
            poison = h.verify_header_integrity_poison(bytes(tampered), tag, 0x13579BDF, 0x01000193)
            self.assertNotEqual(poison, 0)

    def test_mba_identities_match_exact_64bit_arithmetic_and_bitwise_ops(self):
        samples = [
            (0, 0),
            (1, 1),
            (0xFFFFFFFF, 1),
            (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
            (0x123456789ABCDEF0, 0xFEDCBA9876543210),
            (0x8000000000000000, 0x7FFFFFFFFFFFFFFF),
        ]
        for a, b in samples:
            for variant in range(3):
                self.assertEqual(h.evaluate_mba_u64("add", a, b, variant), (a + b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("sub", a, b, variant), (a - b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("xor", a, b, variant), (a ^ b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("and", a, b, variant), (a & b) & h.U64_MASK)
                self.assertEqual(h.evaluate_mba_u64("or", a, b, variant), (a | b) & h.U64_MASK)

    def test_opaque_zero_holds_for_all_boundary_and_sampled_u64_values(self):
        values = [
            0, 1, 2, 3, 7, 8, 255, 65535,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
            0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9,
        ]
        for x in values:
            self.assertEqual(h.opaque_zero_u64(x), 0)

    def test_string_and_constant_stream_encryption_roundtrips(self):
        secret = b"ANTIREA-SECRET-CONSTANT-TABLE-V2"
        cipher = h.encrypt_bytes(secret, 0xCAFEBABE)
        self.assertNotEqual(cipher, secret)
        self.assertEqual(h.decrypt_bytes(cipher, 0xCAFEBABE), secret)
        c_code = h.emit_encrypted_constant_pool("test_pool", secret, 0xCAFEBABE)
        self.assertIn("test_pool_enc", c_code)
        self.assertIn("test_pool_decrypt", c_code)

    def test_dynamic_api_symbol_hash_and_multi_vm_seeds(self):
        h1 = h.api_symbol_hash("IsDebuggerPresent")
        h2 = h.api_symbol_hash("NtQueryInformationProcess")
        self.assertNotEqual(h1, h2)
        seeds = h.derive_multi_vm_seeds(99, 4)
        self.assertEqual(len(set(seeds)), 4)

    def test_specialize_runtime_and_vendor_projects_include_all_hardening_layers(self):
        params = d.parameters(7, {"F_RR_ADD", "OP_RET"})
        self.assertIn("hardening", params)
        prelude = h.emit_runtime_hardening_helpers(params["hardening"])
        self.assertIn("antirea_env_and_tamper_guard", prelude)
        self.assertIn("antirea_honeypot_feistel", prelude)
        self.assertIn("antirea_mba_add", prelude)
        self.assertIn("antirea_opaque_zero", prelude)
        self.assertIn("__readgsqword(0x60ul)", prelude)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "app.exe"
            exe.write_bytes(_sample_pe64())
            service = Service.ensure_default_config(root / "protectors.json", workspace_root=root)
            for provider in ("vmprotect", "themida", "code_virtualizer"):
                gen = service.generate_project(provider, exe, defense_level="max_vm", min_speed_percent=80)
                self.assertEqual(set(gen["hardening_features"]), set(h.HARDENING_LAYERS))
                xml = Path(gen["project_path"]).read_text(encoding="utf-8")
                if provider == "vmprotect":
                    self.assertIn('DebuggerDetection="UserMode+KernelMode"', xml)
                    self.assertIn('MemoryProtection="true"', xml)
                    self.assertIn('ImportProtection="true"', xml)
                    self.assertIn('PackOutput="true"', xml)
                else:
                    self.assertIn('AntiDebug="Ultra"', xml)
                    self.assertIn('AntiFrida="true"', xml)
                    self.assertIn('AntiTamperMemoryGuard="true"', xml)
                    self.assertIn('AntiDumpHeaderErase="true"', xml)
                    self.assertIn('ImportProtectionIAT="true"', xml)
                    self.assertIn('MultiVM="true"', xml)
                    self.assertIn('AntiLLMHoneypot="true"', xml)
                    self.assertIn("Fish64_Extreme", xml)
                    self.assertIn("Dolphin64_Black", xml)
                    self.assertIn("Eagle64_Red", xml)


if __name__ == "__main__":
    unittest.main()
