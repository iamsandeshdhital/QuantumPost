"""Tests for the hybrid combiner, the CLI and the deterministic RNG hooks."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from quantumpost import cli, mldsa, mlkem, utils
from quantumpost.combine import (
    classical_combine,
    hybrid_decapsulate,
    hybrid_encapsulate,
    sign_with_hybrid,
    verify_with_hybrid,
)
from quantumpost.params import get_mldsa, get_mlkem


class TestCombiner(unittest.TestCase):
    def test_deterministic_and_order_sensitive(self):
        a, b = b"\x01" * 32, b"\x02" * 32
        self.assertEqual(classical_combine(a, b), classical_combine(a, b))
        self.assertNotEqual(classical_combine(a, b), classical_combine(b, a))

    def test_output_is_32_bytes(self):
        self.assertEqual(len(classical_combine(b"x", b"y")), 32)

    def test_length_extension_is_bound(self):
        """A short classical secret must not be padded into a longer one."""
        short = classical_combine(b"a" * 32, b"b" * 32)
        long = classical_combine(b"a" * 32, b"b" * 33)
        self.assertNotEqual(short, long)

    def test_rejects_empty_inputs(self):
        with self.assertRaises(ValueError):
            classical_combine(b"", b"y")
        with self.assertRaises(ValueError):
            classical_combine(b"x", b"")

    def test_changing_either_input_changes_the_key(self):
        base = classical_combine(b"\x01" * 32, b"\x02" * 32)
        self.assertNotEqual(base, classical_combine(b"\x03" * 32, b"\x02" * 32))
        self.assertNotEqual(base, classical_combine(b"\x01" * 32, b"\x03" * 32))


class TestHybridKEM(unittest.TestCase):
    def test_round_trip(self):
        spec = get_mlkem("ML-KEM-768")
        ek, dk = mlkem.generate_keypair(spec)
        classical = os.urandom(32)
        key_a, ct = hybrid_encapsulate(spec, ek, classical)
        key_b = hybrid_decapsulate(spec, dk, ct, classical)
        self.assertEqual(key_a, key_b)
        self.assertEqual(len(key_a), 32)

    def test_mismatched_classical_secret_fails(self):
        spec = get_mlkem("ML-KEM-768")
        ek, dk = mlkem.generate_keypair(spec)
        _, ct = hybrid_encapsulate(spec, ek, os.urandom(32))
        other = hybrid_decapsulate(spec, dk, ct, os.urandom(32))
        self.assertNotEqual(other, hybrid_decapsulate(spec, dk, ct, b"\x00" * 32))


class TestHybridSignatures(unittest.TestCase):
    def test_round_trip(self):
        spec = get_mldsa("ML-DSA-65")
        pk, sk = mldsa.generate_keypair(spec)
        pub = b"ed25519 public key"
        sig = sign_with_hybrid(spec, sk, b"payload", pub)
        self.assertTrue(verify_with_hybrid(spec, pk, b"payload", pub, sig))
        self.assertFalse(verify_with_hybrid(spec, pk, b"payload", b"other pub", sig))
        self.assertFalse(verify_with_hybrid(spec, pk, b"other payload", pub, sig))

    def test_length_bound_on_the_classical_value(self):
        """The bound prevents moving bytes between the key and the message."""
        spec = get_mldsa("ML-DSA-65")
        pk, sk = mldsa.generate_keypair(spec)
        sig = sign_with_hybrid(spec, sk, b"m", b"ab")
        self.assertTrue(verify_with_hybrid(spec, pk, b"m", b"ab", sig))
        self.assertFalse(verify_with_hybrid(spec, pk, b"m", b"a", b"b" + sig[1:]))


class TestDeterministicRandom(unittest.TestCase):
    def test_use_random_is_scoped(self):
        with utils.use_random(utils.DeterministicRandom(b"\x07" * 32)):
            first = utils.random_bytes(16)
            second = utils.random_bytes(16)
        with utils.use_random(utils.DeterministicRandom(b"\x07" * 32)):
            self.assertEqual(utils.random_bytes(16), first)
            self.assertEqual(utils.random_bytes(16), second)
        self.assertNotEqual(first, second)

    def test_restores_previous_source(self):
        original = utils.get_random()
        with utils.use_random(utils.DeterministicRandom(b"\x01")):
            pass
        self.assertIs(utils.get_random(), original)

    def test_deterministic_keygen_uses_the_hook(self):
        with utils.use_random(utils.DeterministicRandom(b"\x02" * 32)):
            ek1, dk1 = mlkem.generate_keypair("ML-KEM-512")
            ek2, dk2 = mlkem.generate_keypair("ML-KEM-512")
        with utils.use_random(utils.DeterministicRandom(b"\x02" * 32)):
            ek3, dk3 = mlkem.generate_keypair("ML-KEM-512")
        self.assertEqual((ek1, dk1), (ek3, dk3))
        self.assertNotEqual((ek1, dk1), (ek2, dk2))


class TestCLI(unittest.TestCase):
    def test_list(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["list"]), 0)
        self.assertIn("ML-KEM-768", buf.getvalue())
        self.assertIn("ML-DSA-65", buf.getvalue())

    def test_list_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(["list", "--json"])
        payload = json.loads(buf.getvalue())
        self.assertEqual(len(payload["kem"]), 3)
        self.assertEqual(len(payload["signature"]), 3)
        self.assertEqual(payload["kem"][1]["name"], "ML-KEM-768")

    def test_info(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(["info", "ML-DSA-65"])
        record = json.loads(buf.getvalue())
        self.assertEqual(record["standard"], "FIPS 204")
        self.assertEqual(record["sig_len"], 3309)

    def test_self_test(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["self-test"]), 0)
        self.assertIn("all self tests passed", buf.getvalue())

    def test_kem_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            ek = os.path.join(tmp, "ek.bin")
            dk = os.path.join(tmp, "dk.bin")
            ct = os.path.join(tmp, "ct.bin")
            ss = os.path.join(tmp, "ss.bin")
            ss2 = os.path.join(tmp, "ss2.bin")
            with redirect_stderr(io.StringIO()):
                cli.main(["kem-keygen", "-a", "ML-KEM-512", "--ek", ek, "--dk", dk])
            cli.main(["kem-encaps", "-a", "ML-KEM-512", "--ek", ek, "--ct", ct, "--ss", ss])
            cli.main(["kem-decaps", "-a", "ML-KEM-512", "--dk", dk, "--ct", ct, "--out", ss2])
            with open(ss, "rb") as a, open(ss2, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_signature_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            pk = os.path.join(tmp, "pk.bin")
            sk = os.path.join(tmp, "sk.bin")
            msg = os.path.join(tmp, "msg.bin")
            sig = os.path.join(tmp, "sig.bin")
            with open(msg, "wb") as handle:
                handle.write(b"cli round trip")
            cli.main(["sig-keygen", "-a", "ML-DSA-44", "--pk", pk, "--sk", sk])
            cli.main(["sig-sign", "-a", "ML-DSA-44", "--sk", sk, "-m", msg, "--out", sig])
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(
                    cli.main(["sig-verify", "-a", "ML-DSA-44", "--pk", pk,
                              "-m", msg, "--signature", sig]), 0)
            self.assertIn("valid", buf.getvalue())

    def test_verify_returns_one_on_bad_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            pk = os.path.join(tmp, "pk.bin")
            sk = os.path.join(tmp, "sk.bin")
            msg = os.path.join(tmp, "msg.bin")
            sig = os.path.join(tmp, "sig.bin")
            with open(msg, "wb") as handle:
                handle.write(b"payload")
            cli.main(["sig-keygen", "-a", "ML-DSA-44", "--pk", pk, "--sk", sk])
            cli.main(["sig-sign", "-a", "ML-DSA-44", "--sk", sk, "-m", msg, "--out", sig])
            with open(sig, "r+b") as handle:
                handle.seek(0)
                handle.write(b"\xff")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    cli.main(["sig-verify", "-a", "ML-DSA-44", "--pk", pk,
                              "-m", msg, "--signature", sig]), 1)

    def test_hex_seed_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for run in ("a", "b"):
                ek = os.path.join(tmp, f"ek{run}.bin")
                cli.main(["kem-keygen", "-a", "ML-KEM-512", "--seed", "00" * 64,
                          "--ek", ek, "--dk", os.path.join(tmp, "dk.bin")])
                with open(ek, "rb") as handle:
                    outs.append(handle.read())
            self.assertEqual(outs[0], outs[1])

    def test_bad_hex_exits(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["kem-keygen", "--seed", "zzzz", "--ek", "-", "--dk", "-"])


if __name__ == "__main__":
    unittest.main()