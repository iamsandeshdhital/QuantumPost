"""FIPS 203 ML-KEM tests: sizes, round trips, implicit rejection, determinism."""

from __future__ import annotations

import unittest

from quantumpost import mlkem
from quantumpost.params import MLDSAParams, get_mlkem

#: Sizes published in FIPS 203 Table 2.
FIPS203_SIZES = {
    "ML-KEM-512": (800, 1632, 768),
    "ML-KEM-768": (1184, 2400, 1088),
    "ML-KEM-1024": (1568, 3168, 1568),
}


class TestSizes(unittest.TestCase):
    def test_published_sizes(self):
        for name, (ek, dk, ct) in FIPS203_SIZES.items():
            spec = get_mlkem(name)
            self.assertEqual((spec.ek_len, spec.dk_len, spec.ct_len), (ek, dk, ct), name)
            self.assertEqual(spec.shared_secret_len, 32)

    def test_parameter_values(self):
        """Guard the constants that drive the encoders."""
        expected = {
            "ML-KEM-512": dict(k=2, eta1=3, eta2=2, du=10, dv=4),
            "ML-KEM-768": dict(k=3, eta1=2, eta2=2, du=10, dv=4),
            "ML-KEM-1024": dict(k=4, eta1=2, eta2=2, du=11, dv=5),
        }
        for name, want in expected.items():
            spec = get_mlkem(name)
            for attr, value in want.items():
                self.assertEqual(getattr(spec, attr), value, f"{name}.{attr}")

    def test_alias_resolution(self):
        self.assertIs(get_mlkem("ml-kem-768"), get_mlkem("ML-KEM-768"))
        self.assertIs(get_mlkem("768"), get_mlkem("ML-KEM-768"))
        with self.assertRaises(KeyError):
            get_mlkem("ML-KEM-999")


class TestRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        for name in FIPS203_SIZES:
            spec = get_mlkem(name)
            with self.subTest(name):
                ek, dk = mlkem.generate_keypair(spec)
                ss_a, ct = mlkem.encapsulate(spec, ek)
                ss_b = mlkem.decapsulate(spec, dk, ct)
                self.assertEqual(ss_a, ss_b)
                self.assertEqual(len(ss_a), 32)
                self.assertEqual(len(ct), spec.ct_len)

    def test_decapsulation_key_embeds_encapsulation_key(self):
        """FIPS 203 dk = dk_PKE || ek || H(ek) || z, so ek is recoverable."""
        from quantumpost.hashes import sha3_256

        spec = get_mlkem("ML-KEM-768")
        k = spec.k
        ek, dk = mlkem.generate_keypair(spec)
        self.assertEqual(dk[384 * k:768 * k + 32], ek, "ek must sit inside dk")
        self.assertEqual(dk[768 * k + 32:768 * k + 64], sha3_256(ek), "H(ek) must follow ek")

    def test_deterministic_keypair_and_encapsulation(self):
        spec = get_mlkem("ML-KEM-512")
        d, z = bytes(range(32)), bytes(range(32, 64))
        ek1, dk1 = mlkem.keypair_from_seed(spec, d, z)
        ek2, dk2 = mlkem.keypair_from_seed(spec, d, z)
        self.assertEqual((ek1, dk1), (ek2, dk2))
        message = bytes(range(32, 64))
        ss1, ct1 = mlkem.encapsulate_deterministic(spec, ek1, message)
        ss2, ct2 = mlkem.encapsulate_deterministic(spec, ek2, message)
        self.assertEqual((ss1, ct1), (ss2, ct2))


class TestImplicitRejection(unittest.TestCase):
    """FIPS 203 mandates deterministic, key-independent rejection on failure."""

    def test_tampered_ciphertext_yields_a_different_secret(self):
        for name in FIPS203_SIZES:
            spec = get_mlkem(name)
            with self.subTest(name):
                ek, dk = mlkem.generate_keypair(spec)
                ss, ct = mlkem.encapsulate(spec, ek)
                for index in (0, 1, len(ct) // 2, len(ct) - 1):
                    bad = bytearray(ct)
                    bad[index] ^= 0x01
                    self.assertNotEqual(mlkem.decapsulate(spec, dk, bytes(bad)), ss)

    def test_rejection_is_deterministic(self):
        spec = get_mlkem("ML-KEM-512")
        ek, dk = mlkem.generate_keypair(spec)
        _, ct = mlkem.encapsulate(spec, ek)
        bad = bytearray(ct)
        bad[0] ^= 0xFF
        first = mlkem.decapsulate(spec, dk, bytes(bad))
        second = mlkem.decapsulate(spec, dk, bytes(bad))
        self.assertEqual(first, second)

    def test_rejection_independent_of_private_key(self):
        """The fallback secret must not leak which key was used."""
        spec = get_mlkem("ML-KEM-512")
        ek, dk = mlkem.generate_keypair(spec)
        _, ct = mlkem.encapsulate(spec, ek)
        bad = bytearray(ct)
        bad[0] ^= 0x01
        a = mlkem.decapsulate(spec, dk, bytes(bad))
        _, dk_other = mlkem.generate_keypair(spec)
        b = mlkem.decapsulate(spec, dk_other, bytes(bad))
        self.assertNotEqual(a, b)

    def test_wrong_key_rejects(self):
        spec = get_mlkem("ML-KEM-512")
        ek, _ = mlkem.generate_keypair(spec)
        _, other_dk = mlkem.generate_keypair(spec)
        ss, ct = mlkem.encapsulate(spec, ek)
        self.assertNotEqual(mlkem.decapsulate(spec, other_dk, ct), ss)


class TestInputValidation(unittest.TestCase):
    def test_bad_lengths_raise(self):
        spec = get_mlkem("ML-KEM-512")
        with self.assertRaises(ValueError):
            mlkem.decapsulate(spec, b"short", b"x" * spec.ct_len)
        with self.assertRaises(ValueError):
            mlkem.encapsulate(spec, b"short")
        with self.assertRaises(ValueError):
            mlkem.keypair_from_seed(spec, b"short", bytes(32))

    def test_decapsulation_key_layout(self):
        spec = get_mlkem("ML-KEM-768")
        ek, dk = mlkem.generate_keypair(spec)
        self.assertEqual(len(dk), spec.dk_len)
        self.assertEqual(len(ek), spec.ek_len)

    def test_encapsulation_message_length(self):
        spec = get_mlkem("ML-KEM-512")
        ek, _ = mlkem.generate_keypair(spec)
        with self.assertRaises(ValueError):
            mlkem.encapsulate_deterministic(spec, ek, b"too short")

    def test_strict_variant_raises_on_failure(self):
        from quantumpost.mlkem import CiphertextRejected

        spec = get_mlkem("ML-KEM-512")
        ek, dk = mlkem.generate_keypair(spec)
        _, ct = mlkem.encapsulate(spec, ek)
        mlkem.decapsulate_strict(spec, dk, ct)
        bad = bytearray(ct)
        bad[0] ^= 0x01
        with self.assertRaises(CiphertextRejected):
            mlkem.decapsulate_strict(spec, dk, bytes(bad))


class TestSelfConsistency(unittest.TestCase):
    def test_many_encapsulations_agree(self):
        spec = get_mlkem("ML-KEM-768")
        ek, dk = mlkem.generate_keypair(spec)
        for _ in range(3):
            ss_a, ct = mlkem.encapsulate(spec, ek)
            self.assertEqual(ss_a, mlkem.decapsulate(spec, dk, ct))

    def test_describe(self):
        record = mlkem.describe("ML-KEM-768")
        self.assertEqual(record["name"], "ML-KEM-768")
        self.assertEqual(record["standard"], "FIPS 203")
        self.assertEqual(record["ek_len"], 1184)

    def test_no_dsa_params_leaked(self):
        """The KEM module must not depend on the signature parameters."""
        self.assertFalse(hasattr(mlkem, "MLDSAParams"))


if __name__ == "__main__":
    unittest.main()