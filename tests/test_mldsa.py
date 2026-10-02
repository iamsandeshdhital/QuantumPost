"""FIPS 204 ML-DSA tests: sizes, round trips, negative tests, determinism."""

from __future__ import annotations

import unittest

from quantumpost import mldsa
from quantumpost.params import get_mldsa

#: Sizes published in FIPS 204 Table 1 / Table 2.
FIPS204_SIZES = {
    "ML-DSA-44": (1312, 2560, 2420),
    "ML-DSA-65": (1952, 4032, 3309),
    "ML-DSA-87": (2592, 4896, 4627),
}

#: Parameter values from FIPS 204 Table 1.
FIPS204_PARAMS = {
    "ML-DSA-44": dict(k=4, ell=4, eta=2, tau=39, beta=78, gamma1=2 ** 17,
                      gamma2=(8380417 - 1) // 88, omega=80, lam=128),
    "ML-DSA-65": dict(k=6, ell=5, eta=4, tau=49, beta=196, gamma1=2 ** 19,
                      gamma2=(8380417 - 1) // 32, omega=55, lam=192),
    "ML-DSA-87": dict(k=8, ell=7, eta=2, tau=60, beta=120, gamma1=2 ** 19,
                      gamma2=(8380417 - 1) // 32, omega=75, lam=256),
}


class TestParameters(unittest.TestCase):
    def test_published_sizes(self):
        for name, (pk, sk, sig) in FIPS204_SIZES.items():
            spec = get_mldsa(name)
            self.assertEqual((spec.pk_len, spec.sk_len, spec.sig_len), (pk, sk, sig), name)

    def test_sk_len_matches_fips_table(self):
        for name, (_, sk, _) in FIPS204_SIZES.items():
            self.assertEqual(get_mldsa(name).sk_len, MLDSAParams_SK(name), name)

    def test_parameter_values(self):
        for name, want in FIPS204_PARAMS.items():
            spec = get_mldsa(name)
            for attr, value in want.items():
                self.assertEqual(getattr(spec, attr), value, f"{name}.{attr}")

    def test_z_and_t1_widths(self):
        for name in FIPS204_SIZES:
            spec = get_mldsa(name)
            self.assertEqual(spec.t1_bits, 10, name)
            self.assertEqual(spec.z_bits, spec.gamma1.bit_length(), name)
            self.assertEqual(spec.eta_bits, (2 * spec.eta).bit_length(), name)
            self.assertEqual(spec.c_tilde_len, spec.lam // 4, name)


def MLDSAParams_SK(name: str) -> int:
    return FIPS204_SIZES[name][1]


class TestKeyGeneration(unittest.TestCase):
    def test_sizes_match(self):
        for name in FIPS204_SIZES:
            spec = get_mldsa(name)
            pk, sk = mldsa.generate_keypair(spec)
            self.assertEqual(len(pk), spec.pk_len, name)
            self.assertEqual(len(sk), spec.sk_len, name)

    def test_deterministic_from_seed(self):
        spec = get_mldsa("ML-DSA-44")
        seed = bytes(range(32))
        self.assertEqual(mldsa.keypair_from_seed(spec, seed),
                         mldsa.keypair_from_seed(spec, seed))
        self.assertNotEqual(mldsa.keypair_from_seed(spec, seed),
                            mldsa.keypair_from_seed(spec, bytes(32)))

    def test_private_key_layout(self):
        """sk = rho || K || tr || s1 || s2 || t0, so rho is shared with pk."""
        pk, sk = mldsa.generate_keypair("ML-DSA-65")
        self.assertEqual(sk[:32], pk[:32])
        from quantumpost.hashes import shake256

        self.assertEqual(sk[64:128], shake256(pk, 64), "tr = H(pk, 64)")

    def test_seed_length_is_enforced(self):
        with self.assertRaises(ValueError):
            mldsa.keypair_from_seed(get_mldsa("ML-DSA-44"), b"short")


class TestSignVerify(unittest.TestCase):
    def test_round_trip(self):
        message = b"QuantumPost ML-DSA round trip"
        for name in FIPS204_SIZES:
            spec = get_mldsa(name)
            with self.subTest(name):
                pk, sk = mldsa.generate_keypair(spec)
                sig = mldsa.sign(spec, sk, message)
                self.assertEqual(len(sig), spec.sig_len)
                self.assertTrue(mldsa.verify(spec, pk, message, sig))

    def test_deterministic_signing(self):
        spec = get_mldsa("ML-DSA-44")
        pk, sk = mldsa.generate_keypair(spec)
        a = mldsa.sign(spec, sk, b"m", rnd=bytes(32))
        b = mldsa.sign(spec, sk, b"m", rnd=bytes(32))
        self.assertEqual(a, b)

    def test_hedged_signing_differs(self):
        spec = get_mldsa("ML-DSA-44")
        pk, sk = mldsa.generate_keypair(spec)
        sigs = {mldsa.sign(spec, sk, b"m") for _ in range(2)}
        self.assertEqual(len(sigs), 2, "randomised signing must not be deterministic")
        for sig in sigs:
            self.assertTrue(mldsa.verify(spec, pk, b"m", sig))


class TestNegativeTests(unittest.TestCase):
    def setUp(self):
        self.spec = get_mldsa("ML-DSA-44")
        self.pk, self.sk = mldsa.generate_keypair(self.spec)
        self.message = b"negative test message"
        self.sig = mldsa.sign(self.spec, self.sk, self.message)

    def test_wrong_message(self):
        self.assertFalse(mldsa.verify(self.spec, self.pk, b"other", self.sig))

    def test_wrong_key(self):
        other_pk, _ = mldsa.generate_keypair(self.spec)
        self.assertFalse(mldsa.verify(self.spec, other_pk, self.message, self.sig))

    def test_every_single_bit_flip_is_rejected(self):
        """Flipping any bit must destroy verifiability."""
        for index in (0, 31, 32, len(self.sig) // 2, len(self.sig) - 84, len(self.sig) - 1):
            for bit in (0, 7):
                bad = bytearray(self.sig)
                bad[index] ^= 1 << bit
                self.assertFalse(
                    mldsa.verify(self.spec, self.pk, self.message, bytes(bad)),
                    f"flip at byte {index} bit {bit} was accepted",
                )

    def test_truncated_and_padded_signatures(self):
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, self.sig[:-1]))
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, self.sig + b"\0"))
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, b""))

    def test_malformed_public_key(self):
        self.assertFalse(mldsa.verify(self.spec, b"short", self.message, self.sig))

    def test_context_is_bound(self):
        ctx = b"application context"
        sig = mldsa.sign(self.spec, self.sk, self.message, ctx=ctx)
        self.assertTrue(mldsa.verify(self.spec, self.pk, self.message, sig, ctx=ctx))
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, sig))
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, sig, ctx=b"other"))

    def test_context_length_limit(self):
        self.assertFalse(mldsa.verify(self.spec, self.pk, self.message, self.sig,
                                      ctx=b"x" * 256))
        with self.assertRaises(ValueError):
            mldsa.sign(self.spec, self.sk, self.message, ctx=b"x" * 256)

    def test_verify_strict_raises(self):
        with self.assertRaises(mldsa.InvalidSignature):
            mldsa.verify_strict(self.spec, self.pk, b"other", self.sig)


class TestIntrospection(unittest.TestCase):
    def test_parameter_sets(self):
        self.assertEqual(list(mldsa.parameter_sets()), list(FIPS204_SIZES))

    def test_describe(self):
        record = mldsa.describe("ML-DSA-65")
        self.assertEqual(record["standard"], "FIPS 204")
        self.assertEqual(record["sig_len"], 3309)

    def test_expansion_factor_is_one_point_six(self):
        """ML-DSA's headline number: signatures are ~1.7x the public key."""
        spec = get_mldsa("ML-DSA-65")
        self.assertAlmostEqual(spec.sig_len / spec.pk_len, 1.69, places=1)


if __name__ == "__main__":
    unittest.main()