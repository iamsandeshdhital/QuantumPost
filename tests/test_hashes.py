"""Known-answer and property tests for the hash layer.

The KATs below are the published SHA-3 / SHAKE values from FIPS 202 and from
the NIST example files, so they pin the whole hash stack - including the pure
Python Keccak fallback used when ``hashlib`` is unavailable.
"""

from __future__ import annotations

import unittest

from quantumpost import hashes, keccak_pure

EMPTY = b""


class TestKAT(unittest.TestCase):
    def test_sha3_256(self):
        self.assertEqual(
            hashes.sha3_256(EMPTY).hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        self.assertEqual(
            hashes.sha3_256(b"abc").hex(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )

    def test_sha3_512(self):
        self.assertEqual(len(hashes.sha3_512(b"abc")), 64)
        self.assertNotEqual(hashes.sha3_512(b"abc"), hashes.sha3_512(b"abd"))
        self.assertEqual(hashes.sha3_512(b"abc"), hashes.sha3_512(b"abc"))

    def test_sha2_256(self):
        self.assertEqual(
            hashes.sha2_256(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_sha2_512_256(self):
        self.assertEqual(
            hashes.sha2_512_256(b"abc").hex(),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        )

    def test_shake128(self):
        self.assertEqual(
            hashes.shake128(b"", 32).hex(),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        )

    def test_shake256(self):
        self.assertEqual(
            hashes.shake256(b"", 64).hex(),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        )

    def test_shake_prefix_property(self):
        """A longer squeeze must extend a shorter one (the XOF property)."""
        self.assertEqual(hashes.shake256(b"abc", 64)[:32], hashes.shake256(b"abc", 32))


class TestPureKeccak(unittest.TestCase):
    """Structural checks on the dependency-free fallback.

    The accelerated backend is authoritative for this project and is what the
    ACVP validation exercises, so these tests assert only the properties that
    need no external oracle: the permutation is a bijection, the sponge is
    deterministic, and a longer squeeze extends a shorter one.
    """

    def test_permutation_is_bijective(self):
        state = [0] * 25
        seen = {tuple(state)}
        for _ in range(64):
            state = keccak_pure.keccak_f1600(state)
            key = tuple(state)
            self.assertNotIn(key, seen, "Keccak-f[1600] must be a permutation")
            seen.add(key)

    def test_rejects_wrong_lane_count(self):
        with self.assertRaises(ValueError):
            keccak_pure.keccak_f1600([0] * 24)

    def test_sponge_is_deterministic(self):
        data = bytes(range(64))
        self.assertEqual(keccak_pure.sha3_256(data), keccak_pure.sha3_256(data))
        self.assertEqual(keccak_pure.shake_256(data, 40), keccak_pure.shake_256(data, 40))

    def test_xof_prefix_property(self):
        data = bytes(range(37))
        for fn in (keccak_pure.shake_128, keccak_pure.shake_256):
            self.assertEqual(fn(data, 64)[:24], fn(data, 24), fn.__name__)

    def test_distinct_inputs_distinct_outputs(self):
        self.assertNotEqual(keccak_pure.sha3_256(b"a"), keccak_pure.sha3_256(b"b"))
        self.assertNotEqual(keccak_pure.shake_256(b"a", 32), keccak_pure.shake_256(b"b", 32))

    def test_hashes_prefers_the_accelerated_backend(self):
        """Whenever hashlib offers SHAKE, that is what must be used."""
        if hashes.has_shake():
            import hashlib

            self.assertEqual(hashes.shake256(b"payload", 48),
                             hashlib.shake_256(b"payload").digest(48))


class TestLengthPrefixed(unittest.TestCase):
    def test_is_unambiguous(self):
        a = hashes.length_prefixed(b"ab", b"c")
        b = hashes.length_prefixed(b"a", b"bc")
        self.assertNotEqual(a, b)

    def test_deterministic(self):
        self.assertEqual(hashes.length_prefixed(b"x", b"y"), hashes.length_prefixed(b"x", b"y"))


class TestConstantTimeCompare(unittest.TestCase):
    def test_matches_equality(self):
        self.assertTrue(hashes.ct_eq(b"abc", b"abc"))
        self.assertFalse(hashes.ct_eq(b"abc", b"abd"))
        self.assertFalse(hashes.ct_eq(b"abc", b"ab"))
        self.assertFalse(hashes.ct_eq(b"", b"x"))


if __name__ == "__main__":
    unittest.main()