"""Tests for the negacyclic NTT and the bit/byte packing helpers."""

from __future__ import annotations

import random
import unittest

from quantumpost import ntt
from quantumpost.ntt import NegacyclicNTT, centered, schoolbook_mul
from quantumpost.utils import bitpack, bitunpack, bytedecode, bytepack

Q_MLKEM = 3329
Q_MLDSA = 8380417


class TestNTTAgainstOracle(unittest.TestCase):
    """Every fast path must agree with the O(n^2) schoolbook multiplication."""

    def _polys(self, q, count=256, seed=1):
        rng = random.Random(seed)
        return [[rng.randrange(q) for _ in range(count)] for _ in range(4)]

    def test_mldsa_roundtrip_and_product(self):
        ntt_obj = NegacyclicNTT(Q_MLDSA, 256)
        self.assertTrue(ntt_obj.supported)
        a, b, _, _ = self._polys(Q_MLDSA)
        self.assertEqual(ntt_obj.inverse(ntt_obj.forward(a)), a)
        self.assertEqual(
            ntt_obj.inverse([x * y % Q_MLDSA for x, y in
                             zip(ntt_obj.forward(a), ntt_obj.forward(b))]),
            schoolbook_mul(a, b, Q_MLDSA),
        )

    def test_mlkem_domain_multiplication(self):
        """FIPS 203 uses a degree-128 NTT because 512 does not divide q-1."""
        a, b, _, _ = self._polys(Q_MLKEM, count=256, seed=7)
        got = ntt.mlkem_mul_domain(a, b)
        self.assertEqual(len(got), 256)
        self.assertTrue(all(0 <= c < Q_MLKEM for c in got))
        self.assertEqual(got, ntt.mlkem_mul_domain(a, b), "domain product is deterministic")

    def test_centered(self):
        self.assertEqual(centered(0, 7), 0)
        self.assertEqual(centered(3, 7), 3)
        self.assertEqual(centered(4, 7), -3)
        self.assertEqual(centered(-4, 7), 3)


class TestBytePack(unittest.TestCase):
    def test_roundtrip(self):
        for q, k in ((Q_MLKEM, 2), (Q_MLKEM, 3), (Q_MLDSA, 4)):
            rng = random.Random(k)
            coeffs = [rng.randrange(1 << k) for _ in range(256)]
            packed = bytepack(coeffs, k)
            self.assertEqual(bytedecode(packed, k, 256, q), coeffs, f"q={q} k={k}")
            self.assertEqual(len(packed), 32 * k)

    def test_length_is_stable(self):
        for k in (1, 2, 3, 4, 6, 12):
            self.assertEqual(len(bytepack([0] * 256, k)), 256 * k // 8)

    def test_rejects_short_input(self):
        with self.assertRaises(ValueError):
            bytedecode(b"\x00" * 8, 12, 256, Q_MLDSA)


class TestBitPack(unittest.TestCase):
    def test_roundtrip(self):
        for bits in (1, 3, 4, 6, 10, 13, 18, 20):
            rng = random.Random(bits)
            coeffs = [rng.randrange(1 << bits) for _ in range(256)]
            self.assertEqual(bitunpack(bitpack(bits, coeffs), bits, 256, 0), coeffs)

    def test_signed_reflection(self):
        """``alpha`` shifts each limb, wrapping inside the w bit field."""
        raw = bitunpack(bytes(32), 8, 32, 0)
        shifted = bitunpack(bytes(32), 8, 32, 1)
        self.assertEqual(raw, [0] * 32)
        self.assertEqual(shifted, [(-1) % 256] * 32)


if __name__ == "__main__":
    unittest.main()