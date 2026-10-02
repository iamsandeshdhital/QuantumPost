"""Byte-level serialisation helpers shared by ML-KEM, ML-DSA and SPHINCS+.

Cryptographic specifications are written in terms of *bit* strings; Python
exposes *byte* strings.  Every conversion between the two lives here, is
covered by unit tests, and follows the little-endian packing convention used
by FIPS 203/204:

* :func:`bytepack` / :func:`bytedecode` - FIPS 203 (K-PKE) 12-bit (and generic)
  packing of polynomial coefficients.
* :func:`bitpack` / :func:`bitunpack` - FIPS 204 BitPack/BitUnpack for
  ``w``-bit coefficients.

The module also owns every piece of randomness policy in the library: a single
injectable :class:`RandomSource` is threaded through all algorithms so that
deterministic known-answer tests can be produced reproducibly.
"""

from __future__ import annotations

import secrets
from math import gcd
from typing import Callable, Protocol, Sequence

__all__ = [
    "RandomSource",
    "SystemRandom",
    "DeterministicRandom",
    "get_random",
    "set_random",
    "use_random",
    "random_bytes",
    "bytes_to_int",
    "int_to_bytes",
    "bytepack",
    "bytedecode",
    "bitpack",
    "bitunpack",
    "coeffs_to_bytes",
    "bytes_to_coeffs",
]


# --------------------------------------------------------------------------- #
# Randomness                                                                   #
# --------------------------------------------------------------------------- #
class RandomSource(Protocol):
    """Minimal interface required from a random byte source."""

    def random_bytes(self, count: int) -> bytes:  # pragma: no cover - protocol
        ...


class SystemRandom:
    """OS CSPRNG (``secrets``); the only source permitted in production."""

    __slots__ = ()

    def random_bytes(self, count: int) -> bytes:
        if count < 0:
            raise ValueError("count must be non-negative")
        return secrets.token_bytes(count)


class DeterministicRandom:
    """Reproducible XOF-based source, for tests and reproducible demos.

    Never use outside tests: it is a public function of its seed.
    """

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        self._seed = bytes(seed)
        self._counter = 0

    def random_bytes(self, count: int) -> bytes:
        from quantumpost.hashes import shake256

        out = shake256(
            b"QuantumPost/deterministic-drbg/v1" + len(self._seed).to_bytes(2, "big")
            + self._seed + self._counter.to_bytes(8, "big"),
            count,
        )
        self._counter += 1
        return out


_random_source: RandomSource = SystemRandom()


def get_random() -> RandomSource:
    """Return the currently installed global random source."""
    return _random_source


def set_random(source: RandomSource) -> RandomSource:
    """Install ``source`` as the global random source; returns the previous one."""
    global _random_source
    if not hasattr(source, "random_bytes"):
        raise TypeError("random source must provide random_bytes(count)")
    previous = _random_source
    _random_source = source
    return previous


class use_random:
    """Context manager that temporarily installs a random source."""

    __slots__ = ("_source", "_previous")

    def __init__(self, source: RandomSource) -> None:
        self._source = source
        self._previous: RandomSource | None = None

    def __enter__(self) -> RandomSource:
        self._previous = set_random(self._source)
        return self._source

    def __exit__(self, *exc_info: object) -> None:
        if self._previous is not None:
            set_random(self._previous)
            self._previous = None


def random_bytes(count: int) -> bytes:
    """Draw ``count`` bytes from the installed global random source."""
    return _random_source.random_bytes(count)


# --------------------------------------------------------------------------- #
# Scalars                                                                     #
# --------------------------------------------------------------------------- #
def bytes_to_int(data: bytes) -> int:
    """Big-endian integer decode."""
    return int.from_bytes(bytes(data), "big")


def int_to_bytes(value: int, length: int) -> bytes:
    """Big-endian integer encode."""
    if value < 0:
        raise ValueError("negative values are not encodable")
    if value.bit_length() > 8 * length:
        raise ValueError("integer does not fit in the requested length")
    return value.to_bytes(length, "big")


# --------------------------------------------------------------------------- #
# FIPS 203 packing                                                            #
# --------------------------------------------------------------------------- #
def bytepack(coeffs: Sequence[int], d: int) -> bytes:
    """FIPS 203 :math:`\\operatorname{BytePack}_d`.

    Coefficients are packed little endian, ``d`` bits each, with no padding
    between them - so ``d = 1`` yields a bit string and ``d = 12`` yields three
    bytes per two coefficients.
    """
    if d < 1:
        raise ValueError("d must be positive")
    group = 8 // gcd(d, 8)
    if group * d % 8 == 0:
        # Whole bytes: pack `group` coefficients per little-endian block.
        width = group * d // 8
        out = bytearray()
        for i in range(0, len(coeffs), group):
            packed = 0
            for j in range(group):
                if i + j < len(coeffs):
                    packed |= (coeffs[i + j] & ((1 << d) - 1)) << (d * j)
            out += packed.to_bytes(width, "little")
        return bytes(out)
    # Generic bit-level packing.
    bits: list[int] = []
    for coeff in coeffs:
        bits.extend((coeff >> i) & 1 for i in range(d))
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i + 8]):
            byte |= bit << j
        out.append(byte)
    return bytes(out)


def bytedecode(data: bytes, d: int, count: int, q: int | None = None) -> list[int]:
    """FIPS 203 :math:`\\operatorname{ByteDecode}_d`, the inverse of :func:`bytepack`.

    When ``q`` is given the decoded integers are additionally reduced modulo
    ``q``; when ``q`` is ``None`` the raw ``d``-bit integers are returned.
    """
    if d < 1:
        raise ValueError("d must be positive")
    out: list[int] = []
    group = 8 // gcd(d, 8)
    if group * d % 8 == 0:
        width = group * d // 8
        if len(data) < ((count + group - 1) // group) * width:
            raise ValueError("byte string too short for the requested decode")
        for i in range(count):
            block = data[(i // group) * width:(i // group + 1) * width]
            packed = int.from_bytes(block, "little")
            out.append((packed >> (d * (i % group))) & ((1 << d) - 1))
    else:
        needed = (count * d + 7) // 8
        if len(data) < needed:
            raise ValueError("byte string too short for the requested decode")
        for i in range(count):
            value = 0
            for j in range(d):
                index = i * d + j
                value |= ((data[index // 8] >> (index % 8)) & 1) << j
            out.append(value)
    return [value if q is None else value % q for value in out]


# --------------------------------------------------------------------------- #
# FIPS 204 packing                                                            #
# --------------------------------------------------------------------------- #
def bitpack(w: int, coeffs: Sequence[int]) -> bytes:
    """FIPS 204 :math:`\\operatorname{BitPack}_w` (little-endian bit order)."""
    bits: list[int] = []
    for coeff in coeffs:
        bits.extend((coeff >> i) & 1 for i in range(w))
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i + 8]):
            byte |= bit << j
        out.append(byte)
    return bytes(out)


def bitunpack(data: bytes, w: int, count: int, alpha: int) -> list[int]:
    """FIPS 204 :math:`\\operatorname{BitUnpack}(v, \\alpha, w)`.

    Each coefficient is read as a ``w``-bit little-endian limb ``t`` and mapped
    to the signed representative of ``t - alpha``; the modular reduction is what
    lets callers pass ``alpha = 0`` to obtain the raw unsigned limb.
    """
    values: list[int] = []
    bit_index = 0
    for _ in range(count):
        value = 0
        for i in range(w):
            byte_index = (bit_index + i) // 8
            bit = (data[byte_index] >> ((bit_index + i) % 8)) & 1
            value |= bit << i
        bit_index += w
        values.append((value - alpha) % (1 << w))
    return values


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of equal-length strings."""
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(p ^ q for p, q in zip(a, b))


def concat(*chunks: bytes) -> bytes:
    """Concatenate byte strings."""
    return b"".join(bytes(c) for c in chunks)


RandomFactory = Callable[[], RandomSource]