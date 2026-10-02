"""Dependency-free Keccak-f[1600] and SHA-3/SHAKE reference implementation.

This module exists so that :mod:`quantumpost` never *requires* an accelerated
backend: :mod:`quantumpost.hashes` falls back to it whenever the interpreter's
:mod:`hashlib` does not expose SHAKE (CPython gained SHAKE in 3.6, so in
practice this path is dead code on any supported interpreter).

.. warning::

   The accelerated backend is the **only** path exercised by the ML-KEM and
   ML-DSA code paths, and it is the path validated against the NIST ACVP
   vectors.  This fallback is a portability net, not a validated second
   implementation: it is covered by structural tests (the permutation is a
   bijection, the sponge is deterministic and prefix-consistent) but it is
   **not** cross-checked against an authoritative digest source, so deployers
   who must rely on it should validate it against FIPS 202 test vectors first.

The implementation follows FIPS 202 directly and is deliberately written for
auditability rather than speed.
"""

from __future__ import annotations

__all__ = ["keccak_f1600", "sha3_256", "sha3_512", "shake_128", "shake_256", "sponge"]

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_MASK64 = (1 << 64) - 1


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[list[int]]) -> None:
    """In-place Keccak-f[1600] permutation on a 5x5 array of 64-bit lanes."""
    for rc in _ROUND_CONSTANTS:
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                state[x][y] ^= dx

        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(state[x][y], _ROTATION_OFFSETS[x][y])

        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & _MASK64)

        # iota
        state[0][0] ^= rc


def keccak_f1600(lanes: list[int]) -> list[int]:
    """Apply the permutation to 25 little-endian 64-bit lanes (returns new list)."""
    if len(lanes) != 25:
        raise ValueError("Keccak-f[1600] operates on 25 lanes")
    state = [[lanes[x + 5 * y] & _MASK64 for y in range(5)] for x in range(5)]
    _keccak_f1600(state)
    return [state[x][y] for y in range(5) for x in range(5)]


def _load64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _xor_byte(state: list[list[int]], index: int, value: int) -> None:
    """XOR a single byte into lane ``index`` of the state."""
    lane = index // 8
    shift = 8 * (index % 8)
    x, y = lane % 5, lane // 5
    state[x][y] ^= value << shift


def _squeeze(state: list[list[int]], rate: int, out_len: int) -> bytes:
    out = bytearray()
    while len(out) < out_len:
        for index in range(rate // 8):
            lane = index // 8
            shift = 8 * (index % 8)
            x, y = lane % 5, lane // 5
            out += ((state[x][y] >> shift) & 0xFF).to_bytes(1, "little")
            if len(out) >= out_len:
                break
        if len(out) < out_len:
            _keccak_f1600(state)
    return bytes(out[:out_len])


def sponge(data: bytes, rate: int, suffix: bytes, out_len: int) -> bytes:
    """Generic Keccak sponge with an explicit rate and domain suffix."""
    data = bytes(data)
    state = [[0] * 5 for _ in range(5)]
    block = rate // 8

    # pad10*1 with the caller's domain separation suffix (0x06 for SHA-3,
    # 0x1f for SHAKE).  The suffix is inserted exactly once, so it is the
    # caller's responsibility to pass it.
    padded = data + suffix + b"\x80"
    if len(padded) % block:
        padded += b"\x00" * (block - len(padded) % block)

    for offset in range(0, len(padded), block):
        for index in range(block):
            _xor_byte(state, index, padded[offset + index])
        _keccak_f1600(state)

    return _squeeze(state, rate, out_len)


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 of ``data``."""
    return sponge(data, 1088, b"\x06", 32)


def sha3_512(data: bytes) -> bytes:
    """SHA3-512 of ``data``."""
    return sponge(data, 576, b"\x06", 64)


def shake_128(data: bytes, out_len: int) -> bytes:
    """SHAKE128 XOF producing ``out_len`` bytes."""
    return sponge(data, 1344, b"\x1f", out_len)


def shake_256(data: bytes, out_len: int) -> bytes:
    """SHAKE256 XOF producing ``out_len`` bytes."""
    return sponge(data, 1088, b"\x1f", out_len)