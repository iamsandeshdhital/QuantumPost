"""Hash and extendable-output-function (XOF) primitives used by the library.

The module exposes a single, uniform interface over the four hash families that
appear in FIPS 203/204/205:

``SHA3-256`` / ``SHA3-512``
    Keccak based fixed-output hashes (FIPS 202).  Required by ML-KEM and ML-DSA.
``SHAKE128`` / ``SHAKE256``
    Keccak based extendable-output functions (FIPS 202).  Required by ML-KEM,
    ML-DSA (per-block shuffling) and the SLH-DSA-SHAKE parameter sets.
``SHA-256`` / ``SHA-512/256``
    FIPS 180-4 hashes required by the SLH-DSA-SHA2 parameter sets.

Everything is served by :mod:`hashlib`, i.e. the platform's OpenSSL backend, so
the library has **no third-party dependencies**.  A self-contained Keccak
fallback (:mod:`quantumpost.keccak_pure`) is used automatically when the running
interpreter does not provide SHAKE, which keeps the reference implementation
portable to constrained environments.

All digests are returned as :class:`bytes`.  ``squeeze`` accepts an explicit
output length in **bytes** which removes the most common source of errors in
post-quantum code (bit/byte confusion in the specifications).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Callable

from quantumpost import keccak_pure

__all__ = [
    "HASHES",
    "has_shake",
    "sha3_256",
    "sha3_512",
    "sha2_256",
    "sha2_512_256",
    "sha_512",
    "shake128",
    "shake256",
    "xof",
    "hash_for",
    "xof_for",
    "select_drbg",
    "length_prefixed",
]


def has_shake() -> bool:
    """Return ``True`` when the accelerated (OpenSSL) SHAKE is available."""
    return hasattr(hashlib, "shake_128") and hasattr(hashlib, "shake_256")


# --------------------------------------------------------------------------- #
# Fixed-output hashes                                                          #
# --------------------------------------------------------------------------- #
def sha3_256(data: bytes) -> bytes:
    """SHA3-256 (32 byte digest)."""
    return hashlib.sha3_256(bytes(data)).digest()


def sha3_512(data: bytes) -> bytes:
    """SHA3-512 (64 byte digest)."""
    return hashlib.sha3_512(bytes(data)).digest()


def sha2_256(data: bytes) -> bytes:
    """SHA-256 (32 byte digest)."""
    return hashlib.sha256(bytes(data)).digest()


def sha2_512_256(data: bytes) -> bytes:
    """SHA-512/256 (32 byte digest)."""
    try:
        return hashlib.new("sha512_256", bytes(data)).digest()
    except ValueError:  # pragma: no cover - exotic builds without the alias
        return hashlib.sha512(bytes(data)).digest()[:32]


def sha_512(data: bytes) -> bytes:
    """SHA-512 (64 byte digest)."""
    return hashlib.sha512(bytes(data)).digest()


# --------------------------------------------------------------------------- #
# Extendable output functions                                                  #
# --------------------------------------------------------------------------- #
def shake128(data: bytes, out_len: int) -> bytes:
    """SHAKE128 squeezed to ``out_len`` **bytes**."""
    data = bytes(data)
    if has_shake():
        return hashlib.shake_128(data).digest(out_len)
    return keccak_pure.shake_128(data, out_len)


def shake256(data: bytes, out_len: int) -> bytes:
    """SHAKE256 squeezed to ``out_len`` **bytes**."""
    data = bytes(data)
    if has_shake():
        return hashlib.shake_256(data).digest(out_len)
    return keccak_pure.shake_256(data, out_len)


def xof(data: bytes, out_len: int, name: str = "shake256") -> bytes:
    """Generic XOF dispatch by name (``shake128`` or ``shake256``)."""
    if name == "shake128":
        return shake128(data, out_len)
    if name == "shake256":
        return shake256(data, out_len)
    raise ValueError(f"unknown XOF: {name!r}")


# --------------------------------------------------------------------------- #
# Algorithm -> hash binding                                                     #
# --------------------------------------------------------------------------- #
HASHES: dict[str, Callable[[bytes], bytes]] = {
    "sha3-256": sha3_256,
    "sha3-512": sha3_512,
    "sha2-256": sha2_256,
    "sha2-512-256": sha2_512_256,
    "sha-512": sha_512,
}


def hash_for(name: str, data: bytes) -> bytes:
    """Hash ``data`` with the named FIPS 180/202 primitive."""
    try:
        return HASHES[name](data)
    except KeyError as exc:  # pragma: no cover - programming error
        raise ValueError(f"unsupported hash primitive: {name!r}") from exc


def xof_for(name: str, data: bytes, out_len: int) -> bytes:
    """Squeeze ``name`` (a SHAKE variant) over ``data`` to ``out_len`` bytes."""
    return xof(data, out_len, name)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def length_prefixed(*chunks: bytes) -> bytes:
    """Domain-separate and length-prefix a sequence of byte strings.

    Concatenating variable length cryptographic messages without a delimiter is
    the classic source of length-extension and boundary confusion bugs, so all
    transcript / KDF inputs in this library go through this helper.

    The encoding is::

        len(c0) || c0 || len(c1) || c1 || ...

    with 8 byte big-endian lengths.
    """
    out = bytearray()
    for chunk in chunks:
        chunk = bytes(chunk)
        out += len(chunk).to_bytes(8, "big")
        out += chunk
    return bytes(out)


def select_drbg(seed: bytes) -> bytes:
    """Return 64 deterministic bytes used to seed XOF based DRBGs in tests."""
    return shake256(b"QuantumPost/DRBG/v1" + seed, 64)


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality for secret comparisons (delegates to HMAC)."""
    return hmac.compare_digest(bytes(a), bytes(b))