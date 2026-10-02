"""ML-KEM (FIPS 203, NIST PQC standard 3 of 2024).

ML-KEM is the module-Lattice-Based Key-Encapsulation Mechanism standardised by
NIST, derived from the CRYSTALS-Kyber submission of Lang, Koo, Ducas, Peikert,
Mitzenmacher and de Boer (IEEE S&P 2017).  Its security rests on the hardness of
Module-LWE over ``Z_3329[X]/(X^256 + 1)``.

Implementation notes
--------------------
The algorithms of FIPS 203 (K-PKE.KeyGen / Encrypt / Decrypt and
ML-KEM.KeyGen / Encaps / Decaps) are implemented in the NTT domain end to end.
For ML-KEM that domain is the pair of 128-point negacyclic transforms of the even
and odd polynomial components, because ``512`` does not divide ``q - 1 = 3328``
and a degree-256 negacyclic transform therefore cannot exist over ``Z_3329``.
See :mod:`quantumpost.ntt` for the derivation; :func:`quantumpost.ntt.schoolbook_mul`
serves as the independent correctness oracle in the test-suite.

The Fujisaki-Okamoto transform with **implicit rejection** is the security
critical part: a decapsulated ciphertext that fails re-encryption never raises,
it silently returns the pseudorandom key ``J(z || c)``.  That is what makes the
KEM IND-CCA secure, and the test-suite exercises it directly.
"""

from __future__ import annotations

from typing import Iterable

from quantumpost.hashes import sha3_256, sha3_512, shake128, shake256
from quantumpost.ntt import (
    N,
    mlkem_add_domain,
    mlkem_mul_domain,
    mlkem_sub_domain,
    mlkem_transform,
    mlkem_transform_inverse,
)
from quantumpost.params import MLKEMParams, get_mlkem
from quantumpost.utils import bytepack, bytedecode, random_bytes

__all__ = [
    "Q",
    "CiphertextRejected",
    "generate_keypair",
    "encapsulate",
    "decapsulate",
    "keypair_from_seed",
    "encapsulate_deterministic",
    "parameter_sets",
    "describe",
    "decapsulate_strict",
]

Q = 3329  # FIPS 203 prime modulus
_XOF_WINDOW = 1024


class CiphertextRejected(RuntimeError):
    """Raised by :func:`decapsulate_strict` when a ciphertext fails its check."""


# --------------------------------------------------------------------------- #
# Hash functions of FIPS 203                                                   #
# --------------------------------------------------------------------------- #
def _g(data: bytes) -> tuple[bytes, bytes]:
    """``G``: SHA3-512 split into two 32 byte halves."""
    digest = sha3_512(data)
    return digest[:32], digest[32:]


def _h(data: bytes) -> bytes:
    """``H``: SHA3-256."""
    return sha3_256(data)


def _j(data: bytes) -> bytes:
    """``J``: SHAKE256 squeezed to 32 bytes (implicit rejection key)."""
    return shake256(data, 32)


def _prf(eta: int, seed: bytes, nonce: int) -> bytes:
    """``PRF_eta``: SHAKE256(eta || seed || nonce) squeezed to ``64*eta`` bytes."""
    return shake256(bytes([eta]) + seed + bytes([nonce]), 64 * eta)


# --------------------------------------------------------------------------- #
# XOF reader for SampleNTT                                                     #
# --------------------------------------------------------------------------- #
class _XOFReader:
    """Incremental reader over a SHAKE-128 stream.

    ``hashlib`` XOF objects cannot be extended, so a refilled window is used.
    The window size changes only how many bytes are squeezed per call, never the
    stream itself, which keeps results window independent.
    """

    __slots__ = ("_seed", "_buffer", "_offset", "_window")

    def __init__(self, seed: bytes, window: int = _XOF_WINDOW) -> None:
        self._seed = bytes(seed)
        self._buffer = b""
        self._offset = 0
        self._window = window

    def read(self, count: int) -> bytes:
        if self._offset + count > len(self._buffer):
            self._window = max(self._window, count)
            self._buffer = shake128(self._seed + self._offset.to_bytes(4, "big"), self._window)
            self._offset = 0
        chunk = self._buffer[self._offset:self._offset + count]
        self._offset += count
        return chunk


# --------------------------------------------------------------------------- #
# Sampling                                                                     #
# --------------------------------------------------------------------------- #
def _sample_poly_cbd(eta: int, seed: bytes, nonce: int) -> list[int]:
    """FIPS 203 ``SamplePolyCBD_eta``: centred binomial distribution."""
    if eta not in (2, 3):
        raise ValueError("eta must be 2 or 3")
    bits = _prf(eta, seed, nonce)
    coeffs: list[int] = []
    for i in range(N):
        offset = 2 * eta * i
        acc = 0
        for j in range(eta):
            acc += (bits[(offset + j) // 8] >> ((offset + j) % 8)) & 1
        acc2 = 0
        for j in range(eta):
            index = offset + eta + j
            acc2 += (bits[index // 8] >> (index % 8)) & 1
        coeffs.append((acc - acc2) % Q)
    return coeffs


def _sample_ntt(seed: bytes) -> list[int]:
    """FIPS 203 ``SampleNTT``: rejection sampling of uniform residues mod q.

    Three input bytes yield two 12 bit candidates (``d1 = b0 | b1<<8`` and
    ``d2 = b1<<8 | b2``); candidates ``>= q`` are discarded and the stream
    continues.  The output is a value in the transformed domain.
    """
    reader = _XOFReader(seed)
    coeffs: list[int] = []
    while len(coeffs) < N:
        b0, b1, b2 = reader.read(3)
        d1 = b0 | (b1 << 8)
        d2 = (b1 << 8) | b2
        if d1 < Q:
            coeffs.append(d1)
            if len(coeffs) == N:
                break
        if d2 < Q:
            coeffs.append(d2)
    return coeffs


def _matrix_entry(rho: bytes, row: int, col: int) -> list[int]:
    """``A[row][col] = SampleNTT(rho || col || row)`` in the transformed domain."""
    return _sample_ntt(rho + bytes((col, row)))





# --------------------------------------------------------------------------- #
# Compression and encoding                                                     #
# --------------------------------------------------------------------------- #
def _compress(value: int, d: int) -> int:
    """FIPS 203 ``Compress_d``: round ``2^d * value / q`` (ties round up)."""
    return ((value << d) * 2 + Q) // (2 * Q)


def _decompress(value: int, d: int) -> int:
    """FIPS 203 ``Decompress_d``: round ``q * value / 2^d`` (ties round up)."""
    return ((value * Q) * 2 + (1 << d)) // (2 << d)


def _byte_encode(poly, d: int) -> bytes:
    """FIPS 203 ``ByteEncode_d``: pack coefficients mod ``2^d``."""
    return bytepack([value & ((1 << d) - 1) for value in poly], d)


def _byte_decode(data: bytes, d: int, count: int = N) -> list:
    """FIPS 203 ``ByteDecode_d``: unpack without reduction modulo q."""
    return bytedecode(data, d, count, q=None)


# --------------------------------------------------------------------------- #
# K-PKE (FIPS 203 Algorithms 13-15)                                            #
# --------------------------------------------------------------------------- #
def _kpke_keygen(params: MLKEMParams, seed: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 13 - K-PKE key generation, in the transformed domain."""
    k = params.k
    rho, sigma = _g(seed + bytes([k]))

    s: list[list] = []
    e: list[list] = []
    nonce = 0
    for _ in range(k):
        s.append(mlkem_transform(_sample_poly_cbd(params.eta1, sigma, nonce)))
        nonce += 1
    for _ in range(k):
        e.append(mlkem_transform(_sample_poly_cbd(params.eta2, sigma, nonce)))
        nonce += 1

    t: list[list] = [[0] * N for _ in range(k)]
    for i in range(k):
        for j in range(k):
            t[i] = mlkem_add_domain(t[i], mlkem_mul_domain(_matrix_entry(rho, i, j), s[j]))
        t[i] = mlkem_add_domain(t[i], e[i])

    ek = b"".join(_byte_encode(poly, 12) for poly in t) + rho
    dk = b"".join(_byte_encode(poly, 12) for poly in s)
    return ek, dk


def _kpke_encrypt(params: MLKEMParams, ek: bytes, message: bytes, coins: bytes) -> bytes:
    """FIPS 203 Algorithm 14 - K-PKE encryption."""
    k = params.k
    if len(ek) != 384 * k + 32:
        raise ValueError(f"encapsulation key must be {384 * k + 32} bytes")
    if len(message) != 32:
        raise ValueError("message must be 32 bytes")
    # dk/ek already store values in the transformed domain, so decoding them
    # yields domain values directly - no second transform.
    t_hat = [_byte_decode(ek[i * 384:(i + 1) * 384], 12) for i in range(k)]
    rho = ek[384 * k:]

    y: list[list] = []
    e1: list[list] = []
    nonce = 0
    for _ in range(k):
        y.append(mlkem_transform(_sample_poly_cbd(params.eta1, coins, nonce)))
        nonce += 1
    for _ in range(k):
        e1.append(mlkem_transform(_sample_poly_cbd(params.eta2, coins, nonce)))
        nonce += 1
    e2 = mlkem_transform(_sample_poly_cbd(params.eta2, coins, nonce))

    # u = NTT^-1(A^T . y) + e1
    u: list[list] = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = mlkem_add_domain(acc, mlkem_mul_domain(_matrix_entry(rho, j, i), y[j]))
        u.append(mlkem_add_domain(acc, e1[i]))

    # v = NTT^-1(t^T . y) + e2 + Decompress_1(message)
    acc = [0] * N
    for i in range(k):
        acc = mlkem_add_domain(acc, mlkem_mul_domain(t_hat[i], y[i]))
    # The 32 byte message carries 256 bits = one full polynomial of v.
    mu = [_decompress(bit, 1) for bit in _byte_decode(message, 1, N)]
    v_hat = mlkem_transform_inverse(acc)
    e2_hat = mlkem_transform_inverse(e2)
    v = [(v_hat[i] + e2_hat[i] + mu[i]) % Q for i in range(N)]

    c1 = b"".join(
        _byte_encode([_compress(c, params.du) for c in mlkem_transform_inverse(poly)], params.du)
        for poly in u
    )
    c2 = _byte_encode([_compress(c, params.dv) for c in v], params.dv)
    return c1 + c2


def _kpke_decrypt(params: MLKEMParams, dk: bytes, ciphertext: bytes) -> bytes:
    """FIPS 203 Algorithm 15 - K-PKE decryption."""
    k = params.k
    s_hat = [_byte_decode(dk[i * 384:(i + 1) * 384], 12) for i in range(k)]

    split = params.du * 32 * k
    c1, c2 = ciphertext[:split], ciphertext[split:]
    u = []
    for i in range(k):
        block = c1[i * params.du * 32:(i + 1) * params.du * 32]
        coeffs = [_decompress(c, params.du) for c in _byte_decode(block, params.du)]
        u.append(mlkem_transform(coeffs))
    v = [_decompress(c, params.dv) for c in _byte_decode(c2, params.dv)]

    acc = [0] * N
    for i in range(k):
        acc = mlkem_add_domain(acc, mlkem_mul_domain(s_hat[i], u[i]))
    w = [(a - b) % Q for a, b in zip(v, mlkem_transform_inverse(acc))]
    return _byte_encode([_compress(c, 1) for c in w], 1)


# --------------------------------------------------------------------------- #
# ML-KEM (FIPS 203 Algorithms 16-18)                                           #
# --------------------------------------------------------------------------- #
def keypair_from_seed(params: MLKEMParams, d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 16 - deterministic key generation from ``(d, z)``."""
    if len(d) != 32 or len(z) != 32:
        raise ValueError("d and z must both be 32 bytes")
    ek, dk_pke = _kpke_keygen(params, d)
    return ek, dk_pke + ek + _h(ek) + z


def generate_keypair(
    params: MLKEMParams | str = "ML-KEM-768",
    *,
    seed: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Generate an ML-KEM key pair ``(ek, dk)``.

    ``seed`` (64 bytes) exists for reproducible test-vector generation; in
    production the 64 bytes always come from the system CSPRNG.
    """
    if isinstance(params, str):
        params = get_mlkem(params)
    if seed is None:
        seed = random_bytes(params.seed_len)
    if len(seed) != params.seed_len:
        raise ValueError(f"seed must be {params.seed_len} bytes")
    return keypair_from_seed(params, seed[:32], seed[32:])


def encapsulate_deterministic(
    params: MLKEMParams | str,
    ek: bytes,
    message: bytes,
) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 17 - encapsulation with an explicit 32 byte message."""
    if isinstance(params, str):
        params = get_mlkem(params)
    if len(message) != 32:
        raise ValueError("message must be 32 bytes")
    key, coins = _g(message + _h(ek))
    return key, _kpke_encrypt(params, ek, message, coins)


def encapsulate(
    params: MLKEMParams | str = "ML-KEM-768",
    ek: bytes | None = None,
    *,
    message: bytes | None = None,
) -> tuple[bytes, bytes]:
    """FIPS 203 Algorithm 17 - encapsulate, returning ``(shared_secret, ct)``."""
    if isinstance(params, str):
        params = get_mlkem(params)
    if ek is None:
        raise ValueError("an encapsulation key is required")
    if message is None:
        message = random_bytes(32)
    return encapsulate_deterministic(params, ek, message)


def _decapsulation_parts(params: MLKEMParams, dk: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    k = params.k
    if len(dk) != params.dk_len:
        raise ValueError(f"decapsulation key must be {params.dk_len} bytes")
    return (
        dk[:384 * k],
        dk[384 * k:768 * k + 32],
        dk[768 * k + 32:768 * k + 64],
        dk[768 * k + 64:768 * k + 96],
    )


def decapsulate(
    params: MLKEMParams | str,
    dk: bytes,
    ciphertext: bytes,
) -> bytes:
    """FIPS 203 Algorithm 18 - decapsulation with implicit rejection.

    A structurally invalid ``dk`` raises :class:`ValueError`, since there is no
    ``z`` available to build a rejection key from.  Every other failure mode -
    wrong ciphertext length, modified ciphertext, corrupted ``ek`` inside ``dk`` -
    returns the pseudorandom key ``J(z || c)`` without raising, which is exactly
    the IND-CCA property FIPS 203 requires.
    """
    if isinstance(params, str):
        params = get_mlkem(params)
    dk_pke, ek, h, z = _decapsulation_parts(params, dk)

    if len(ciphertext) != params.ct_len:
        return _j(z + ciphertext)

    message = _kpke_decrypt(params, dk_pke, ciphertext)
    key, coins = _g(message + h)
    if _kpke_encrypt(params, ek, message, coins) != ciphertext:
        return _j(z + ciphertext)
    return key


def decapsulate_strict(
    params: MLKEMParams | str,
    dk: bytes,
    ciphertext: bytes,
) -> bytes:
    """Like :func:`decapsulate` but raises :class:`CiphertextRejected` on failure.

    Provided for test suites and callers that want an explicit error; the
    security-critical path is :func:`decapsulate`.
    """
    if isinstance(params, str):
        params = get_mlkem(params)
    dk_pke, ek, h, z = _decapsulation_parts(params, dk)
    if len(ciphertext) != params.ct_len:
        raise CiphertextRejected("ciphertext has the wrong length")
    message = _kpke_decrypt(params, dk_pke, ciphertext)
    key, coins = _g(message + h)
    if _kpke_encrypt(params, ek, message, coins) != ciphertext:
        raise CiphertextRejected("ciphertext failed re-encryption")
    return key


# --------------------------------------------------------------------------- #
# Introspection                                                                #
# --------------------------------------------------------------------------- #
def parameter_sets() -> Iterable[str]:
    """Names of the standardised ML-KEM parameter sets."""
    return ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")


def describe(name: str = "ML-KEM-768") -> dict:
    """Full metadata record for a parameter set."""
    return get_mlkem(name).as_dict()