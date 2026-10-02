"""ML-DSA (FIPS 204, NIST PQC standard 2 of 2024).

ML-DSA is the module-Lattice-Based Digital Signature Algorithm standardised by
NIST, derived from the CRYSTALS-Dilithium submission of Ducas, Durmus,
Lepoint, Lyubashevsky, Peters, Savasta and Taylor (IACR TCHES 2018).  Its
security rests on Module-LWE and Module-SIS over
``Z_8380417[X]/(X^256 + 1)``.

Design notes
------------
Signatures are *randomised*: signing draws fresh coins each time, so two
signatures over the same message differ while both verify.  Rejection sampling
bounds the norm of the response ``z`` and of the commitment ``w``; if a
candidate exceeds the bounds the algorithm retries with the next counter, which
is what keeps verification from leaking the secret key.

Because ``512`` divides ``q - 1`` for ``q = 8380417``, a degree-256 negacyclic
NTT exists and every polynomial operation runs in the transformed domain exactly
as FIPS 204 prescribes.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from quantumpost.hashes import sha3_256, sha3_512, shake256
from quantumpost.ntt import NegacyclicNTT, centered
from quantumpost.params import MLDSAParams, get_mldsa
from quantumpost.utils import bitpack, bitunpack, bytes_to_int, int_to_bytes, random_bytes

__all__ = [
    "Q",
    "D",
    "InvalidSignature",
    "generate_keypair",
    "sign",
    "verify",
    "keypair_from_seed",
    "parameter_sets",
    "describe",
]

Q = 8380417
D = 13
_N = 256
_NTT = NegacyclicNTT(Q, _N)
assert _NTT.supported, "q = 8380417 must admit a degree-256 negacyclic NTT"


class InvalidSignature(ValueError):
    """Raised by :func:`verify_strict` when a signature does not verify."""


# --------------------------------------------------------------------------- #
# Primitives                                                                   #
# --------------------------------------------------------------------------- #
def _h(data: bytes) -> bytes:
    return sha3_256(data)


def _g(data: bytes) -> tuple[bytes, bytes]:
    digest = sha3_512(data)
    return digest[:32], digest[32:]


def _xof(data: bytes, out_len: int) -> bytes:
    return shake256(data, out_len)


def _bitlen(value: int) -> int:
    return value.bit_length()


def _inf_norm(poly: Sequence[int]) -> int:
    """Infinity norm with symmetric representatives (FIPS 204 ``||.||_inf``)."""
    return max((abs(centered(c, Q)) for c in poly), default=0)


def _max_abs(values: Iterable[int]) -> int:
    return max((abs(centered(v, Q)) for v in values), default=0)


# --------------------------------------------------------------------------- #
# Sampling                                                                     #
# --------------------------------------------------------------------------- #
def _sample_in_ball(c_tilde: bytes) -> list[int]:
    """FIPS 204 ``SampleInBall``: a uniform point on the sphere of radius 23.

    The result has exactly ``c = 8`` nonzero coefficients, all within the top
    eight positions, with magnitudes ``2**0 .. 2**7``.  Positions are chosen by
    consuming one bit at a time from a SHAKE256 stream of ``c_tilde``: a ``1``
    rejects the current position and moves on, a ``0`` accepts it.  That is
    uniform over the admissible supports and the acceptance rate is ``2**-8``
    per attempt, so termination is immediate in practice.
    """
    c = 8
    signs = int.from_bytes(_h(c_tilde), "little")
    stream = int.from_bytes(_xof(c_tilde, 64), "little")

    coeffs = [0] * _N
    accepted = 0
    position = _N - 1
    refills = 0
    while accepted < c:
        if stream == 0:  # stream exhausted, refill as the specification does
            refills += 1
            stream = int.from_bytes(
                _xof(c_tilde + bytes([refills & 0xFF])), 64
            )
            continue
        bit = stream & 1
        stream >>= 1
        if bit:
            continue  # reject this position and try the next one downwards
        value = 1 << accepted
        coeffs[position] = -value if (signs >> accepted) & 1 else value
        position -= 1
        accepted += 1
    return coeffs


def _rej_ntt_poly(seed: bytes) -> list[int]:
    """FIPS 204 ``RejNTTPoly``: uniform values in the transformed domain."""
    out: list[int] = []
    offset = 0
    while len(out) < _N:
        chunk = _xof(seed + offset.to_bytes(2, "little"), 3 * 32)
        for i in range(0, len(chunk), 3):
            val = (chunk[i] | (chunk[i + 1] << 8) | (chunk[i + 2] << 16))
            val >>= 1
            if val < Q:
                out.append(val)
                if len(out) == _N:
                    break
        offset += 3
    return out


def _matrix_entry(rho: bytes, row: int, col: int) -> list[int]:
    """``A[row][col] = RejNTTPoly(rho || col || row)`` in the transformed domain."""
    return _rej_ntt_poly(rho + bytes((col, row)))


def _poly_cbd(eta: int, seed: bytes, nonce: int) -> list[int]:
    """FIPS 204 ``SamplePolyCBD_eta``, returned in the *coefficient* domain.

    FIPS 204 stores ``s1`` and ``s2`` in the coefficient domain, unlike ``A``
    and ``t``, which live in the transformed domain.
    """
    bits = _xof(seed + nonce.to_bytes(2, "little"), 64 * eta)
    coeffs = []
    for i in range(_N):
        offset = 2 * eta * i
        acc = 0
        for j in range(eta):
            index = offset + j
            acc += (bits[index // 8] >> (index % 8)) & 1
        acc2 = 0
        for j in range(eta):
            index = offset + eta + j
            acc2 += (bits[index // 8] >> (index % 8)) & 1
        value = acc - acc2
        coeffs.append(value % Q)
    return coeffs


def _poly_uniform_gamma1(gamma1: int, seed: bytes, nonce: int) -> list[int]:
    """FIPS 204 ``SamplePolyUniformGamma1``."""
    bits = _bitlen(gamma1 - 1)
    raw = _xof(seed + nonce.to_bytes(2, "little"), 32 * bits)
    values = bitunpack(raw, bits, _N, gamma1)
    return [(-v) % Q for v in values]


def _ntt(poly: Sequence[int]) -> list[int]:
    return _NTT.forward(poly)


def _inv_ntt(poly: Sequence[int]) -> list[int]:
    return _NTT.inverse(poly)


def _ntt_mul(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Multiply two transformed-domain polynomials."""
    return [x * y % Q for x, y in zip(a, b)]


def _ntt_mul_coeff(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Multiply a transformed polynomial by a coefficient-domain polynomial."""
    return _inv_ntt(_ntt_mul(a, _ntt(b)))


# --------------------------------------------------------------------------- #
# Rounding helpers                                                             #
# --------------------------------------------------------------------------- #
def _power2round(r: int) -> tuple[int, int]:
    """FIPS 204 ``Power2Round``: ``r -> (r1, r0)`` with ``r = r1*2^13 + r0``.

    ``r0`` is the balanced remainder modulo ``2**13`` and ``r1`` the quotient.
    """
    rp = centered(r % Q, Q)
    r0 = centered(rp, 2 ** D)
    r1 = (rp - r0) // (1 << D)
    return r1, r0


def _decompose(r: int, gamma1: int, gamma2: int) -> tuple[int, int]:
    """FIPS 204 ``Decompose``: ``r -> (r1, r0)`` with ``r = r1*gamma1 + r0``.

    ``r0`` is the balanced representative modulo ``gamma1``.  The special case
    ``r+ - r0 == q - 1`` is what keeps the map uniform, so it is preserved.
    """
    rp = centered(r % Q, Q)
    r0 = centered(rp, gamma1)
    if rp - r0 == Q - 1:
        return 0, r0 - 1
    return (rp - r0) // gamma1, r0


def _high_bits(poly: Sequence[int]) -> list[int]:
    return [_power2round(c)[0] for c in poly]


def _make_hint(z: int, r: int, gamma1: int, gamma2: int) -> int:
    """FIPS 204 ``MakeHint``."""
    r1 = _decompose(r, gamma1, gamma2)[0]
    v1 = _power2round(z + r)[0]
    return 1 if r1 != v1 else 0


def _use_hint(hint: int, r: int, gamma1: int, gamma2: int) -> int:
    """FIPS 204 ``UseHint``."""
    r1 = _decompose(r, gamma1, gamma2)[1]
    if hint == 0:
        return _decompose(r, gamma1, gamma2)[0]
    return r1


# --------------------------------------------------------------------------- #
# Encoding                                                                     #
# --------------------------------------------------------------------------- #
def _simple_bit_pack(poly: Sequence[int], bits: int) -> bytes:
    """FIPS 204 ``SimpleBitPack``: ``bits``-wide little-endian limbs mod q."""
    return bitpack(bits, [centered(c, Q) % (1 << bits) for c in poly])


def _simple_bit_unpack(data: bytes, bits: int, count: int = _N) -> list[int]:
    """FIPS 204 ``SimpleBitUnpack``: read back ``bits``-wide limbs."""
    return bitunpack(data, bits, count, (1 << bits) - 1)


def _w1_encode(poly: Sequence[int]) -> bytes:
    """FIPS 204 ``w1Encode``: 35-bit packing of the high bits."""
    return bitpack(35, [centered(c, Q) % (1 << 35) for c in poly])


def _pk_encode(params: MLDSAParams, rho: bytes, t1: list[list[int]]) -> bytes:
    out = bytearray(rho)
    for poly in t1:
        out += _simple_bit_pack(poly, params.t1_bits)
    return bytes(out)


def _pk_decode(params: MLDSAParams, pk: bytes) -> tuple[bytes, list[list[int]]]:
    expected = params.pk_len
    if len(pk) != expected:
        raise ValueError(f"public key must be {expected} bytes")
    rho = pk[:32]
    t1 = []
    offset = 32
    stride = MLDSAParams._packed(params.t1_bits)
    for _ in range(params.k):
        t1.append(_simple_bit_unpack(pk[offset:offset + stride], params.t1_bits))
        offset += stride
    return rho, t1


def _sk_encode(
    params: MLDSAParams,
    rho: bytes,
    key: bytes,
    tr: bytes,
    s1: list[list[int]],
    s2: list[list[int]],
    t0: list[list[int]],
) -> bytes:
    out = bytearray()
    out += rho + key + tr
    for poly in s1:
        out += _simple_bit_pack(poly, params.eta)
    for poly in s2:
        out += _simple_bit_pack(poly, params.eta)
    for poly in t0:
        out += _simple_bit_pack(poly, D)
    return bytes(out)


def _sk_decode(params: MLDSAParams, sk: bytes) -> dict:
    expected = params.sk_len
    if len(sk) != expected:
        raise ValueError(f"private key must be {expected} bytes")
    rho = sk[:32]
    key = sk[32:64]
    tr = sk[64:128]
    offset = 128
    s1, s2, t0 = [], [], []
    eta_stride = MLDSAParams._packed(params.eta)
    d_stride = MLDSAParams._packed(D)
    for _ in range(params.k):
        s1.append(_simple_bit_unpack(sk[offset:offset + eta_stride], params.eta))
        offset += eta_stride
    for _ in range(params.k):
        s2.append(_simple_bit_unpack(sk[offset:offset + eta_stride], params.eta))
        offset += eta_stride
    for _ in range(params.k):
        t0.append(_simple_bit_unpack(sk[offset:offset + d_stride], D))
        offset += d_stride
    return {
        "rho": rho, "key": key, "tr": tr,
        "s1": s1, "s2": s2, "t0": t0,
        "s1_hat": [_ntt(p) for p in s1],
        "s2_hat": [_ntt(p) for p in s2],
        "t0_hat": [_ntt(p) for p in t0],
    }


def _sig_encode(
    params: MLDSAParams,
    c_tilde: bytes,
    z: list[list[int]],
    hints: bytes,
) -> bytes:
    packed_z = b"".join(
        bitpack(params.z_bits, [centered(c, Q) % params.gamma1 for c in poly])
        for poly in z
    )
    return c_tilde + packed_z + hints


def _sig_decode(params: MLDSAParams, sig: bytes):
    c_len = params.c_tilde_len
    z_len = params.ell * 32 * params.z_bits
    hint_len = params.k * _N
    if len(sig) != c_len + z_len + hint_len:
        raise ValueError(f"signature must be {params.sig_len} bytes")
    c_tilde = sig[:c_len]
    raw_z = sig[c_len:c_len + z_len]
    hints = sig[c_len + z_len:]
    bits = params.z_bits
    z = []
    per = 32 * bits
    for i in range(params.ell):
        block = raw_z[i * per:(i + 1) * per]
        values = bitunpack(block, bits, _N, params.gamma1)
        z.append([centered(v, params.gamma1) % Q for v in values])
    return c_tilde, z, hints


# --------------------------------------------------------------------------- #
# Key generation (FIPS 204 Algorithm 6)                                        #
# --------------------------------------------------------------------------- #
def keypair_from_seed(params: MLDSAParams, xi: bytes) -> tuple[bytes, bytes]:
    """Deterministic key generation from a 32 byte seed ``xi``."""
    if len(xi) != 32:
        raise ValueError("seed must be 32 bytes")
    k = params.k
    # Domain separation matches the official NIST ACVP keyGen vectors:
    # (rho, rho', K) <- SHAKE256(xi || k || ell, 128).
    expanded = _xof(xi + bytes((k, params.ell)), 128)
    rho, rho_prime, key = expanded[:32], expanded[32:64], expanded[64:96]

    s1 = [_poly_cbd(params.eta, rho_prime, i) for i in range(k)]
    s2 = [_poly_cbd(params.eta, rho_prime, k + i) for i in range(k)]

    t = []
    for i in range(k):
        acc = list(s2[i])
        for j in range(k):
            acc = [(x + y) % Q for x, y in zip(acc, _ntt_mul_coeff(_matrix_entry(rho, i, j), s1[j]))]
        t.append(acc)

    t1 = []
    t0 = []
    for poly in t:
        hi = _high_bits(poly)
        lo = [_power2round(c)[1] for c in poly]
        t1.append(hi)
        t0.append(lo)

    pk = _pk_encode(params, rho, t1)
    # FIPS 204: tr = H(pk, 64), a 64 byte SHAKE256 digest, not a 32 byte hash.
    tr = _xof(pk, 64)
    sk = _sk_encode(params, rho, key, tr, s1, s2, t0)
    return pk, sk


def generate_keypair(
    params: MLDSAParams | str = "ML-DSA-65",
    *,
    seed: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Generate an ML-DSA key pair ``(pk, sk)``."""
    if isinstance(params, str):
        params = get_mldsa(params)
    if seed is None:
        seed = random_bytes(32)
    return keypair_from_seed(params, seed)


# --------------------------------------------------------------------------- #
# Signing (FIPS 204 Algorithm 7)                                               #
# --------------------------------------------------------------------------- #
def sign(
    params: MLDSAParams | str,
    sk: bytes,
    message: bytes,
    *,
    rnd: bytes | None = None,
) -> bytes:
    """Produce a randomised signature over ``message``."""
    if isinstance(params, str):
        params = get_mldsa(params)
    if rnd is None:
        rnd = random_bytes(32)
    if len(rnd) != 32:
        raise ValueError("rnd must be 32 bytes")
    obj = _sk_decode(params, sk)
    mu = _h(obj["tr"] + message)
    rho_pp = _h(obj["key"] + rnd + mu)

    gamma1, gamma2, beta = params.gamma1, params.gamma2, params.beta
    kappa = 0
    while True:
        y = [_poly_uniform_gamma1(gamma1, rho_pp, kappa + i) for i in range(params.ell)]

        # w = A y  (transformed domain throughout)
        w = []
        for i in range(params.k):
            acc = [0] * _N
            for j in range(params.k):
                acc = [(a + b) % Q for a, b in zip(acc, _ntt_mul(_matrix_entry(obj["rho"], i, j), y[j]))]
            w.append(acc)

        w1 = [_high_bits(poly) for poly in w]
        c_tilde = _h(mu + b"".join(_w1_encode(poly) for poly in w1))
        c_hat = _ntt(_sample_in_ball(c_tilde))

        # z = y + c*s1,  r0 = lowbits(w - c*s2)
        z = []
        for i in range(params.ell):
            correction = _inv_ntt(_ntt_mul(c_hat, obj["s1_hat"][i]))
            z.append([(a + b) % Q for a, b in zip(y[i], correction)])

        w_cs2 = []
        for i in range(params.k):
            correction = _inv_ntt(_ntt_mul(c_hat, obj["s2_hat"][i]))
            w_cs2.append([(a - b) % Q for a, b in zip(w[i], correction)])
        r0 = []
        for i in range(params.k):
            r0.extend(_decompose(c, gamma1, gamma2)[1] for c in w_cs2[i])

        if _max_abs([c for poly in z for c in poly]) >= gamma1 - beta or \
                _max_abs(r0) >= gamma2 - beta:
            kappa += params.ell
            continue

        # csq = c * (t0 * y)
        # csq = c * (t0 * y).  The security condition is not that csq itself is
        # small, but that ``w - c*s2 + csq`` has vanishing high bits, i.e. that
        # it is exactly divisible by 2^d.  That is what stops the committed
        # high bits from leaking information about the secret key.
        hint_bits = bytearray()
        hint_count = 0
        ok = True
        for i in range(params.k):
            part = _inv_ntt(_ntt_mul(c_hat, obj["t0_hat"][i]))
            yy = _inv_ntt(_ntt_mul(c_hat, y[i]))
            csq = [(a - b) % Q for a, b in zip(part, yy)]
            combined = [(a + b) % Q for a, b in zip(w_cs2[i], csq)]
            if any(_power2round(c)[1] != 0 for c in combined):
                ok = False
                break
            for j in range(_N):
                hint = _make_hint(z[j][i], combined[j], gamma1, gamma2)
                hint_bits.append(hint)
                hint_count += hint
        if not ok or hint_count > params.omega:
            kappa += params.ell
            continue

        return _sig_encode(params, c_tilde, z, bytes(hint_bits))


# --------------------------------------------------------------------------- #
# Verification (FIPS 204 Algorithm 8)                                           #
# --------------------------------------------------------------------------- #
def verify(
    params: MLDSAParams | str,
    pk: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify ``signature`` over ``message``; returns ``False`` on any failure."""
    if isinstance(params, str):
        params = get_mldsa(params)
    if len(pk) != params.pk_len or len(signature) != params.sig_len:
        return False
    try:
        rho, t1 = _pk_decode(params, pk)
        c_tilde, z, hints = _sig_decode(params, signature)
    except ValueError:
        return False

    gamma1, gamma2, beta = params.gamma1, params.gamma2, params.beta
    if _max_abs([c for poly in z for c in poly]) >= gamma1 - beta:
        return False
    if any(h > 1 for h in hints):
        return False

    # tr = H(pk, 64) must match the value stored in the signing key.
    mu = _h(_xof(pk, 64) + message)
    c_hat = _ntt(_sample_in_ball(c_tilde))

    t1_hat = [_ntt(poly) for poly in t1]
    index = 0
    w1_bytes = bytearray()
    for i in range(params.k):
        acc = [0] * _N
        for j in range(params.k):
            acc = [(a + b) % Q for a, b in zip(acc, _ntt_mul(_matrix_entry(rho, i, j), z[j]))]
        acc = [(a - b) % Q for a, b in zip(acc, _ntt_mul(c_hat, t1_hat[i]))]
        # w1[i] = UseHint(h, w[i]); the hint stream is interleaved i-major
        poly = []
        for j in range(_N):
            hint = hints[i * _N + j]
            poly.append(_use_hint(hint, acc[j], gamma1, gamma2) % Q)
            index += 1
        w1_bytes += _w1_encode(poly)

    return c_tilde == _h(mu + bytes(w1_bytes))


def verify_strict(
    params: MLDSAParams | str,
    pk: bytes,
    message: bytes,
    signature: bytes,
) -> None:
    """Like :func:`verify` but raises :class:`InvalidSignature` on failure."""
    if not verify(params, pk, message, signature):
        raise InvalidSignature("signature verification failed")


# --------------------------------------------------------------------------- #
# Introspection                                                                #
# --------------------------------------------------------------------------- #
def parameter_sets() -> Iterable[str]:
    """Names of the standardised ML-DSA parameter sets."""
    return ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


def describe(name: str = "ML-DSA-65") -> dict:
    """Full metadata record for a parameter set."""
    return get_mldsa(name).as_dict()