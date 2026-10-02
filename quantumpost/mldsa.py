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

from quantumpost.hashes import ct_eq, sha3_256, sha3_512, shake128, shake256
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
#: SHAKE256 output bytes consumed per ``RejNTTPoly`` squeeze round.
_REJ_BLOCKS = 3
#: FIPS 204 Sec. 11 lower bound on ``ML-DSA.Sign_internal`` iterations.
_SIGN_ATTEMPT_LIMIT = 8192
#: ``q^-1 mod 2^32`` used by the Montgomery reduction (FIPS 204 Alg. 49).
_Q_INV = 58728449
_MONT = 1 << 32
#: FIPS 204 Algorithm 41 zeta table: ``zetas[k] = zeta^(brv(k)) mod q``.
_ZETAS: tuple[int, ...] = tuple(
    int(literal)
    for literal in """0 25847 -2608894 -518909 237124 -777960 -876248 466468
1826347 2353451 -359251 -2091905 3119733 -2884855 3111497 2680103 2725464
1024112 -1079900 3585928 -549488 -1119584 2619752 -2108549 -2118186 -3859737
-1399561 -3277672 1757237 -19422 4010497 280005 2706023 95776 3077325
3530437 -1661693 -3592148 -2537516 3915439 -3861115 -3043716 3574422 -2867647
3539968 -300467 2348700 -539299 -1699267 -1643818 3505694 -3821735 3507263
-2140649 -1600420 3699596 811944 531354 954230 3881043 3900724 -2556880
2071892 -2797779 -3930395 -1528703 -3677745 -3041255 -1452451 3475950 2176455
-1585221 -1257611 1939314 -4083598 -1000202 -3190144 -3157330 -3632928 126922
3412210 -983419 2147896 2715295 -2967645 -3693493 -411027 -2477047 -671102
-1228525 -22981 -1308169 -381987 1349076 1852771 -1430430 -3343383 264944
508951 3097992 44288 -1100098 904516 3958618 -3724342 -8578 1653064
-3249728 2389356 -210977 759969 -1316856 189548 -3553272 3159746 -1851402
-2409325 -177440 1315589 1341330 1285669 -1584928 -812732 -1439742 -3019102
-3881060 -3628969 3839961 2091667 3407706 2316500 3817976 -3342478 2244091
-2446433 -3562462 266997 2434439 -1235728 3513181 -3520352 -3759364 -1197226
-3193378 900702 1859098 909542 819034 495491 -1613174 -43260 -522500
-655327 -3122442 2031748 3207046 -3556995 -525098 -768622 -3595838 342297
286988 -2437823 4108315 3437287 -3342277 1735879 203044 2842341 2691481
-2590150 1265009 4055324 1247620 2486353 1595974 -3767016 1250494 2635921
-3548272 -2994039 1869119 1903435 -1050970 -1333058 1237275 -3318210 -1430225
-451100 1312455 3306115 -1962642 -1279661 1917081 -2546312 -1374803 1500165
777191 2235880 3406031 -542412 -2831860 -1671176 -1846953 -2584293 -3724270
594136 -3776993 -2013608 2432395 2454455 -164721 1957272 3369112 185531
-1207385 -3183426 162844 1616392 3014001 810149 1652634 -3694233 -1799107
-3038916 3523897 3866901 269760 2213111 -975884 1717735 472078 -426683
1723600 -1803090 1910376 -1667432 -1104333 -260646 -3833893 -2939036 -2235985
-420899 -2286327 183443 -976891 1612842 -3545687 -554416 3919660 -48306
-1362209 3937738 1400424 -846154 1976782""".split()
)
assert len(_ZETAS) == _N, "FIPS 204 requires a 256 entry zeta table"
assert _ZETAS[1] % Q == 25847, "zetas[1] must be zeta^brv(1) = zeta^128 mod q"


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
def _sample_in_ball(c_tilde: bytes, tau: int) -> list[int]:
    """FIPS 204 Algorithm 29 ``SampleInBall``.

    A single SHAKE256 instance seeded with ``c_tilde`` supplies both the sign
    bits (its first eight bytes, little-endian) and the index stream.  Walking
    ``i`` from ``256 - tau`` upwards, each step draws indices until one is at
    most ``i``, swaps that coefficient up to position ``i`` and writes a fresh
    sign into it, which is the textbook constant-weight sampler over the sphere
    of radius ``tau``.
    """
    coeffs = [0] * _N
    want = 8 + 256
    stream = shake256(c_tilde, want)
    signs = int.from_bytes(stream[:8], "little")
    pos = 8
    for i in range(_N - tau, _N):
        while True:
            if pos >= len(stream):
                want += 256
                stream = shake256(c_tilde, want)
            byte = stream[pos]
            pos += 1
            if byte <= i:
                break
        coeffs[i] = coeffs[byte]
        coeffs[byte] = 1 - 2 * (signs & 1)
        signs >>= 1
    return coeffs


def _rej_ntt_poly(seed: bytes) -> list[int]:
    """FIPS 204 Algorithm 32 ``RejNTTPoly``: uniform values in the Z_q domain.

    ``seed`` is the absorbed prefix (``rho || s || r``).  Each three byte group
    yields the 23-bit candidate ``t = (C0 | C1<<8 | C2<<16) & 0x7FFFFF``, which
    is accepted when ``t < q``.  One XOF instance is squeezed incrementally.
    """
    out: list[int] = []
    want = 3 * _REJ_BLOCKS
    chunk = shake128(seed, want)
    pos = 0
    while len(out) < _N:
        if pos + 3 > len(chunk):
            want += 3 * _REJ_BLOCKS
            chunk = shake128(seed, want)
        value = (chunk[pos] | (chunk[pos + 1] << 8) | (chunk[pos + 2] << 16)) & 0x7FFFFF
        pos += 3
        if value < Q:
            out.append(value)
    return out


def _matrix_entry(rho: bytes, row: int, col: int) -> list[int]:
    """``A[row][col] = RejNTTPoly(rho || col || row)`` in the transformed domain."""
    return _rej_ntt_poly(rho + bytes((col, row)))


def _poly_uniform_eta(eta: int, seed: bytes, nonce: int) -> list[int]:
    """FIPS 204 Algorithm 29 ``RejBoundedPoly``, coefficient domain.

    Each byte of ``SHAKE256(seed || nonce)`` supplies two 4-bit candidates.
    A candidate is accepted only when it is below ``15`` (``eta = 2``) or
    ``9`` (``eta = 4``) and is then reflected into ``[-eta, eta]``.  For
    ``eta = 2`` the accepted range strictly exceeds the target, so the value is
    additionally folded modulo 5 by the branch-free ``205*t >> 10`` identity;
    for ``eta = 4`` no folding is needed.
    """
    bound = 15 if eta == 2 else 9
    out: list[int] = []
    pos = 0
    want = 64 + _N // 2
    buf = shake256(seed + nonce.to_bytes(2, "little"), want)
    while len(out) < _N:
        if pos >= len(buf):
            want += 64 + _N // 2
            buf = shake256(seed + nonce.to_bytes(2, "little"), want)
        byte = buf[pos]
        pos += 1
        for nibble in (byte & 0x0F, byte >> 4):
            if nibble >= bound or len(out) >= _N:
                continue
            # For eta = 2 the accepted nibble can reach 14, so fold it back into
            # [0, 4] first; 205*t>>10 is the branch-free modulo 5 reduction.
            value = (nibble - (205 * nibble >> 10) * 5) if eta == 2 else nibble
            out.append(eta - value)
    return [c % Q for c in out]


def _poly_uniform_gamma1(gamma1: int, seed: bytes, nonce: int) -> list[int]:
    """FIPS 204 Algorithm 34 ``SamplePolyUniformGamma1``.

    The 17/19 bit limbs of ``SHAKE256(seed || nonce)`` are read little-endian
    and reflected as ``gamma1 - v``, giving a sample in ``[-(gamma1-1), gamma1]``.
    """
    bits = _bitlen(gamma1 - 1)
    raw = shake256(seed + nonce.to_bytes(2, "little"), _N * bits // 8)
    values = bitunpack(raw, bits, _N, 0)
    return [(gamma1 - v) % Q for v in values]


def _ntt(poly: Sequence[int]) -> list[int]:
    """FIPS 204 Algorithm 41 ``NTT``: coefficient domain to the zeta domain.

    The transform is the plain negacyclic Cooley-Tukey network of FIPS 204 with
    the ``zetas`` table; no Montgomery factor is applied to the output, so this
    is a bijection of ``R_q`` exactly like the reference.
    """
    r = [c % Q for c in poly]
    layer, index = 1, 1
    while layer <= 8:
        length = _N >> layer
        for start in range(0, _N, 2 * length):
            zeta = _ZETAS[index]
            index += 1
            for j in range(start, start + length):
                t = _montgomery_reduce(r[j + length] * zeta)
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
        layer += 1
    return r


def _inv_ntt(poly: Sequence[int]) -> list[int]:
    """FIPS 204 Algorithm 42 ``NTT^-1``: zeta domain back to the coefficient domain."""
    r = [c % Q for c in poly]
    layer, index = 8, _N
    while layer >= 1:
        length = _N >> layer
        for start in range(0, _N, 2 * length):
            index -= 1
            zeta = -_ZETAS[index]
            for j in range(start, start + length):
                t = r[j]
                u = r[j + length]
                r[j] = (t + u) % Q
                r[j + length] = _montgomery_reduce((t - u) * zeta)
        layer -= 1
    factor = _montgomery_reduce(_MONT) * pow(_N, -1, Q) % Q
    return [c * factor % Q for c in r]


def _montgomery_reduce(a: int) -> int:
    """FIPS 204 Algorithm 49 ``MontgomeryReduce``: ``a * R^-1 mod q`` for ``R = 2^32``."""
    t = ((a % _MONT) * _Q_INV) % _MONT
    if t >= 1 << 31:
        t -= _MONT
    return (a - t * Q) >> 32


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
    """FIPS 204 Algorithm 16 ``Power2Round``: ``r -> (r1, r0)``, ``r = r1*2^13 + r0``.

    ``r`` must be a standard representative in ``[0, q)``.  The invariant is
    ``-2^12 < r0 <= 2^12``, which is what makes the 13 bit packing of ``t0`` and
    the 10 bit packing of ``t1`` injective.  Ties resolve downwards, i.e.
    ``r1 = (r + 2^(d-1) - 1) >> d``.
    """
    rp = r % Q
    r1 = (rp + (1 << (D - 1)) - 1) >> D
    r0 = rp - (r1 << D)
    return r1, r0


def _decompose(r: int, gamma2: int) -> tuple[int, int]:
    """FIPS 204 Algorithm 20 ``Decompose``: ``r -> (r1, r0)``, ``r = r1*a + r0``.

    ``a = 2*gamma2``.  ``r1`` is the nearest quotient with ties resolved upwards
    and is then folded back into ``[0, (q-1)//a]``; ``r0 = r - r1*a`` is returned
    as a **signed** integer in ``(-a/2, a/2]`` (the folded top residue instead
    lands near ``-q/2``).  That window is what :func:`_make_hint` and
    :func:`_use_hint` reason about, and the fold is what lets ``UseHint`` wrap
    from the top high-bit value back to ``0``.
    """
    alpha = 2 * gamma2
    modulus = (Q - 1) // alpha
    rp = r % Q
    a1 = (rp + gamma2) // alpha
    if a1 >= modulus:
        # The top bucket would run past q; fold it onto zero and let a0 carry
        # the (negative) residue, matching the reference's wrap-around case.
        a1 = 0
    a0 = rp - a1 * alpha
    if a0 > Q // 2:
        a0 -= Q
    return a1, a0


def _high_bits(poly: Sequence[int], gamma2: int) -> list[int]:
    return [_decompose(c, gamma2)[0] for c in poly]


def _low_bits(poly: Sequence[int], gamma2: int) -> list[int]:
    return [_decompose(c, gamma2)[1] for c in poly]


def _make_hint(a0: int, a1: int, gamma2: int) -> int:
    """FIPS 204 Algorithm 22 ``MakeHint``.

    Returns ``1`` when the low part ``a0`` overflows the ``(-gamma2, gamma2]``
    window that :func:`_use_hint` can repair with a single step, else ``0``.
    """
    if a0 > gamma2 or a0 < -gamma2:
        return 1
    if a0 == -gamma2 and a1 != 0:
        return 1
    return 0


def _use_hint(hint: int, r: int, gamma2: int) -> int:
    """FIPS 204 Algorithm 23 ``UseHint``: repair the high bits of ``r``."""
    a1, a0 = _decompose(r, gamma2)
    if hint == 0:
        return a1
    modulus = (Q - 1) // (2 * gamma2)
    if a0 > 0:
        return (a1 + 1) % modulus
    return (a1 - 1) % modulus


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
    """FIPS 204 Algorithm 24 ``w1Encode``: 6 bits per committed high bit."""
    return bitpack(6, [c % 64 for c in poly])


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
        # t1 is a plain 10 bit unsigned limb: read it raw, with no bias.
        t1.append(bitunpack(pk[offset:offset + stride], params.t1_bits, _N, 0))
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
    eta_mod = 1 << params.eta_bits
    for poly in s1 + s2:
        # Coefficients live in Z_q but are bounded by eta, so they must be
        # centred before the biased encoding ``eta - a`` is applied.
        out += bitpack(params.eta_bits,
                       [(params.eta - centered(c, Q)) % eta_mod for c in poly])
    for poly in t0:
        # FIPS 204 stores t0 as the limb ``2^(d-1) - t0``, which lands inside
        # d bits for every t0 in (-2^(d-1), 2^(d-1)] and needs no sign bit.
        out += bitpack(D, [((1 << (D - 1)) - centered(c, Q)) % (1 << D) for c in poly])
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
    eta_stride = MLDSAParams._packed(params.eta_bits)
    d_stride = MLDSAParams._packed(D)
    for _ in range(params.ell):
        s1.append([params.eta - v for v in bitunpack(
            sk[offset:offset + eta_stride], params.eta_bits, _N, 0)])
        offset += eta_stride
    for _ in range(params.k):
        s2.append([params.eta - v for v in bitunpack(
            sk[offset:offset + eta_stride], params.eta_bits, _N, 0)])
        offset += eta_stride
    for _ in range(params.k):
        # Undo the ``2^(d-1) - t0`` reflection applied by :func:`_sk_encode`.
        t0.append([((1 << (D - 1)) - v) % Q
                   for v in bitunpack(sk[offset:offset + d_stride], D, _N, 0)])
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
    hints: bytearray,
) -> bytes:
    packed_z = b"".join(
        bitpack(params.z_bits, [(centered(c, Q) + params.gamma1) % (1 << params.z_bits)
                                for c in poly])
        for poly in z
    )
    return c_tilde + packed_z + bytes(hints)


def _hint_pack(params: MLDSAParams, hints: Sequence[Sequence[int]]) -> bytes:
    """FIPS 204 Algorithm 17 ``Hint``: ``omega`` index bytes plus ``k`` counters."""
    out = bytearray(params.omega)
    counts = bytearray(params.k)
    index = 0
    for i, poly in enumerate(hints):
        for j in range(_N):
            if poly[j]:
                if index >= params.omega:
                    raise ValueError("hint weight exceeds omega")
                out[index] = j
                index += 1
        counts[i] = index
    return bytes(out + counts)


def _hint_unpack(params: MLDSAParams, raw: bytes) -> list[list[int]] | None:
    """FIPS 204 Algorithm 18 ``HintBitUnpack``; ``None`` when malformed.

    ``raw`` is ``omega`` index bytes followed by ``k`` cumulative counters.  The
    counters must be non-decreasing, the last must not exceed ``omega``, the
    unused index slots must be zero (this is what buys strong unforgeability),
    and the indices inside one row must be strictly increasing.
    """
    omega, k = params.omega, params.k
    if len(raw) != omega + k:
        return None
    indices = list(raw[:omega])
    bounds = list(raw[omega:])
    if bounds[-1] > omega:
        return None
    if any(b < a for a, b in zip(bounds, bounds[1:])):
        return None
    if any(indices[bounds[-1]:omega]):
        return None
    hints = [[0] * _N for _ in range(k)]
    start = 0
    for i in range(k):
        row = indices[start:bounds[i]]
        if any(row[j] >= row[j + 1] for j in range(len(row) - 1)):
            return None
        for index in row:
            hints[i][index] = 1
        start = bounds[i]
    return hints


def _sig_decode(params: MLDSAParams, sig: bytes):
    c_len = params.c_tilde_len
    z_len = params.ell * _N * params.z_bits // 8
    hint_len = params.omega + params.k
    if len(sig) != c_len + z_len + hint_len:
        raise ValueError(f"signature must be {params.sig_len} bytes")
    c_tilde = sig[:c_len]
    raw_z = sig[c_len:c_len + z_len]
    hints = _hint_unpack(params, sig[c_len + z_len:])
    bits = params.z_bits
    z = []
    per = _N * bits // 8
    for i in range(params.ell):
        block = raw_z[i * per:(i + 1) * per]
        values = bitunpack(block, bits, _N, 0)
        z.append([(v - params.gamma1) % Q for v in values])
    return c_tilde, z, hints


# --------------------------------------------------------------------------- #
# Key generation (FIPS 204 Algorithm 6)                                        #
# --------------------------------------------------------------------------- #
def keypair_from_seed(params: MLDSAParams, xi: bytes) -> tuple[bytes, bytes]:
    """Deterministic key generation from a 32 byte seed ``xi``."""
    if len(xi) != 32:
        raise ValueError("seed must be 32 bytes")
    k = params.k
    # FIPS 204 Algorithm 6: one expansion step yields all three secrets.
    #   (rho, rho', K) <- H(xi || IntegerToBytes(k,1) || IntegerToBytes(l,1), 128)
    expanded = _xof(xi + bytes((k, params.ell)), 128)
    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:128]

    s1 = [_poly_uniform_eta(params.eta, rho_prime, i) for i in range(params.ell)]
    s2 = [_poly_uniform_eta(params.eta, rho_prime, params.ell + i) for i in range(k)]

    # A is k x ell in FIPS 204, so t = A s1 + s2 sums over the ell real columns.
    t = []
    for i in range(k):
        acc = list(s2[i])
        for j in range(params.ell):
            acc = [(x + y) % Q for x, y in
                   zip(acc, _ntt_mul_coeff(_matrix_entry(rho, i, j), s1[j]))]
        t.append(acc)

    t1 = []
    t0 = []
    for poly in t:
        # FIPS 204 splits the *public* value with Power2Round (alpha = 2^13),
        # not with Decompose: that is what makes t1 a 10 bit field.
        t1.append([_power2round(c)[0] for c in poly])
        t0.append([_power2round(c)[1] for c in poly])

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
def _message_prefix(message: bytes, ctx: bytes) -> bytes:
    """FIPS 204 Algorithm 2: ``M' = 0x00 || len(ctx) || ctx || M``."""
    if len(ctx) > 255:
        raise ValueError("context string must be at most 255 bytes")
    return b"\x00" + bytes((len(ctx),)) + ctx + message


def sign_internal(
    params: MLDSAParams,
    sk: bytes,
    prefixed: bytes,
    rnd: bytes,
) -> bytes:
    """FIPS 204 Algorithm 7 ``ML-DSA.Sign_internal`` over an already-prefixed message."""
    obj = _sk_decode(params, sk)
    tr = obj["tr"]
    mu = _xof(tr + prefixed, 64)
    rho_pp = _xof(obj["key"] + rnd + mu, 64)

    gamma1, gamma2, beta = params.gamma1, params.gamma2, params.beta
    rho = obj["rho"]
    kappa = 0
    for _ in range(_SIGN_ATTEMPT_LIMIT):
        y = [_poly_uniform_gamma1(gamma1, rho_pp, kappa + i) for i in range(params.ell)]

        # w = A y.  A lives in the transformed domain, so y must be transformed too.
        y_hat = [_ntt(poly) for poly in y]
        w = []
        for i in range(params.k):
            acc = [0] * _N
            for j in range(params.ell):
                acc = [(a + b) % Q for a, b in
                       zip(acc, _ntt_mul(_matrix_entry(rho, i, j), y_hat[j]))]
            w.append(_inv_ntt(acc))

        w1 = [_high_bits(poly, gamma2) for poly in w]
        c_tilde = _xof(mu + b"".join(_w1_encode(poly) for poly in w1), params.c_tilde_len)
        c_hat = _ntt(_sample_in_ball(c_tilde, params.tau))

        # z = y + c*s1
        z = []
        for i in range(params.ell):
            correction = _inv_ntt(_ntt_mul(c_hat, obj["s1_hat"][i]))
            z.append([(a + b) % Q for a, b in zip(y[i], correction)])

        # w0 = LowBits(w), then w0 -= c*s2 (in place), which is exactly the
        # rejection-sampling quantity the specification calls r0.
        w0 = [_low_bits(poly, gamma2) for poly in w]
        for i in range(params.k):
            correction = _inv_ntt(_ntt_mul(c_hat, obj["s2_hat"][i]))
            w0[i] = [centered(a - b, Q) for a, b in zip(w0[i], correction)]

        if _max_abs([c for poly in z for c in poly]) >= gamma1 - beta or \
                _max_abs([c for poly in w0 for c in poly]) >= gamma2 - beta:
            kappa += params.ell
            continue

        # c*t0 must stay inside the repair window, and the hint vector must fit
        # in omega bits; together these guarantee the verifier can recover w1.
        ct0 = [_inv_ntt(_ntt_mul(c_hat, obj["t0_hat"][i])) for i in range(params.k)]
        if _max_abs([c for poly in ct0 for c in poly]) >= gamma2:
            kappa += params.ell
            continue

        hints: list[list[int]] = []
        weight = 0
        for i in range(params.k):
            row = []
            for j in range(_N):
                # MakeHint(a0 = w0 - cs2 + ct0, a1 = HighBits(w))
                a0 = centered(w0[i][j] + ct0[i][j], Q)
                bit = _make_hint(a0, w1[i][j], gamma2)
                row.append(bit)
                weight += bit
            hints.append(row)
        if weight > params.omega:
            kappa += params.ell
            continue

        return _sig_encode(params, c_tilde, z, _hint_pack(params, hints))

    raise RuntimeError("ML-DSA signing exceeded the FIPS 204 iteration limit")


def sign(
    params: MLDSAParams | str,
    sk: bytes,
    message: bytes,
    *,
    rnd: bytes | None = None,
    ctx: bytes = b"",
) -> bytes:
    """Produce a randomised signature over ``message``."""
    if isinstance(params, str):
        params = get_mldsa(params)
    if rnd is None:
        rnd = random_bytes(32)
    if len(rnd) != 32:
        raise ValueError("rnd must be 32 bytes")
    return sign_internal(params, sk, _message_prefix(message, ctx), rnd)


# --------------------------------------------------------------------------- #
# Verification (FIPS 204 Algorithm 8)                                           #
# --------------------------------------------------------------------------- #
def verify_internal(
    params: MLDSAParams,
    pk: bytes,
    prefixed: bytes,
    signature: bytes,
) -> bool:
    """FIPS 204 Algorithm 8 ``ML-DSA.Verify_internal`` over a prefixed message."""
    if len(pk) != params.pk_len or len(signature) != params.sig_len:
        return False
    try:
        rho, t1 = _pk_decode(params, pk)
        c_tilde, z, hints = _sig_decode(params, signature)
    except ValueError:
        return False
    if hints is None:
        return False

    gamma1, gamma2, beta = params.gamma1, params.gamma2, params.beta
    if _max_abs([c for poly in z for c in poly]) >= gamma1 - beta:
        return False

    mu = _xof(_xof(pk, 64) + prefixed, 64)
    c_hat = _ntt(_sample_in_ball(c_tilde, params.tau))
    t1_hat = [_ntt(poly) for poly in t1]

    w1_bytes = bytearray()
    z_hat = [_ntt(poly) for poly in z]
    for i in range(params.k):
        acc = [0] * _N
        for j in range(params.ell):
            acc = [(a + b) % Q for a, b in
                   zip(acc, _ntt_mul(_matrix_entry(rho, i, j), z_hat[j]))]
        # w'_approx = A z - c * (t1 * 2^d).  The 2^d shift belongs to the
        # *coefficient* polynomial, so it must be applied before the NTT.
        t1_scaled = _ntt([(c * (1 << D)) % Q for c in t1[i]])
        acc = _inv_ntt([(a - b) % Q for a, b in zip(acc, _ntt_mul(c_hat, t1_scaled))])
        w1_bytes += _w1_encode([_use_hint(hints[i][j], acc[j], gamma2)
                                for j in range(_N)])

    return ct_eq(c_tilde, _xof(mu + bytes(w1_bytes), params.c_tilde_len))


def verify(
    params: MLDSAParams | str,
    pk: bytes,
    message: bytes,
    signature: bytes,
    *,
    ctx: bytes = b"",
) -> bool:
    """Verify ``signature`` over ``message``; returns ``False`` on any failure."""
    if isinstance(params, str):
        params = get_mldsa(params)
    if len(ctx) > 255:
        return False
    return verify_internal(params, pk, _message_prefix(message, ctx), signature)


def verify_strict(
    params: MLDSAParams | str,
    pk: bytes,
    message: bytes,
    signature: bytes,
    *,
    ctx: bytes = b"",
) -> None:
    """Like :func:`verify` but raises :class:`InvalidSignature` on failure."""
    if not verify(params, pk, message, signature, ctx=ctx):
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