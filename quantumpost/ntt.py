"""Negacyclic Number Theoretic Transform for lattice schemes.

Both ML-KEM (FIPS 203) and ML-DSA (FIPS 204) work in
``R_q = Z_q[X] / (X^256 + 1)`` with degree-255 polynomials.  A negacyclic
convolution of length ``n`` over ``Z_q`` is the diagonalisable operation
``X -> zeta`` for a primitive ``2n``-th root of unity ``zeta`` modulo ``q``,
so such a transform exists **only if** ``2n`` divides ``q - 1``.  That condition
differs between the two standards and drives the whole design of this module:

``q = 8380417`` (ML-DSA)
    ``q - 1 = 2^23 * 999``; since ``512 | q - 1`` a primitive 512-th root of
    unity exists and a direct 256-point negacyclic NTT is available.  This is
    the classical transform used by CRYSTALS-Dilithium.

``q = 3329`` (ML-KEM)
    ``q - 1 = 2^8 * 13``; ``512`` does **not** divide ``q - 1``, so no
    primitive 512-th root of unity exists and a 256-point negacyclic transform
    is impossible over ``Z_3329``.  The standard resolves this with a two-level
    construction: writing ``X^256 = -1`` as ``(X^2)^128 = -1`` and splitting
    each polynomial into even/odd powers gives ``Y = X^2``, where ``Y^128 = -1``.
    Multiplication in ``R_q`` then reduces to **three** 128-point negacyclic
    convolutions, and ``128``-point negacyclic transforms *do* exist because a
    primitive 256-th root of unity does (``256 | q - 1``).

The implementation below therefore provides:

* :class:`NegacyclicNTT` - a direct transform for any ``(q, n)`` where
  ``2n | q - 1`` (used by ML-DSA);
* :func:`mlkem_mul` - the even/odd reduction with three 128-point transforms,
  used by ML-KEM;
* :func:`schoolbook_mul` - an independent reference oracle.

Every fast path is cross-checked against :func:`schoolbook_mul` by the
test-suite, so a mistake in the twiddle schedule cannot go unnoticed.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Sequence

__all__ = [
    "N",
    "NegacyclicNTT",
    "get_ntt",
    "mlkem_mul",
    "mlkem_transform",
    "schoolbook_mul",
    "centered",
    "inf_norm",
    "has_direct_ntt",
    "ring_decomposition",
]

N = 256  # ring degree, fixed by FIPS 203 and FIPS 204


# --------------------------------------------------------------------------- #
# Scalar helpers                                                              #
# --------------------------------------------------------------------------- #
def centered(coeff: int, modulus: int) -> int:
    """Map ``coeff`` to the symmetric representative in ``(-q/2, q/2]``."""
    value = coeff % modulus
    return value - modulus if value > modulus // 2 else value


def inf_norm(poly: Sequence[int], modulus: int | None = None) -> int:
    """Infinity norm with symmetric representatives - the security workhorse."""
    mod = modulus or 8380417
    return max((abs(centered(c, mod)) for c in poly), default=0)


def schoolbook_mul(a: Sequence[int], b: Sequence[int], modulus: int) -> list[int]:
    """Multiply in ``Z_q[X]/(X^256+1)`` by explicit convolution.

    This is the ground-truth oracle: it has no twiddle factors, no index
    subtleties and no normalisation convention, so it can validate any fast
    implementation.  Cost is ``O(n^2)`` which is acceptable in tests.
    """
    if len(a) != N or len(b) != N:
        raise ValueError(f"polynomials must have degree {N - 1}")
    acc = [0] * (2 * N)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                acc[i + j] += ai * bj
    return [(acc[i] - acc[i + N]) % modulus for i in range(N)]


# --------------------------------------------------------------------------- #
# Direct negacyclic NTT (requires 2n | q - 1)                                 #
# --------------------------------------------------------------------------- #
class NegacyclicNTT:
    """Negacyclic NTT of degree ``n`` when ``2n`` divides ``q - 1``.

    The transform is a plain Cooley-Tukey butterfly network driven by
    ``zeta ** brv(k)`` twiddles, with an inverse that reuses the same table in
    descending order - exactly the structure of FIPS 203 Alg. 9/10 and
    FIPS 204 Alg. 9/10, but parameterised by a verified root of unity rather than
    a hard-coded constant.  :attr:`supported` reports whether the modulus
    admits the required root, so callers can never silently use an invalid
    transform.
    """

    __slots__ = ("q", "n", "zetas", "root", "supported", "_n_inv")

    def __init__(self, modulus: int, n: int = N) -> None:
        if n & (n - 1):
            raise ValueError("degree must be a power of two")
        self.q = modulus
        self.n = n
        self.supported = (modulus - 1) % (2 * n) == 0
        self.zetas: list[int] = []
        self.root = 0
        self._n_inv = pow(modulus - 1, -1, modulus)
        if not self.supported:
            return
        root = self._find_root(modulus, 2 * n)
        if root is None:  # pragma: no cover - group theory guarantees this
            raise ValueError(f"no primitive {2 * n}-th root of unity modulo {modulus}")
        self.root = root
        bits = n.bit_length() - 1
        self.zetas = [1] * n
        for k in range(1, n):
            rev = int(format(k, f"0{bits}b")[::-1], 2)
            self.zetas[k] = pow(root, rev, modulus)

    @staticmethod
    def _find_root(modulus: int, order: int) -> int | None:
        """Locate an element of *exactly* the requested multiplicative order."""
        if (modulus - 1) % order:
            return None
        exponent = (modulus - 1) // order
        for candidate in (17, 62, 1753, 23, 45, 3, 5, 7, 11, 13, 19, 29, 31, 37):
            root = pow(candidate, exponent, modulus)
            if pow(root, order // 2, modulus) == modulus - 1:
                return root
        return None  # pragma: no cover

    def forward(self, poly: Sequence[int]) -> list[int]:
        """Forward transform (no normalisation is applied)."""
        if not self.supported:  # pragma: no cover - guarded by callers
            raise RuntimeError(f"modulus {self.q} does not admit a degree-{self.n} negacyclic NTT")
        if len(poly) != self.n:
            raise ValueError(f"polynomial must have {self.n} coefficients")
        q, coeffs = self.q, list(poly)
        length = self.n // 2
        k = 1
        while length >= 1:
            start = 0
            span = length * 2
            while start < self.n:
                zeta = self.zetas[k]
                k += 1
                for j in range(start, start + length):
                    t = zeta * coeffs[j + length] % q
                    coeffs[j + length] = (coeffs[j] - t) % q
                    coeffs[j] = (coeffs[j] + t) % q
                start += span
            length >>= 1
        return coeffs

    def inverse(self, poly: Sequence[int]) -> list[int]:
        """Inverse transform, including the ``1/n`` normalisation."""
        if not self.supported:  # pragma: no cover
            raise RuntimeError(f"modulus {self.q} does not admit a degree-{self.n} negacyclic NTT")
        q, coeffs = self.q, list(poly)
        length = 1
        k = self.n - 1
        while length < self.n:
            start = 0
            span = length * 2
            while start < self.n:
                zeta = self.zetas[k]
                k -= 1
                for j in range(start, start + length):
                    t = coeffs[j]
                    coeffs[j] = (t + coeffs[j + length]) % q
                    coeffs[j + length] = zeta * (coeffs[j + length] - t) % q
                start += span
            length <<= 1
        n_inv = pow(self.n, q - 2, q)
        return [c * n_inv % q for c in coeffs]

    def mul(self, a: Sequence[int], b: Sequence[int]) -> list[int]:
        """Multiply two polynomials given in the transformed domain."""
        return self.inverse([x * y % self.q for x, y in zip(a, b)])


_DILITHIUM = NegacyclicNTT(8380417, N)
_KYBER_HALF = NegacyclicNTT(3329, N // 2)


@lru_cache(maxsize=1)
def _kyber_even_odd_matrix() -> tuple[tuple[int, ...], ...]:
    """Return the 128 x 128 matrix of multiplication by ``Y`` in the NTT basis.

    ``Y = X^2`` is the shift-with-sign-flip operator in ``Z_q[Y]/(Y^128 + 1)``.
    In the evaluation basis of a negacyclic NTT, any ring multiplication is
    diagonal, so this conjugate matrix is diagonal with eigenvalues equal to the
    128 evaluation points - which lets ML-KEM's Karatsuba reduction run
    entirely inside the transformed domain.
    """
    n = N // 2
    columns = []
    for i in range(n):
        seed = [0] * n
        seed[i] = 1
        columns.append(_KYBER_HALF.forward(_negacyclic_times_y(_KYBER_HALF.inverse(seed), 3329)))
    return tuple(tuple(columns[i][i] for i in range(n)) for _ in (0,))


def _negacyclic_times_y(poly: Sequence[int], modulus: int) -> list[int]:
    """Multiply by ``Y`` in ``Z_modulus[Y]/(Y^n + 1)``: shift with sign flip."""
    n = len(poly)
    return [(-poly[n - 1]) % modulus] + [poly[i] % modulus for i in range(n - 1)]


_KYBER_EVEN_ODD_DIAG = _kyber_even_odd_matrix()[0]


def has_direct_ntt(modulus: int, n: int = N) -> bool:
    """Whether a direct degree-``n`` negacyclic NTT exists modulo ``modulus``."""
    return (modulus - 1) % (2 * n) == 0


def get_ntt(modulus: int) -> NegacyclicNTT | None:
    """Return a cached direct NTT instance, or ``None`` if unsupported."""
    if modulus == 8380417:
        return _DILITHIUM
    if modulus == 3329:
        return None  # requires the two-level reduction below
    ntt = NegacyclicNTT(modulus, N)
    return ntt if ntt.supported else None


def ring_decomposition() -> str:
    """Human readable description of the ML-KEM ring reduction strategy."""
    return (
        "Z_3329[X]/(X^256+1): 512 does not divide q-1, so multiplication is "
        "reduced via Y = X^2 to three 128-point negacyclic convolutions "
        "(256 | q-1 admits the required root of unity)."
    )


# --------------------------------------------------------------------------- #
# ML-KEM: even/odd reduction to three 128-point negacyclic convolutions       #
# --------------------------------------------------------------------------- #
def _split_even_odd(poly: Sequence[int], modulus: int) -> tuple[list[int], list[int]]:
    """Return ``(a_even, a_odd)`` with ``a(X^2) = a_even(Y) + X a_odd(Y)``."""
    half = len(poly) // 2
    even = [poly[2 * i] % modulus for i in range(half)]
    odd = [poly[2 * i + 1] % modulus for i in range(half)]
    return even, odd


def _combine_even_odd(
    even: Sequence[int], odd: Sequence[int], modulus: int
) -> list[int]:
    """Inverse of :func:`_split_even_odd`."""
    half = len(even)
    out = [0] * (2 * half)
    for i in range(half):
        out[2 * i] = even[i] % modulus
        out[2 * i + 1] = odd[i] % modulus
    return out


def mlkem_transform(poly: Sequence[int]) -> list[int]:
    """Map a coefficient-domain polynomial into the ML-KEM working domain.

    The working domain is the pair of 128-point NTTs of the even and odd
    components.  The map is a bijection (its inverse is
    :func:`mlkem_transform_inverse`), which is all the public key encoding
    requires, and :func:`mlkem_mul` is the matching multiplication.
    """
    even, odd = _split_even_odd(poly, 3329)
    return _KYBER_HALF.forward(even) + _KYBER_HALF.forward(odd)


def mlkem_transform_inverse(values: Sequence[int]) -> list[int]:
    """Inverse of :func:`mlkem_transform`."""
    half = len(values) // 2
    even = _KYBER_HALF.inverse(values[:half])
    odd = _KYBER_HALF.inverse(values[half:])
    return _combine_even_odd(even, odd, 3329)


def _times_y(poly: Sequence[int], modulus: int) -> list[int]:
    """Multiply by ``Y`` in ``Z_q[Y]/(Y^n+1)``: shift with a wrap-around sign flip."""
    return _negacyclic_times_y(poly, modulus)


def _times_y_domain(values: Sequence[int]) -> list[int]:
    """Multiply by ``Y`` acting on 128-point NTT-domain values."""
    return [x * d % 3329 for x, d in zip(values, _KYBER_EVEN_ODD_DIAG)]


def mlkem_mul_domain(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Multiply two *transformed* ML-KEM polynomials.

    ``a`` and ``b`` are :func:`mlkem_transform` images (256 values = the two
    128-point NTTs of the even and odd components).  The result is again a
    transformed value, so a whole keygen/encaps can run without ever leaving
    the domain.

    Uses Karatsuba on ``(ae, ao)`` and (be, bo)``:

    ``even = ae*be + Y*ao*bo`` and ``odd = (ae+ao)(be+bo) - ae*be - ao*bo``

    which costs three 128-point negacyclic convolutions instead of four.
    """
    c0 = [x * y % 3329 for x, y in zip(a[:128], b[:128])]
    c2 = [x * y % 3329 for x, y in zip(a[128:], b[128:])]
    cross = [x * y % 3329 for x, y in zip(
        [(p + q_) % 3329 for p, q_ in zip(a[:128], a[128:])],
        [(p + q_) % 3329 for p, q_ in zip(b[:128], b[128:])],
    )]
    even = [(x + y) % 3329 for x, y in zip(c0, _times_y_domain(c2))]
    odd = [(s - x - y) % 3329 for s, x, y in zip(cross, c0, c2)]
    return even + odd


def mlkem_add_domain(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Addition of two transformed ML-KEM polynomials."""
    return [(x + y) % 3329 for x, y in zip(a, b)]


def mlkem_sub_domain(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Subtraction of two transformed ML-KEM polynomials."""
    return [(x - y) % 3329 for x, y in zip(a, b)]


def mlkem_mul(a: Sequence[int], b: Sequence[int]) -> list[int]:
    """Multiply two *coefficient-domain* ML-KEM polynomials.

    Thin wrapper over :func:`mlkem_transform_inverse` and
    :func:`mlkem_mul_domain`; the test-suite checks it against
    :func:`schoolbook_mul` over random inputs.
    """
    return mlkem_transform_inverse(
        mlkem_mul_domain(mlkem_transform(a), mlkem_transform(b))
    )