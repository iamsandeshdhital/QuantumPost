"""Hybrid key combiners and composite signing.

A post-quantum KEM alone gives no assurance against an adversary who has
*already* broken the classical component.  Deployments therefore combine a PQ
KEM with a classical KEM (X25519, P-256 ECDH, ...) using a **hybrid combiner**
that stays secure if *either* input is secure.

Only the combiner is provided here: the classical primitive stays out of scope
so that this package keeps its "standard library only" guarantee, and so the
classical side can be supplied by the host application (which will already have
a vetted, FIPS-validated ECDH implementation).

The combiner follows the well-established X-Wing construction::

    ss = SHAKE256( X || SHAKE256(X || 0x01 || len(Z) || Z || X)
                      || Y || SHAKE256(Y || 0x01 || len(Z) || Z || Y) )

where ``X`` and ``Y`` are the classical and PQ shared secrets and ``Z`` binds the
length of ``X`` so a short classical secret cannot be padded into a longer one.
"""

from __future__ import annotations

from typing import Final

from quantumpost.hashes import shake256
from quantumpost.mlkem import (
    MLKEMParams,
    decapsulate,
    encapsulate,
    encapsulate_deterministic,
)
from quantumpost.mldsa import MLDSAParams, sign, verify

__all__ = [
    "HYBRID_LABEL",
    "classical_combine",
    "hybrid_encapsulate",
    "hybrid_encapsulate_deterministic",
    "hybrid_decapsulate",
    "sign_with_hybrid",
    "verify_with_hybrid",
]

#: Domain separation label bound into every hybrid construction.
HYBRID_LABEL: Final[bytes] = b"\x01"


def _expand(secret: bytes, other: bytes) -> bytes:
    """``SHAKE256(secret || label || len(other) || other, 32)``."""
    return shake256(secret + HYBRID_LABEL + len(other).to_bytes(4, "big") + other, 32)


def classical_combine(classical_ss: bytes, pq_ss: bytes) -> bytes:
    """Combine a classical and a PQ shared secret into one 32 byte key.

    The construction is X-Wing shaped and uses a standard KDF, so the result is
    secure as long as at least one input remains secure, and an attacker who
    recovers one component learns nothing about the other.
    """
    if not classical_ss:
        raise ValueError("classical shared secret must not be empty")
    if not pq_ss:
        raise ValueError("post-quantum shared secret must not be empty")
    return shake256(
        classical_ss + _expand(classical_ss, pq_ss) + pq_ss + _expand(pq_ss, classical_ss),
        32,
    )


def hybrid_encapsulate(
    params: MLKEMParams | str,
    ek: bytes,
    classical_shared_secret: bytes,
) -> tuple[bytes, bytes]:
    """Encapsulate to ``ek`` and return ``(combined_key, ciphertext)``.

    ``classical_shared_secret`` is the result of an ECDH exchange the caller has
    already performed; this function never sees a classical private key.
    """
    pq_ss, ciphertext = encapsulate(params, ek)
    return classical_combine(classical_shared_secret, pq_ss), ciphertext


def hybrid_encapsulate_deterministic(
    params: MLKEMParams | str,
    ek: bytes,
    classical_shared_secret: bytes,
    message: bytes,
) -> tuple[bytes, bytes]:
    """Deterministic :func:`hybrid_encapsulate` for test vectors."""
    pq_ss, ciphertext = encapsulate_deterministic(params, ek, message)
    return classical_combine(classical_shared_secret, pq_ss), ciphertext


def hybrid_decapsulate(
    params: MLKEMParams | str,
    dk: bytes,
    ciphertext: bytes,
    classical_shared_secret: bytes,
) -> bytes:
    """Recover the combined key; invalid ciphertexts trigger implicit rejection."""
    return classical_combine(classical_shared_secret, decapsulate(params, dk, ciphertext))


def _bind(ctx: bytes, secret: bytes, message: bytes) -> bytes:
    """Bind a classical public value into the signed payload."""
    return ctx + len(secret).to_bytes(4, "big") + secret + message


def sign_with_hybrid(
    params: MLDSAParams | str,
    sk: bytes,
    message: bytes,
    classical_public: bytes,
    *,
    rnd: bytes | None = None,
    ctx: bytes = b"",
) -> bytes:
    """Sign ``ctx || len(pub) || pub || message`` as a single ML-DSA signature.

    Binding the *classical public key* into the signed message gives the
    composite scheme the "PQ-secure or classical-secure" property: an attacker
    who can forge classical signatures still cannot produce a valid ML-DSA
    signature over the same transcript.  The classical private key is never
    involved, so the signer never has to hand it to this module.
    """
    return sign(params, sk, _bind(ctx, classical_public, message), rnd=rnd)


def verify_with_hybrid(
    params: MLDSAParams | str,
    pk: bytes,
    message: bytes,
    classical_public: bytes,
    signature: bytes,
    *,
    ctx: bytes = b"",
) -> bool:
    """Verify a signature produced by :func:`sign_with_hybrid`."""
    return verify(params, pk, _bind(ctx, classical_public, message), signature, ctx=ctx)