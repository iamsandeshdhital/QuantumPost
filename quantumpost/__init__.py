"""QuantumPost - dependency-free post-quantum cryptography.

An implementation of the two NIST standardised Module-Lattice primitives:

* **ML-KEM** (FIPS 203) - key encapsulation, the CRYSTALS-Kyber successor.
* **ML-DSA** (FIPS 204) - digital signatures, the CRYSTALS-Dilithium successor.

Everything is written against the Python standard library only - there are no
third-party dependencies, no C extensions and no network access - so the
package can be audited end to end and vendored anywhere Python runs.

Quick start::

    from quantumpost import mlkem, mldsa

    ek, dk = mlkem.generate_keypair("ML-KEM-768")
    shared_secret, ciphertext = mlkem.encapsulate("ML-KEM-768", ek)
    assert shared_secret == mlkem.decapsulate("ML-KEM-768", dk, ciphertext)

    pk, sk = mldsa.generate_keypair("ML-DSA-65")
    signature = mldsa.sign("ML-DSA-65", sk, b"message")
    assert mldsa.verify("ML-DSA-65", pk, b"message", signature)

A command line interface is available as ``python -m quantumpost``.
"""

from __future__ import annotations

__version__ = "1.0.0"

from quantumpost import combine, hashes, keccak_pure, mldsa, mlkem, ntt, params, utils
from quantumpost.combine import (
    classical_combine,
    hybrid_decapsulate,
    hybrid_encapsulate,
    sign_with_hybrid,
    verify_with_hybrid,
)
from quantumpost.params import (
    KEM_TLS_GROUPS,
    MLDSA_SETS,
    MLKEM_SETS,
    MLDSAParams,
    MLKEMParams,
    ParameterSet,
    get_mldsa,
    get_mlkem,
    mldsa_levels,
    mlkem_levels,
)

__all__ = [
    "__version__",
    # submodules
    "combine",
    "hashes",
    "keccak_pure",
    "mldsa",
    "mlkem",
    "ntt",
    "params",
    "utils",
    # ML-KEM
    "mlkem_generate_keypair",
    "mlkem_encapsulate",
    "mlkem_decapsulate",
    # ML-DSA
    "mldsa_generate_keypair",
    "mldsa_sign",
    "mldsa_verify",
    # hybrid
    "classical_combine",
    "hybrid_encapsulate",
    "hybrid_decapsulate",
    "sign_with_hybrid",
    "verify_with_hybrid",
    # metadata
    "ParameterSet",
    "MLKEMParams",
    "MLDSAParams",
    "KEM_TLS_GROUPS",
    "MLKEM_SETS",
    "MLDSA_SETS",
    "get_mlkem",
    "get_mldsa",
    "mlkem_levels",
    "mldsa_levels",
]

# --------------------------------------------------------------------------- #
# Flat convenience wrappers                                                      #
# --------------------------------------------------------------------------- #
def mlkem_generate_keypair(params: str = "ML-KEM-768", *, seed: bytes | None = None):
    """Generate an ML-KEM key pair ``(ek, dk)``."""
    return mlkem.generate_keypair(params, seed=seed)


def mlkem_encapsulate(params: str, ek: bytes, *, message: bytes | None = None):
    """Encapsulate to ``ek``, returning ``(shared_secret, ciphertext)``."""
    if message is None:
        return mlkem.encapsulate(params, ek)
    return mlkem.encapsulate_deterministic(params, ek, message)


def mlkem_decapsulate(params: str, dk: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ``ciphertext``, returning the shared secret."""
    return mlkem.decapsulate(params, dk, ciphertext)


def mldsa_generate_keypair(params: str = "ML-DSA-65", *, seed: bytes | None = None):
    """Generate an ML-DSA key pair ``(pk, sk)``."""
    return mldsa.generate_keypair(params, seed=seed)


def mldsa_sign(params: str, sk: bytes, message: bytes, *, rnd: bytes | None = None):
    """Sign ``message`` with ``sk``."""
    return mldsa.sign(params, sk, message, rnd=rnd)


def mldsa_verify(params: str, pk: bytes, message: bytes, signature: bytes) -> bool:
    """Verify ``signature`` over ``message``; never raises on bad input."""
    return mldsa.verify(params, pk, message, signature)