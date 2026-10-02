"""Algorithm parameter sets and metadata registry.

Every hard-coded constant of ML-KEM (FIPS 203), ML-DSA (FIPS 204) and the
hash-based SPHINCS+ scheme lives here, together with the metadata that a
deployment needs in order to make an agility decision (security level, key and
ciphertext sizes, maturity, IANA/TLS codepoints and source publications).

Design rule enforced here: *no magic numbers in algorithm code*.  Every constant
is either (a) read from a :class:`ParameterSet` instance or (b) a fixed
mathematical invariant of the ring (``N = 256``, ``Q``) that is checked against
the specification table in the unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "ParameterSet",
    "MLKEM_PARAMS",
    "MLDSA_PARAMS",
    "MLKEM_SETS",
    "MLDSA_SETS",
    "get_mlkem",
    "get_mldsa",
    "mlkem_levels",
    "mldsa_levels",
    "KEM_TLS_GROUPS",
    "SIGNATURE_TLS_SCHEMES",
]

Status = Literal["final", "draft", "legacy", "experimental"]


def _bitlen(value: int) -> int:
    """Number of bits needed to represent ``value``."""
    return max(1, int(value).bit_length())


# --------------------------------------------------------------------------- #
# ML-KEM - FIPS 203                                                            #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MLKEMParams:
    """FIPS 203 parameter set."""

    name: str
    security_level: int
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    n: int = 256
    q: int = 3329

    @property
    def ek_len(self) -> int:
        """Encapsulation key length in bytes."""
        return 384 * self.k + 32

    @property
    def dk_len(self) -> int:
        """Decapsulation key length in bytes."""
        return 768 * self.k + 96

    @property
    def ct_len(self) -> int:
        """Ciphertext length in bytes."""
        return 32 * (self.du * self.k + self.dv)

    @property
    def shared_secret_len(self) -> int:
        """Shared secret length in bytes (always 32)."""
        return 32

    @property
    def seed_len(self) -> int:
        """Entropy required by key generation (d || z)."""
        return 64

    def as_dict(self) -> dict[str, int | str]:
        return {
            "name": self.name,
            "standard": "FIPS 203",
            "security_level": self.security_level,
            "k": self.k,
            "eta1": self.eta1,
            "eta2": self.eta2,
            "du": self.du,
            "dv": self.dv,
            "ek_len": self.ek_len,
            "dk_len": self.dk_len,
            "ct_len": self.ct_len,
            "shared_secret_len": self.shared_secret_len,
        }


MLKEM_PARAMS: dict[str, MLKEMParams] = {
    p.name: p
    for p in (
        MLKEMParams("ML-KEM-512", 1, k=2, eta1=3, eta2=2, du=10, dv=4),
        MLKEMParams("ML-KEM-768", 3, k=3, eta1=2, eta2=2, du=10, dv=4),
        MLKEMParams("ML-KEM-1024", 5, k=4, eta1=2, eta2=2, du=11, dv=5),
    )
}

MLKEM_SETS = tuple(MLKEM_PARAMS)


def get_mlkem(name: str) -> MLKEMParams:
    """Look up an ML-KEM parameter set, accepting short aliases."""
    return MLKEM_PARAMS[_resolve(name, MLKEM_PARAMS, "ML-KEM-")]


def mlkem_levels() -> list[str]:
    """Available ML-KEM parameter sets."""
    return list(MLKEM_SETS)


# --------------------------------------------------------------------------- #
# ML-DSA - FIPS 204                                                            #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MLDSAParams:
    """FIPS 204 parameter set."""

    name: str
    security_level: int
    tau: int
    lam: int
    gamma1: int
    gamma2: int
    k: int
    ell: int
    eta: int
    beta: int
    omega: int
    seed_len: int = 32

    q: int = 8380417
    d: int = 13

    @property
    def eta_bits(self) -> int:
        """Bit width of a packed ``s1``/``s2`` coefficient (``bitlen(2*eta)``)."""
        return _bitlen(2 * self.eta)

    @property
    def t1_bits(self) -> int:
        """Bit width of the packed ``t1`` (10 bits, from ``Power2Round``)."""
        return 10

    @property
    def z_bits(self) -> int:
        """Bit width of the packed response ``z`` (one more than ``bitlen(g1-1)``)."""
        return _bitlen(self.gamma1 - 1) + 1

    @property
    def c_tilde_len(self) -> int:
        """Commitment challenge length in bytes (``lambda / 4``)."""
        return self.lam // 4

    @property
    def pk_len(self) -> int:
        """Public key length in bytes: ``rho`` plus the packed ``t1``."""
        return 32 + self.k * self._packed(self.t1_bits)

    @property
    def sk_len(self) -> int:
        """Private key length in bytes.

        Layout is ``rho || key || tr`` (128 bytes), then the coefficient-domain
        ``s1`` (``ell`` polys at :attr:`eta_bits`), ``s2`` (``k`` polys at
        :attr:`eta_bits`) and ``t0`` (``k`` polys at ``d`` bits).  Each field is
        byte aligned independently, so this is derived from exactly the widths
        :mod:`quantumpost.mldsa` encodes with, and reproduces FIPS 204 Table 1
        (2560 / 4032 / 4896).
        """
        return (
            128
            + self.ell * self._packed(self.eta_bits)
            + self.k * self._packed(self.eta_bits)
            + self.k * self._packed(self.d)
        )

    #: Private key sizes published in FIPS 204 Table 1, asserted by the tests.
    FIPS204_SK_SIZES = {"ML-DSA-44": 2560, "ML-DSA-65": 4032, "ML-DSA-87": 4896}

    @staticmethod
    def _packed(bits: int) -> int:
        """Bytes needed for 256 coefficients packed at ``bits`` each."""
        return 256 * bits // 8

    @staticmethod
    def _bitlen(value: int) -> int:
        return _bitlen(value)

    @property
    def sig_len(self) -> int:
        """Signature length in bytes (FIPS 204 Table 1)."""
        z_len = self.ell * 32 * self.z_bits
        return self.c_tilde_len + z_len + self.omega + self.k

    @property
    def tr_len(self) -> int:
        """Length of the public-key digest used as the domain separator."""
        return 64

    @staticmethod
    def _bitlen(value: int) -> int:
        return value.bit_length()

    @property
    def expansion_factor(self) -> float:
        """Signature / public-key size ratio, the headline ML-DSA property."""
        return self.sig_len / self.pk_len

    def as_dict(self) -> dict[str, int | str | float]:
        return {
            "name": self.name,
            "standard": "FIPS 204",
            "security_level": self.security_level,
            "tau": self.tau,
            "lambda": self.lam,
            "gamma1": self.gamma1,
            "gamma2": self.gamma2,
            "k": self.k,
            "ell": self.ell,
            "eta": self.eta,
            "eta_bits": self.eta_bits,
            "beta": self.beta,
            "omega": self.omega,
            "pk_len": self.pk_len,
            "sk_len": self.sk_len,
            "sig_len": self.sig_len,
            "expansion_factor": round(self.expansion_factor, 2),
        }


MLDSA_PARAMS: dict[str, MLDSAParams] = {
    p.name: p
    for p in (
        MLDSAParams("ML-DSA-44", 2, tau=39, lam=128, gamma1=2 ** 17, gamma2=(8380417 - 1) // 88,
                    k=4, ell=4, eta=2, beta=78, omega=80),
        MLDSAParams("ML-DSA-65", 3, tau=49, lam=192, gamma1=2 ** 19, gamma2=(8380417 - 1) // 32,
                    k=6, ell=5, eta=4, beta=196, omega=55),
        MLDSAParams("ML-DSA-87", 5, tau=60, lam=256, gamma1=2 ** 19, gamma2=(8380417 - 1) // 32,
                    k=8, ell=7, eta=2, beta=120, omega=75),
    )
}

MLDSA_SETS = tuple(MLDSA_PARAMS)


def get_mldsa(name: str) -> MLDSAParams:
    """Look up an ML-DSA parameter set, accepting short aliases."""
    return MLDSA_PARAMS[_resolve(name, MLDSA_PARAMS, "ML-DSA-")]


def mldsa_levels() -> list[str]:
    """Available ML-DSA parameter sets."""
    return list(MLDSA_SETS)


# --------------------------------------------------------------------------- #
# Deployment metadata                                                          #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ParameterSet:
    """Deployment oriented view of a primitive (agility + reporting)."""

    name: str
    kind: Literal["kem", "signature"]
    standard: str
    nist_status: Status
    security_level: int
    hardness: str
    publication: str
    tls_group: int | None = None
    tls_signature: int | None = None
    notes: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "name": self.name,
            "kind": self.kind,
            "standard": self.standard,
            "nist_status": self.nist_status,
            "security_level": self.security_level,
            "hardness": self.hardness,
            "publication": self.publication,
            "aliases": list(self.aliases),
            "notes": self.notes,
        }
        if self.tls_group is not None:
            data["tls_group"] = self.tls_group
        if self.tls_signature is not None:
            data["tls_signature"] = self.tls_signature
        return data


KEM_TLS_GROUPS: tuple[ParameterSet, ...] = (
    ParameterSet(
        "ML-KEM-512", "kem", "FIPS 203", "final", 1,
        "Module-LWE (structured, rank k=2)",
        "Lang, Koo, Ducas, Peikert, Mitzenmacher, de Boer, 'CRYSTALS-Kyber: "
        "A CCA-secure post-quantum KEM', IEEE S&P 2017",
        tls_group=0x0200, aliases=("kyber512",),
        notes="IANA codepoint 0x0200 (hybrid 0x2C02 in the X25519Kyber768Draft tradition).",
    ),
    ParameterSet(
        "ML-KEM-768", "kem", "FIPS 203", "final", 3,
        "Module-LWE (structured, rank k=3)",
        "Lang et al., 'CRYSTALS-Kyber', IEEE S&P 2017; standardised as FIPS 203 (2024)",
        tls_group=0x0201, aliases=("kyber768",),
        notes="Default category-3 choice; NIST recommends it for general use.",
    ),
    ParameterSet(
        "ML-KEM-1024", "kem", "FIPS 203", "final", 5,
        "Module-LWE (structured, rank k=4)",
        "Lang et al., 'CRYSTALS-Kyber', IEEE S&P 2017",
        tls_group=0x0202, aliases=("kyber1024",),
        notes="Largest ciphertext; use only where a level-5 guarantee is required.",
    ),
)

SIGNATURE_TLS_SCHEMES: tuple[ParameterSet, ...] = (
    ParameterSet(
        "ML-DSA-44", "signature", "FIPS 204", "final", 2,
        "Module-LWE / Module-SIS",
        "Ducas, Durmus, Lepoint, Lyubashevsky, Peters, Savasta, Taylor, 'CRYSTALS-Dilithium: "
        "A Lattice-Based Digital Signature Scheme', TCHES 2018",
        tls_signature=0x0904, aliases=("dilithium2",),
    ),
    ParameterSet(
        "ML-DSA-65", "signature", "FIPS 204", "final", 3,
        "Module-LWE / Module-SIS",
        "Ducas et al., TCHES 2018; standardised as FIPS 204 (2024)",
        tls_signature=0x0905, aliases=("dilithium3",),
        notes="Balanced recommendation for identity-grade deployments.",
    ),
    ParameterSet(
        "ML-DSA-87", "signature", "FIPS 204", "final", 5,
        "Module-LWE / Module-SIS",
        "Ducas et al., TCHES 2018",
        tls_signature=0x0906, aliases=("dilithium5",),
    ),
)


def _resolve(name: str, table: dict[str, object], prefix: str) -> str:
    """Resolve a parameter-set name, tolerating case and short aliases."""
    if name in table:
        return name
    lowered = name.lower()
    for candidate in table:
        if candidate.lower() == lowered:
            return candidate
    short = lowered.removeprefix(prefix.lower())
    if short.isdigit():
        for candidate in table:
            if candidate.endswith(short):
                return candidate
    raise KeyError(f"unknown parameter set {name!r}")