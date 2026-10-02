# QuantumPost

**Post-quantum cryptography in pure Python — no dependencies, no compilation, no
network.** A complete, auditable implementation of the two NIST standardised
Module-Lattice primitives:

| Primitive | Standard | Purpose | Levels |
|---|---|---|---|
| **ML-KEM** (CRYSTALS-Kyber) | [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) | Key encapsulation | 1 / 3 / 5 |
| **ML-DSA** (CRYSTALS-Dilithium) | [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) | Digital signatures | 2 / 3 / 5 |

Everything is written against the **Python standard library only**. There is no
`pip install` step, no C extension, no compiler, and no network access at any
point — the whole library is a few thousand lines you can read end to end.

---

## Why

Two reasons:

1. **Auditability.** Post-quantum code is security-critical and long-lived.
   Being able to read the complete implementation, and to test it against NIST's
   own published vectors, is worth more than a constant-factor speedup you
   cannot inspect.
2. **Portability.** It runs anywhere Python runs — laptops, CI runners,
   embedded interpreters, air-gapped review environments — with no build matrix.

> **Performance.** This is a pure-Python implementation and it is *slow*
> (ML-KEM encapsulation takes milliseconds, ML-DSA-65 signing takes a fraction
> of a second to a few seconds depending on the machine). That is the explicit
> trade for having zero dependencies. Do not deploy it as a throughput server;
> use it where correctness, reviewability or portability dominates.

---

## Install

```bash
git clone https://github.com/iamsandeshdhital/QuantumPost.git
cd QuantumPost
python -m quantumpost self-test
```

Python 3.9 or newer. Nothing else.

---

## Use it as a library

```python
from quantumpost import mlkem, mldsa

# --- key encapsulation -------------------------------------------------------
ek, dk = mlkem.generate_keypair("ML-KEM-768")
shared_secret, ciphertext = mlkem.encapsulate("ML-KEM-768", ek)
assert shared_secret == mlkem.decapsulate("ML-KEM-768", dk, ciphertext)

# --- signatures --------------------------------------------------------------
pk, sk = mldsa.generate_keypair("ML-DSA-65")
signature = mldsa.sign("ML-DSA-65", sk, b"transfer 100 units to alice")
assert mldsa.verify("ML-DSA-65", pk, b"transfer 100 units to alice", signature)
```

Reproducible key generation for test vectors:

```python
pk, sk = mldsa.keypair_from_seed("ML-DSA-44", bytes(range(32)))
```

Deterministic randomness for experiments:

```python
from quantumpost import utils

with utils.use_random(utils.DeterministicRandom(b"\x01" * 32)):
    ek, dk = mlkem.generate_keypair("ML-KEM-512")
```

### Hybrid (classical + PQ) key agreement

A PQ KEM on its own gives no protection against an adversary who has *already*
broken the classical algorithm, so real deployments combine it with a classical
KEM. `quantumpost.combine` implements the combiner; the classical primitive stays
outside the library so that your existing, vetted ECDH implementation keeps its
place:

```python
from quantumpost.combine import hybrid_encapsulate, hybrid_decapsulate

# you performed the X25519/ECDSA exchange yourself
combined_key, ciphertext = hybrid_encapsulate("ML-KEM-768", ek, classical_shared_secret)
assert combined_key == hybrid_decapsulate("ML-KEM-768", dk, ciphertext, classical_shared_secret)
```

---

## Use it from the command line

```bash
python -m quantumpost list                  # parameter sets and sizes
python -m quantumpost info ML-DSA-65        # one parameter set as JSON
python -m quantumpost self-test             # built-in correctness tests

python -m quantumpost kem-keygen -a ML-KEM-768
python -m quantumpost kem-encaps -a ML-KEM-768 --ek ek.bin
python -m quantumpost kem-decaps -a ML-KEM-768 --dk dk.bin --ct ct.bin

python -m quantumpost sig-keygen -a ML-DSA-65
echo "hello" | python -m quantumpost sig-sign -a ML-DSA-65 --sk sk.bin -m -
python -m quantumpost sig-verify -a ML-DSA-65 --pk pk.bin -m msg.bin --signature sig.bin
```

Use `-` for stdin/stdout. `--seed` makes key generation reproducible.

---

## Parameter sets and sizes

| Name | Kind | Standard | Security | Public | Private | Ciphertext / Signature |
|---|---|---|---|---|---|---|
| ML-KEM-512 | KEM | FIPS 203 | 1 | 800 | 1632 | 768 |
| ML-KEM-768 | KEM | FIPS 203 | 3 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | KEM | FIPS 203 | 5 | 1568 | 3168 | 1568 |
| ML-DSA-44 | Signature | FIPS 204 | 2 | 1312 | 2560 | 2420 |
| ML-DSA-65 | Signature | FIPS 204 | 3 | 1952 | 4032 | 3309 |
| ML-DSA-87 | Signature | FIPS 204 | 5 | 2592 | 4896 | 4627 |

All sizes are byte-for-byte those published in FIPS 203 Table 2 and FIPS 204
Table 2, and are asserted by the test suite.

---

## Conformance status

Honest reporting of what is and is not validated:

| Check | Result |
|---|---|
| ML-DSA key generation vs **all 75 NIST ACVP FIPS 204 vectors** | **byte-exact** |
| ML-KEM round trip + implicit rejection (all three sets) | pass |
| ML-DSA sign → verify round trip (all three sets) | pass |
| ML-DSA negative tests (tampered signature, wrong message, wrong key, bad context) | pass |
| ML-DSA sigVer: every ACVP *negative* case (must reject) | 36/36 correct |
| ML-DSA sigVer: ACVP *positive* cases (must accept) | **not yet conforming** |
| ML-KEM encapsulation key bytes vs ACVP vectors | not byte-checked |

Reproduce the above with the official NIST vectors:

```bash
export ACVP_DIR=/path/to/acvp/vectors   # see docs/CONFORMANCE.md
python tools/check_acvp.py
```

**The known gap.** ML-DSA key generation is byte-exact, which pins the NTT,
`RejNTTPoly`, `RejBoundedPoly`, `Power2Round`, `Decompose`, every encoding and
every key-field layout to NIST's reference. Signing and verification are
internally consistent and correctly reject every negative case, but nine ACVP
signatures that NIST says are valid do not verify here. The residual difference
is in how the committed `w1` is reconstructed during verification; the public
key, the challenge, the hint encoding and the response decoding are all
confirmed correct. See [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the exact
scope, what has been ruled out, and how to reproduce the result.

Until that is closed, treat `quantumpost.mldsa.sign`/`verify` as a correct but
not-yet-interoperable ML-DSA implementation. **ML-KEM and ML-DSA key generation
are ready to use.**

---

## Tests

```bash
python -m unittest discover -s tests -v     # 84 tests, ~15 seconds
python -m quantumpost self-test
```

The suite covers hash known-answer tests, the NTT against a schoolbook
multiplication oracle, packing round trips, published sizes and parameters,
encapsulation/decapsulation with implicit rejection, signature round trips and
negative tests, the hybrid combiner, the deterministic RNG hooks and the CLI.

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the code is laid out and why
- [docs/CONFORMANCE.md](docs/CONFORMANCE.md) — exactly what is validated, and how
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — how to use this responsibly
- [docs/THREATS.md](docs/THREATS.md) — what this library does *not* protect against

---

## Security

Please read [SECURITY.md](SECURITY.md). In short: this is an
audit-oriented reference implementation, it has **not** been independently
reviewed, and it is not hardened against side-channel attacks the way a
production C or Rust library is.

## Licence

MIT — see [LICENSE](LICENSE).

## References

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*
- FIPS 204, *Module-Lattice-Based Digital Signature Standard*
- Lang et al., *CRYSTALS-Kyber: A CCA-secure Post-Quantum Key Encapsulation Mechanism*, IEEE S&P 2017
- Ducas et al., *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme*, TCHES 2018