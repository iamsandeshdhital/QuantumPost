# Architecture

QuantumPost is deliberately small and flat. Every module has one job, and the
dependency graph has no cycles.

```
                 quantumpost/
                       |
      +----------------+----------------+----------------+
      |                |                |                |
   params.py       hashes.py        keccak_pure.py    utils.py
      |                |                                |
      +--------+-------+                                |
               |                                        |
        ntt.py | mlkem.py            mldsa.py <--------+
               |     |                   |
               +-----+-------------------+
                     |
                 combine.py
                     |
                   cli.py
```

## `params.py` — every constant, in one place

The design rule is *no magic numbers in algorithm code*. Every hard-coded value
in ML-KEM and ML-DSA is either a field of a `MLKEMParams` / `MLDSAParams`
instance or a fixed invariant of the ring (`N = 256`). The parameter tables
mirror FIPS 203 Table 2 and FIPS 204 Table 1, including the sizes and the TLS
codepoints, so a deployment can print an agility decision without reading any
algorithm code.

`MLDSAParams.sk_len` is *derived* from the same packing widths the encoder uses
rather than hard-coded, which means a bug in one place cannot silently disagree
with the other.

## `hashes.py` — one narrow interface

Every hash in the library is reached through this module, never through `hashlib`
directly. That buys two things:

- **SHAKE output lengths are in bytes**, not bits, which removes the single most
  common source of errors in post-quantum code;
- the pure-Python fallback is reachable from exactly one place.

`ct_eq` (constant-time comparison) is provided here rather than using `==`,
because secret comparisons must not leak by timing.

## `keccak_pure.py` — the portability net

A dependency-free Keccak-f[1600] used when `hashlib` has no SHAKE. On CPython
3.6+ this path is dead code. It is covered by structural tests (the permutation
is a bijection, the sponge is deterministic and prefix-consistent) but is **not**
cross-checked against an authoritative digest source — see the module docstring.

## `utils.py` — encoding and randomness

Two concerns that are easy to get wrong and painful to retrofit:

- **Packing.** `bytepack`/`bytedecode` (FIPS 203) and `bitpack`/`bitunpack`
  (FIPS 204) in one place, with the FIPS 203 "generic group size" rule
  (`group = 8 // gcd(d, 8)`) handled once.
- **Randomness.** `SystemRandom` by default, but every primitive accepts an
  injectable source. `use_random` is a context manager so tests can pin
  determinism without leaking global state between tests.

## `ntt.py` — the arithmetic core

- `NegacyclicNTT` is a direct Cooley-Tukey negacyclic transform requiring
  `2n | q - 1`. It is used for ML-DSA, where `512 | q - 1`.
- ML-KEM cannot use it: `512` does not divide `3328`. FIPS 203 instead splits
  the ring on `Y = X^2`, where `Y^128 = -1`, and multiplies with three
  degree-128 negacyclic convolutions combined by Karatsuba. `mlkem_mul_domain`
  and `mlkem_transform` implement that, and operate on the *transformed*
  representation directly.
- `schoolbook_mul` is the O(n²) ground-truth oracle. Every fast path is tested
  against it, which is how subtle index bugs get caught.

## `mlkem.py` — FIPS 203

`keypair_from_seed` → `generate_keypair`, `encapsulate` /
`encapsulate_deterministic` → `decapsulate` / `decapsulate_strict`.

Decapsulation always returns a secret. A malformed ciphertext triggers FIPS 203's
implicit rejection — the fallback `J(z || c)` — rather than an error, because
that is what makes ML-KEM IND-CCA. `decapsulate_strict` exists for tests that
want the failure to be loud.

The whole computation stays in the transformed domain; the coefficient-domain
form is never materialised on the hot path.

## `mldsa.py` — FIPS 204

`keypair_from_seed` → `sign` → `verify`, plus `sign_internal` / `verify_internal`
for callers that already applied the domain separation prefix.

Two things are worth calling out:

- **The zeta table is inlined**, exactly as published, rather than generated at
  import time. The cost is 256 lines; the benefit is that a reviewer can compare
  it against FIPS 204 line by line and there is no way for a generation bug to
  change behaviour between runs.
- **Hints are the subtle part.** `MakeHint` records whether the low part of a
  coefficient overflowed the window `UseHint` can repair with a single step;
  `UseHint` then nudges the high bits by one in the direction indicated by the
  low part. The pair round-trips exactly (0/20000 failures in the test suite),
  and the hint weight is capped at `omega` during signing.

`ctx` support is first-class: FIPS 204 binds a context string into `M'`, so a
signature made for one application cannot be replayed in another.

## `combine.py` — hybrid construction

Keeping the classical KEM *outside* the library is a deliberate boundary. The
host application already has a FIPS-validated ECDH; re-implementing it here would
add risk and a dependency for no benefit. What belongs here is the combiner,
which is the part that has to be right and has no good home elsewhere.

## `cli.py` — a thin shell

Every command is a direct call into the library, so the CLI can never disagree
with the API. Commands read and write raw key material; there is no format
invented here, because inventing formats is how key material gets lost.

## Design decisions worth defending

**Pure Python, deliberately.** The alternative is a C or Rust core with Python
bindings, which would be far faster. That is the right choice for production
throughput and the wrong choice for an auditable reference. This repository is
the auditable reference; the spec-compliant C from NIST or PQClean is what you
deploy.

**No key-file format.** Keys are raw bytes. Parsing a bespoke container adds
attack surface and no security.

**Context strings are supported but not invented.** `ctx` defaults to empty and
is the caller's choice, because inventing a context convention would make
signatures incompatible with everyone else.

**Deterministic signatures are available but off by default.** `rnd=None` uses
fresh randomness (hedged signing, which is the safer default); passing
`rnd=bytes(32)` gives deterministic output for test vectors. NIST's vectors are
deterministic, which is why the injection point exists.