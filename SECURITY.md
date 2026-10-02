# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/iamsandeshdhital/QuantumPost/security/advisories/new)
on this repository, or by email to the maintainer.

Please include:

- what you found and why it matters;
- a minimal reproduction (input, expected result, actual result);
- your Python version and platform;
- whether you believe it is exploitable, and by whom.

You should get an acknowledgement within a week. Fixes for confirmed
cryptographic defects will be published as an advisory with credit unless you
prefer otherwise.

## Supported versions

The `main` branch is supported. This is a 1.0 release with no long-term support
tiers.

## Scope

In scope:

- anything in `quantumpost/` that could produce an incorrect cryptographic
  result (wrong shared secret, accepted forgery, rejected valid signature);
- key material leaking through the API, the CLI, error messages or logs;
- the hybrid combiner producing a key that is not bound to both inputs.

Out of scope:

- side-channel attacks against CPython (see [docs/THREATS.md](docs/THREATS.md));
- performance and denial of service;
- the known interoperability gap in ML-DSA signatures, which is documented in
  [docs/CONFORMANCE.md](docs/CONFORMANCE.md) rather than undisclosed.

## Security posture

This library is an **audit-oriented reference implementation**. It is not
claimed to be production-hardened. Before deploying it:

1. Read [docs/THREATS.md](docs/THREATS.md) and confirm none of the listed
   limitations matter for your use case.
2. Read [docs/CONFORMANCE.md](docs/CONFORMANCE.md) and confirm the parts you
   depend on are validated.
3. Consider whether a reviewed C or Rust implementation is the better choice.

### What is validated

- ML-DSA key generation is **byte-exact against all 75 NIST ACVP FIPS 204
  key-generation vectors**.
- ML-KEM round trips and implements implicit rejection for all three sets.
- ML-DSA signing and verification round trip, and reject every invalid signature
  in the ACVP negative corpus (36/36).

### What is not

- ML-DSA signatures do not yet interoperate with NIST's implementation
  (0/9 ACVP positive cases). Do not use them across a trust boundary.
- ML-KEM encapsulation keys and ciphertexts have not been byte-compared to the
  ACVP vectors.
- The pure-Python Keccak fallback is structurally tested but not validated
  against authoritative digests.
- No independent security review has been performed.

## Hardening notes for reviewers

If you are reviewing this code, the places most worth your attention are:

- `quantumpost/mldsa.py` — the `Decompose` / `MakeHint` / `UseHint` trio and the
  `2^d` shift placement in `_inv_ntt`-adjacent code;
- `quantumpost/mlkem.py` — implicit rejection, and that no failure path returns
  a value derived from the private key;
- `quantumpost/utils.py` — `bitpack`/`bitunpack` and `bytedecode`, especially the
  `group = 8 // gcd(d, 8)` rule;
- `quantumpost/hashes.py` — the SHAKE length-in-bytes convention, which is the
  most common place these libraries go wrong.