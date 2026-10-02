# Threats: what this library does not protect against

A list of known limitations, written plainly. If any of these matter for your
use case, use a different implementation.

## 1. Side channels

**Timing.** The algorithms are written to avoid secret-dependent branches and
table lookups in the cryptographic core, and `ct_eq` is constant-time for secret
comparisons. But this is Python: the interpreter, the garbage collector and the
memory allocator all introduce timing variation that the code cannot control. A
remote timing attack against CPython is a documented, practical attack class.

**Caches.** Secret-dependent memory access patterns leak through the CPU cache.
The reference C avoids these with constant-time table lookups; Python offers no
way to.

**Power and electromagnetic emissions.** Not addressed at all.

**What to do instead.** Use PQClean, RustCrypto's `ml-dsa`/`ml-kem`, or
BoringSSL, which are written for this.

## 2. Fault injection

Software fault injection (flipping memory, injecting faults during computation)
can turn a correct implementation into an incorrect one. No countermeasures are
implemented.

## 3. Memory disclosure

Signing and verification derive secret-dependent intermediates. The reference
implementation zeroises them; Python cannot guarantee the interpreter has not
copied them (into a GC arena, a traceback, a `repr`). Long-lived processes that
handle keys are at risk.

## 4. The signing loop is not constant-time

ML-DSA signing rejects and re-samples. The number of iterations is
secret-dependent, so the *timing* of a signature reveals information about the
rejection count. The reference C has the same property and mitigates it by
sampling a fixed number of candidates and zeroising the unused ones. This
implementation does not.

## 5. No key separation across uses

Nothing here enforces that a given key is used for exactly one purpose. Reusing
an ML-DSA key across applications without distinct context strings weakens the
scheme in ways this library will not warn you about.

## 6. No key rotation, storage or lifecycle

Keys are bytes. Generating, distributing, storing, rotating and revoking them is
the caller's job, and this library provides no help with any of it.

## 7. Denial of service

Verification is bounded work. Signing is not: the rejection loop has an iteration
cap (`_SIGN_ATTEMPT_LIMIT`) but in the worst case that is thousands of matrix
products. An attacker who can force you to sign many messages can cost you a lot
of CPU. Signing is not a service endpoint here.

## 8. Randomness quality

The default source is `os.urandom` via `random.SystemRandom`, which is the right
choice on a healthy operating system. This library cannot detect a broken
entropy source, and it cannot detect a VM snapshot or hibernation that replays
randomness.

## 9. Implementation conformance (ML-DSA signatures)

Nine NIST ACVP signatures that should verify do not. See
[CONFORMANCE.md](CONFORMANCE.md). Key generation is byte-exact; signature
verification is not yet interoperable.

## 10. No formal verification

The NTT is tested against a schoolbook multiplication oracle, and key generation
is byte-exact against NIST's vectors. That is strong evidence, not proof. No part
of this library has been machine-checked.

## 11. The pure-Python Keccak fallback is unvalidated

`keccak_pure.py` is a portability net for interpreters whose `hashlib` lacks
SHAKE. It is covered by structural tests only and is **not** cross-checked
against an authoritative digest source. If your interpreter lacks SHAKE in
`hashlib`, validate it against FIPS 202 test vectors before trusting it.

## 12. No protection against a compromised peer

These primitives authenticate keys and establish shared secrets. They say nothing
about whether the *other* endpoint is who it claims to be. That is what
certificates, signatures over identities, and authenticated transport are for.

---

## What the library *does* protect against

For completeness, so the list is not read as uniformly negative:

- An adversary with a quantum computer, running Shor's algorithm, learns nothing
  from the public keys.
- An adversary with classical access to every public value still cannot recover
  the ML-KEM shared secret or forge an ML-DSA signature without the private key
  (assuming the primitives are correctly implemented, which for ML-DSA key
  generation is confirmed against NIST and for signing is not).
- ML-KEM decapsulation does not distinguish "wrong ciphertext" from "right
  ciphertext, wrong key" — implicit rejection returns a pseudorandom secret in
  both cases, which is what IND-CCA requires.
- The hybrid combiner stays secure if either the classical or the PQ component
  is secure, which a PQ-only scheme does not.