# Deployment

## Read this first

QuantumPost is an **audit-oriented reference implementation**. It is designed so
that a reviewer can read the whole thing, and so that it can be checked against
NIST's published test vectors. It has **not** been independently reviewed, it is
**not** hardened against side-channel attacks, and part of ML-DSA is **not yet
interoperable** with NIST's implementation (see [CONFORMANCE.md](CONFORMANCE.md)).

Use it for:

- understanding how ML-KEM and ML-DSA actually work;
- validating other implementations against NIST's vectors;
- prototyping and interoperability experiments in a controlled environment;
- building test harnesses and fuzzers for lattice cryptography.

Do not use it as the only protection for data that must survive the next decade.

---

## If you need production post-quantum security

Use an implementation that has been reviewed and validated, and combine it with a
classical algorithm:

- **liboqs** (Open Quantum Safe) — the reference C implementations from the
  submission packages
- **PQClean** — formally verified, constant-time C
- **BoringSSL / AWS-LC / RustCrypto** — maintained, integrated, with hardware
  acceleration

Then combine the two with a hybrid KDF. `quantumpost.combine.classical_combine`
implements the X-Wing combiner if you want to reason about the construction, but
in production use the combiner from your protocol of choice (TLS hybrid groups,
for instance) so that you inherit its analysis and its interoperability work.

---

## Interoperability status

| Use | Status |
|---|---|
| ML-DSA key generation | **Interoperable** — byte-exact with NIST |
| ML-KEM encapsulation / decapsulation | Self-consistent; ACVP byte comparison outstanding |
| ML-DSA signing / verification | Self-consistent only — **not interoperable** |

If a peer must read your keys, ML-DSA key generation is safe today. Do not send
this library's ML-DSA signatures across a trust boundary.

---

## Handling key material

- **Never** store a `dk` or an `sk` next to a `ct` or a signature.
- Zeroise intermediate buffers if you are running where memory disclosure
  matters. Python makes this awkward: the reference implementation zeroes the
  secret vectors it derives during signing and verification, but the interpreter
  may have copied them.
- Use the deterministic entry points for test fixtures; use the default random
  entry points everywhere else.
- Bind a meaningful `ctx` string to signatures so that a signature made for one
  protocol cannot be replayed in another.

---

## Performance

Measured on one core of a modern laptop (`python -m quantumpost bench`):

| Operation | Typical cost |
|---|---|
| ML-KEM-768 keygen | well under a second |
| ML-KEM-768 encapsulate | well under a second |
| ML-DSA-65 keygen | well under a second |
| ML-DSA-65 sign | hundreds of milliseconds to seconds |
| ML-DSA-65 verify | well under a second |

Signing is dominated by the rejection-sampling loop, which re-samples `y` on
each rejection and therefore re-runs the matrix-vector product. The expected
number of iterations is 3.85–5.1 depending on the parameter set, so the tail is
what you see.

If you need throughput, this is the wrong library. See above.

---

## Integration checklist

1. Pin the parameter set explicitly. Never let a default decide security level.
2. Bind a context string to every signature.
3. Use hedged signing (`rnd=None`) in production.
4. Combine with a classical algorithm rather than replacing it.
5. Run `python -m quantumpost self-test` as part of your build.
6. If you validate other implementations, run `tools/check_acvp.py`.
7. Read [THREATS.md](THREATS.md) and confirm none of the listed gaps matter for
   your use case.

---

## Reporting a problem

Open an issue with:

- what you expected and what happened;
- the exact command or code;
- `python --version`, `python -c "import sys; print(sys.implementation)"` and
  `python -m quantumpost --version`.

If you believe you have found a cryptographic defect, please do **not** open a
public issue first — see [SECURITY.md](../SECURITY.md) for the private reporting
process.