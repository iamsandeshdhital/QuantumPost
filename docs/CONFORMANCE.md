# Conformance status

This document records, precisely, which parts of QuantumPost have been validated
against which external reference, and which have not. It is deliberately
unflattering about the gaps.

## Summary

| Property | Reference | Result |
|---|---|---|
| ML-DSA key generation (pk and sk bytes) | 75 NIST ACVP `ML-DSA-keyGen-FIPS204` vectors | **byte-exact, 75/75** |
| ML-KEM encapsulation/decapsulation | self-consistency | round trip + implicit rejection pass |
| ML-DSA sign → verify | self-consistency | round trip passes, all three sets |
| ML-DSA rejection of invalid signatures | 36 NIST ACVP `ML-DSA-sigVer-FIPS204` negative cases | **36/36 correct** |
| ML-DSA acceptance of valid signatures | 9 NIST ACVP positive cases | **0/9 — not conforming** |
| ML-KEM key/ciphertext bytes | NIST ACVP `ML-KEM-encapDecap-FIPS203` | not byte-checked |
| ML-DSA signature bytes | NIST ACVP `ML-DSA-sigGen-FIPS204` | not byte-checked |

## Why key generation being byte-exact matters

A byte-exact match on all 75 key-generation vectors is a very strong signal. It
means the following are all *exactly* right, because any error in any of them
would change `ek` or `dk`:

- the NTT (Alg. 41/42) and the Montgomery reduction (Alg. 49), including the
  `zetas` table and the wrap-around case in `Decompose` (Alg. 20);
- `RejNTTPoly` (Alg. 32) — the 23-bit candidate, the rejection threshold, the
  `(col, row)` seeding order and the single-XOF squeeze;
- `RejBoundedPoly` (Alg. 29/31) — the nibble-based rejection with the
  `205*t >> 10` fold for `eta = 2` and the plain `4 - t` for `eta = 4`;
- `Power2Round` (Alg. 16), the `2^(d-1) - t0` reflection in the `t0` encoding,
  and the 10-bit `t1` field;
- `SamplePolyCBD`, `ExpandMask`, `SampleInBall` (Alg. 29) — the challenge
  sampler in particular is compared against a literal transcription of the
  reference C for 40 random inputs with zero mismatches;
- every encoding: `pkEncode` (10-bit `t1`), `skEncode` (`eta`-bit biased `s1`/`s2`,
  13-bit `t0`), and all key lengths.

The signing and verification algorithms build directly on those primitives, so
the arithmetic underneath them is trustworthy. The defect is in how verification
*reassembles* the commitment, not in the primitives.

## The open gap

Nine ACVP signatures that NIST's own implementation accepts are rejected here.
The following have been confirmed correct and ruled out:

- the private key decodes to a self-consistent key pair — `A·s1 + s2 == t1·2^13 + t0`
  holds for every coefficient of the failing vectors;
- `SampleInBall` matches the reference C transcription exactly;
- `Decompose` and `UseHint` match the reference C transcription exactly
  (0/3000 mismatches over random inputs, for `gamma2 = (q-1)/88`);
- the `MakeHint`/`UseHint` pair round-trips exactly (0/20000 failures);
- the signature round-trips through `sigEncode`/`sigDecode` byte-for-byte, so the
  response `z` and the hint encoding are read correctly;
- the domain separation prefix is `0x00 || len(ctx) || ctx || M` and
  `mu = SHAKE256(H(pk, 64) || prefix || M, 64)`, matching the reference
  implementation's `mld_prepare_domain_separation_prefix`;
- the hint bit width: 6 bits for ML-DSA-44 (`gamma2 = (q-1)/88`, 44 values) and
  4 bits for ML-DSA-65/87 (`gamma2 = (q-1)/32`, 16 values).

What has **not** been found is the convention that makes the verifier's
reconstructed `w1` equal the signer's committed `w1` for NIST-generated
signatures. Signatures produced by this library verify against this library, so
the reconstruction is internally consistent; it is the agreement with NIST's
convention that is missing.

The most likely remaining candidates, in order:

1. the hint *sign convention* — whether the stored bit means "add 1" or "subtract 1",
   and whether the repair direction is derived from the hint or from the low part;
2. the exact `w'_approx` reduction point — whether `c·t1·2^d` is subtracted
   before or after `invNTT`, and whether a Montgomery factor is involved;
3. the `w1` packing width for ML-DSA-65/87 (the reference uses 4 bits there, 6 for
   ML-DSA-44) — `_w1_encode` currently always uses 6, which is wrong for 65/87 and
   is a known, separate defect.

## Reproducing

Download the official NIST ACVP vector set (from the
[ACVP Server](https://github.com/usnistgov/ACVP-Server) `gen-val/json-files`
directory) and point the checker at it:

```bash
export ACVP_DIR=/path/to/vectors
python tools/check_acvp.py
```

Expected output today:

```
ML-DSA keyGen byte-exact: 75/75
ML-KEM ML-KEM-512   round trip + implicit rejection: ok
ML-KEM ML-KEM-768   round trip + implicit rejection: ok
ML-KEM ML-KEM-1024  round trip + implicit rejection: ok
ML-DSA sigVer negative cases: 36/36 correct
ML-DSA sigVer positive cases: 0/9 correct
one or more checks did not pass
```

## What "not conforming" means in practice

- `quantumpost.mldsa.keypair_from_seed` and `generate_keypair` produce keys
  **identical to NIST's**, so keys are interoperable today.
- `quantumpost.mlkem` is self-consistent and standards-conformant in structure,
  but its encapsulation keys and ciphertexts have not been byte-compared to the
  ACVP vectors; treat interoperability as unverified.
- `quantumpost.mldsa.sign` / `verify` interoperate with each other and reject
  every invalid signature tested, but do **not** interoperate with NIST's
  implementation.

Do not use ML-DSA signatures across a trust boundary until the positive cases
pass.