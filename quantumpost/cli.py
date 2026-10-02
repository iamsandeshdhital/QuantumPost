"""Command line interface: ``python -m quantumpost <command>``.

Every command is a thin shell over the library so that the CLI can never
disagree with the API.  All key material can be pinned to a fixed seed for
reproducible demos and test vectors.
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import sys
from typing import Sequence

from quantumpost import __version__, mldsa, mlkem, params
from quantumpost.combine import classical_combine, hybrid_decapsulate, hybrid_encapsulate
from quantumpost.params import get_mldsa, get_mlkem

__all__ = ["main", "build_parser"]

_BANNER = "QuantumPost {version} - post-quantum KEM and signatures (stdlib only)"


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #
def _hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


def _unhex(text: str, *, exact: int | None = None, what: str = "input") -> bytes:
    cleaned = "".join(text.split())
    try:
        raw = binascii.unhexlify(cleaned)
    except binascii.Error as exc:
        raise SystemExit(f"error: {what} is not valid hex: {exc}") from exc
    if exact is not None and len(raw) != exact:
        raise SystemExit(f"error: {what} must be {exact} bytes, got {len(raw)}")
    return raw


def _read_file(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def _write_file(path: str, data: bytes) -> None:
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    try:
        with open(path, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        raise SystemExit(f"error: cannot write {path}: {exc}") from exc


def _seed(text: str | None, *, exact: int = 32) -> bytes | None:
    if text is None:
        return None
    return _unhex(text, exact=exact, what="--seed")


# --------------------------------------------------------------------------- #
# Commands                                                                      #
# --------------------------------------------------------------------------- #
def cmd_list(args: argparse.Namespace) -> int:
    if args.json:
        payload = {
            "kem": [p.as_dict() for p in params.KEM_TLS_GROUPS],
            "signature": [p.as_dict() for p in params.SIGNATURE_TLS_SCHEMES],
        }
        print(json.dumps(payload, indent=2))
        return 0
    print(f"{'name':<14}{'kind':<11}{'standard':<11}{'lvl':<5}"
          f"{'pub':<7}{'priv':<7}{'ct/sig':<8}{'tls'}")
    print("-" * 72)
    for entry in params.KEM_TLS_GROUPS:
        d = params.get_mlkem(entry.name)
        print(f"{entry.name:<14}{entry.kind:<11}{entry.standard:<11}"
              f"{entry.security_level:<5}{d.ek_len:<7}{d.dk_len:<7}{d.ct_len:<8}"
              f"0x{entry.tls_group:04x}")
    for entry in params.SIGNATURE_TLS_SCHEMES:
        d = params.get_mldsa(entry.name)
        print(f"{entry.name:<14}{entry.kind:<11}{entry.standard:<11}"
              f"{entry.security_level:<5}{d.pk_len:<7}{d.sk_len:<7}{d.sig_len:<8}"
              f"0x{entry.tls_signature:04x}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    if args.algorithm in params.MLKEM_SETS:
        d = params.get_mlkem(args.algorithm).as_dict()
    elif args.algorithm in params.MLDSA_SETS:
        d = params.get_mldsa(args.algorithm).as_dict()
    else:
        raise SystemExit(f"error: unknown parameter set {args.algorithm!r}")
    d["standard"] = "FIPS 203" if args.algorithm in params.MLKEM_SETS else "FIPS 204"
    d["n"] = 256
    if args.algorithm in params.MLDSA_SETS:
        d["d"] = 13
    print(json.dumps(d, indent=2, sort_keys=True))
    return 0


def cmd_kem_keygen(args: argparse.Namespace) -> int:
    seed = _seed(args.seed, exact=64) if args.seed else None
    if seed is None:
        ek, dk = mlkem.generate_keypair(args.algorithm)
    else:
        ek, dk = mlkem.keypair_from_seed(get_mlkem(args.algorithm), seed[:32], seed[32:])
    if args.prefix:
        print(f"{_hex(ek)}", file=sys.stderr)
        print(f"{_hex(dk)}", file=sys.stderr)
        return 0
    _write_file(args.ek, ek)
    _write_file(args.dk, dk)
    return 0


def cmd_kem_encap(args: argparse.Namespace) -> int:
    ek = _read_file(args.ek)
    message = _seed(args.message)
    if message is None:
        ss, ct = mlkem.encapsulate(args.algorithm, ek)
    else:
        ss, ct = mlkem.encapsulate_deterministic(args.algorithm, ek, message)
    _write_file(args.ct, ct)
    _write_file(args.ss, ss)
    return 0


def cmd_kem_decap(args: argparse.Namespace) -> int:
    dk = _read_file(args.dk)
    ct = _read_file(args.ct)
    _write_file(args.out, mlkem.decapsulate(args.algorithm, dk, ct))
    return 0


def cmd_sig_keygen(args: argparse.Namespace) -> int:
    seed = _seed(args.seed)
    if seed is None:
        pk, sk = mldsa.generate_keypair(args.algorithm)
    else:
        pk, sk = mldsa.keypair_from_seed(params.get_mldsa(args.algorithm), seed)
    _write_file(args.pk, pk)
    _write_file(args.sk, sk)
    return 0


def cmd_sig_sign(args: argparse.Namespace) -> int:
    sk = _read_file(args.sk)
    message = _read_file(args.message)
    rnd = _seed(args.rnd)
    ctx = _read_file(args.ctx) if args.ctx else b""
    sig = mldsa.sign(get_mldsa(args.algorithm), sk, message, rnd=rnd, ctx=ctx)
    _write_file(args.out, sig)
    return 0


def cmd_sig_verify(args: argparse.Namespace) -> int:
    pk = _read_file(args.pk)
    message = _read_file(args.message)
    sig = _read_file(args.signature)
    ctx = _read_file(args.ctx) if args.ctx else b""
    ok = mldsa.verify(args.algorithm, pk, message, sig, ctx=ctx)
    print("valid" if ok else "INVALID")
    return 0 if ok else 1


def cmd_self_test(args: argparse.Namespace) -> int:
    failures = 0
    for name in params.MLKEM_SETS:
        spec = params.get_mlkem(name)
        ek, dk = mlkem.generate_keypair(spec)
        ss_a, ct = mlkem.encapsulate(spec, ek)
        ss_b = mlkem.decapsulate(spec, dk, ct)
        bad = bytearray(ct)
        bad[0] ^= 0x01
        ss_c = mlkem.decapsulate(spec, dk, bytes(bad))
        ok = ss_a == ss_b and ss_c != ss_a and len(ct) == spec.ct_len
        failures += not ok
        print(f"  {name:<12} {'ok' if ok else 'FAIL'}  "
              f"ek={len(ek)} dk={len(dk)} ct={len(ct)}")
    for name in params.MLDSA_SETS:
        spec = params.get_mldsa(name)
        pk, sk = mldsa.generate_keypair(spec)
        message = b"QuantumPost self test"
        sig = mldsa.sign(spec, sk, message)
        bad = bytearray(sig)
        bad[-1] ^= 0x01
        ok = (mldsa.verify(spec, pk, message, sig)
              and not mldsa.verify(spec, pk, message, bytes(bad))
              and not mldsa.verify(spec, pk, b"other", sig)
              and len(sig) == spec.sig_len)
        failures += not ok
        print(f"  {name:<12} {'ok' if ok else 'FAIL'}  "
              f"pk={len(pk)} sk={len(sk)} sig={len(sig)}")
    print("all self tests passed" if not failures else f"{failures} self test(s) FAILED")
    return 1 if failures else 0


def cmd_bench(args: argparse.Namespace) -> int:
    import time

    rows = []
    for name in params.MLKEM_SETS:
        spec = params.get_mlkem(name)
        t0 = time.perf_counter()
        ek, dk = mlkem.generate_keypair(spec)
        t_kg = time.perf_counter() - t0
        t0 = time.perf_counter()
        ss, ct = mlkem.encapsulate(spec, ek)
        t_enc = time.perf_counter() - t0
        t0 = time.perf_counter()
        mlkem.decapsulate(spec, dk, ct)
        t_dec = time.perf_counter() - t0
        rows.append((name, "keygen", t_kg))
        rows.append((name, "encaps", t_enc))
        rows.append((name, "decaps", t_dec))
    for name in params.MLDSA_SETS:
        spec = params.get_mldsa(name)
        t0 = time.perf_counter()
        pk, sk = mldsa.generate_keypair(spec)
        t_kg = time.perf_counter() - t0
        message = b"benchmark message"
        t0 = time.perf_counter()
        sig = mldsa.sign(spec, sk, message)
        t_sign = time.perf_counter() - t0
        t0 = time.perf_counter()
        mldsa.verify(spec, pk, message, sig)
        t_ver = time.perf_counter() - t0
        rows.append((name, "keygen", t_kg))
        rows.append((name, "sign", t_sign))
        rows.append((name, "verify", t_ver))
    print(f"{'algorithm':<14}{'operation':<10}{'seconds':>10}")
    print("-" * 34)
    for name, op, dt in rows:
        print(f"{name:<14}{op:<10}{dt:>10.3f}")
    return 0


def cmd_kem_hash(args: argparse.Namespace) -> int:
    """Combine a classical and a PQ shared secret (X-Wing style)."""
    a = _read_file(args.first)
    b = _read_file(args.second)
    print(_hex(classical_combine(a, b)))
    return 0


def cmd_hybrid_demo(args: argparse.Namespace) -> int:
    ek, dk = mlkem.generate_keypair(args.algorithm)
    classical = os.urandom(32)
    combined_a, ct = hybrid_encapsulate(args.algorithm, ek, classical)
    combined_b = hybrid_decapsulate(args.algorithm, dk, ct, classical)
    print(f"combined key agrees : {combined_a == combined_b}")
    print(f"classical secret    : {_hex(classical)[:32]}...")
    print(f"combined key        : {_hex(combined_a)}")
    return 0 if combined_a == combined_b else 1


# --------------------------------------------------------------------------- #
# Parser                                                                        #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantumpost",
        description="QuantumPost - post-quantum KEM and signatures, standard library only.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="list parameter sets")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("info", help="show one parameter set")
    p.add_argument("algorithm", help="e.g. ML-KEM-768 or ML-DSA-65")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("kem-keygen", help="ML-KEM key generation")
    p.add_argument("-a", "--algorithm", default="ML-KEM-768", choices=list(params.MLKEM_SETS))
    p.add_argument("--seed", help="hex: 64 bytes (d || z) for reproducible keys")
    p.add_argument("--ek", default="ek.bin")
    p.add_argument("--dk", default="dk.bin")
    p.add_argument("--prefix", action="store_true",
                   help="print hex to stderr instead of writing files")
    p.set_defaults(func=cmd_kem_keygen)

    p = sub.add_parser("kem-encaps", help="ML-KEM encapsulation")
    p.add_argument("-a", "--algorithm", default="ML-KEM-768", choices=list(params.MLKEM_SETS))
    p.add_argument("--ek", default="ek.bin")
    p.add_argument("--message", help="hex: 32 byte encapsulation randomness")
    p.add_argument("--ct", default="ct.bin")
    p.add_argument("--ss", default="ss.bin")
    p.set_defaults(func=cmd_kem_encap)

    p = sub.add_parser("kem-decaps", help="ML-KEM decapsulation")
    p.add_argument("-a", "--algorithm", default="ML-KEM-768", choices=list(params.MLKEM_SETS))
    p.add_argument("--dk", default="dk.bin")
    p.add_argument("--ct", default="ct.bin")
    p.add_argument("--out", default="ss.bin")
    p.set_defaults(func=cmd_kem_decap)

    p = sub.add_parser("sig-keygen", help="ML-DSA key generation")
    p.add_argument("-a", "--algorithm", default="ML-DSA-65", choices=list(params.MLDSA_SETS))
    p.add_argument("--seed", help="hex: 32 byte seed")
    p.add_argument("--pk", default="pk.bin")
    p.add_argument("--sk", default="sk.bin")
    p.set_defaults(func=cmd_sig_keygen)

    p = sub.add_parser("sig-sign", help="ML-DSA signing")
    p.add_argument("-a", "--algorithm", default="ML-DSA-65", choices=list(params.MLDSA_SETS))
    p.add_argument("--sk", default="sk.bin")
    p.add_argument("-m", "--message", default="-")
    p.add_argument("--ctx", help="context string file (default: empty)")
    p.add_argument("--rnd", help="hex: 32 byte hedged randomness")
    p.add_argument("--out", default="sig.bin")
    p.set_defaults(func=cmd_sig_sign)

    p = sub.add_parser("sig-verify", help="ML-DSA verification")
    p.add_argument("-a", "--algorithm", default="ML-DSA-65", choices=list(params.MLDSA_SETS))
    p.add_argument("--pk", default="pk.bin")
    p.add_argument("-m", "--message", default="-")
    p.add_argument("--ctx", help="context string file (default: empty)")
    p.add_argument("--signature", default="sig.bin")
    p.set_defaults(func=cmd_sig_verify)

    p = sub.add_parser("combine", help="combine a classical and a PQ shared secret")
    p.add_argument("--first", required=True, help="classical shared secret")
    p.add_argument("--second", required=True, help="PQ shared secret")
    p.set_defaults(func=cmd_kem_hash)

    p = sub.add_parser("hybrid-demo", help="end-to-end hybrid KEM demo")
    p.add_argument("-a", "--algorithm", default="ML-KEM-768", choices=list(params.MLKEM_SETS))
    p.set_defaults(func=cmd_hybrid_demo)

    p = sub.add_parser("self-test", help="run built-in correctness tests")
    p.set_defaults(func=cmd_self_test)

    p = sub.add_parser("bench", help="rough single-operation timings")
    p.set_defaults(func=cmd_bench)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "list":
        pass
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    print(_BANNER.format(version=__version__), file=sys.stderr)
    raise SystemExit(main())