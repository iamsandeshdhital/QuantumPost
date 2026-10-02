"""Regression check: ML-DSA keyGen must stay byte-exact against NIST ACVP.

Run manually (the vectors are not vendored in the repository):

    python tools/check_acvp.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantumpost import mldsa, mlkem  # noqa: E402
from quantumpost.params import get_mldsa, get_mlkem  # noqa: E402

ACVP_DIR = Path(os.environ.get("ACVP_DIR", Path.home() / "acvp"))


def _load(name: str) -> dict | None:
    path = ACVP_DIR / name
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_mldsa_keygen() -> bool:
    expected = _load("ML-DSA-keyGen-FIPS204__expectedResults.json")
    prompt = _load("ML-DSA-keyGen-FIPS204__prompt.json")
    if not expected or not prompt:
        print("skip ML-DSA keyGen: ACVP vectors not found in", ACVP_DIR)
        return True
    param_of = {g["tgId"]: g["parameterSet"] for g in prompt["testGroups"]}
    seed_of = {t["tcId"]: t["seed"] for g in prompt["testGroups"] for t in g["tests"]}
    ok = total = 0
    for group in expected["testGroups"]:
        spec = get_mldsa(param_of[group["tgId"]])
        for case in group["tests"]:
            pk, sk = mldsa.keypair_from_seed(spec, bytes.fromhex(seed_of[case["tcId"]]))
            total += 1
            ok += pk == bytes.fromhex(case["pk"]) and sk == bytes.fromhex(case["sk"])
    print(f"ML-DSA keyGen byte-exact: {ok}/{total}")
    return ok == total


def check_mldsa_sigver() -> tuple[bool, bool]:
    """Returns ``(all_negative_ok, all_positive_ok)``."""
    proj = _load("ML-DSA-sigVer-FIPS204__internalProjection.json")
    res = _load("ML-DSA-sigVer-FIPS204__expectedResults.json")
    if not proj or not res:
        print("skip ML-DSA sigVer: ACVP vectors not found in", ACVP_DIR)
        return True, True
    expect = {t["tcId"]: t["testPassed"] for g in res["testGroups"] for t in g["tests"]}
    neg_ok = neg_total = pos_ok = pos_total = 0
    for group in proj["testGroups"]:
        if group.get("preHash") != "pure":
            continue
        spec = get_mldsa(group["parameterSet"])
        for case in group["tests"]:
            tc = case["tcId"]
            if tc not in expect or "message" not in case:
                continue
            ctx = bytes.fromhex(case["context"]) if case.get("context") else b""
            got = mldsa.verify(spec, bytes.fromhex(case["pk"]),
                               bytes.fromhex(case["message"]),
                               bytes.fromhex(case["signature"]), ctx=ctx)
            if expect[tc]:
                pos_total += 1
                pos_ok += got == expect[tc]
            else:
                neg_total += 1
                neg_ok += got == expect[tc]
    print(f"ML-DSA sigVer negative cases: {neg_ok}/{neg_total} correct")
    print(f"ML-DSA sigVer positive cases: {pos_ok}/{pos_total} correct")
    return neg_ok == neg_total, pos_ok == pos_total


def check_mlkem_roundtrip() -> bool:
    ok = True
    for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        spec = get_mlkem(name)
        ek, dk = mlkem.generate_keypair(spec)
        ss_a, ct = mlkem.encapsulate(spec, ek)
        ss_b = mlkem.decapsulate(spec, dk, ct)
        bad = bytearray(ct)
        bad[0] ^= 1
        rejected = mlkem.decapsulate(spec, dk, bytes(bad)) != ss_a
        good = ss_a == ss_b and rejected
        ok &= good
        print(f"ML-KEM {name:<12} round trip + implicit rejection: "
              f"{'ok' if good else 'FAIL'}")
    return ok


def main() -> int:
    print("QuantumPost conformance check")
    print("-" * 40)
    results = [check_mldsa_keygen(), check_mlkem_roundtrip()]
    neg_ok, pos_ok = check_mldsa_sigver()
    results.extend([neg_ok, pos_ok])
    print("-" * 40)
    if all(results):
        print("all executed checks passed")
        return 0
    print("one or more checks did not pass")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())