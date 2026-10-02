"""Brute-force how K = sk[32:64] is derived from the ACVP seed."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost.mldsa import _xof
from quantumpost.hashes import sha3_512, sha3_256

T = os.environ['TEMP'] + r'\acvp'
data = json.load(open(os.path.join(T, 'ML-DSA-keyGen-FIPS204__internalProjection.json')))
P = {'ML-DSA-44': (4, 4), 'ML-DSA-65': (6, 5), 'ML-DSA-87': (8, 7)}

for g in data['testGroups']:
    name = g['parameterSet']
    k, ell = P[name]
    tc = g['tests'][0]
    seed = bytes.fromhex(tc['seed'])
    sk = bytes.fromhex(tc['sk'])
    want = sk[32:64]

    hits = []
    # 2-byte suffixes
    for a in range(256):
        for b in range(256):
            if _xof(seed + bytes((a, b)), 32) == want:
                hits.append(f'shake32(xi||{a},{b})')
            if _xof(seed + bytes((a, b)), 128)[64:96] == want:
                hits.append(f'shake128(xi||{a},{b})[64:96]')
            if _xof(seed + bytes((a, b)), 128)[32:64] == want:
                hits.append(f'shake128(xi||{a},{b})[32:64]')
        if hits:
            break
    # hash-based without suffix
    if not hits:
        if sha3_512(seed)[32:64] == want:
            hits.append('sha3_512(xi)[32:64]')
        if sha3_256(seed) == want:
            hits.append('sha3_256(xi)')
        if _xof(seed, 64)[32:64] == want:
            hits.append('shake256(xi,64)[32:64]')
    print(f'{name}: {hits if hits else "no match"}  (k={k} ell={ell})')