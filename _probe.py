"""Locate s1/s2/t0 inside the official ML-DSA private key by direct probing."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost.mldsa import _xof
from quantumpost.utils import bitpack, bitunpack

Q = 8380417
T = os.environ['TEMP'] + r'\acvp'
data = json.load(open(os.path.join(T, 'ML-DSA-keyGen-FIPS204__internalProjection.json')))
P = {'ML-DSA-44': (4, 4, 2), 'ML-DSA-65': (6, 5, 4), 'ML-DSA-87': (8, 7, 2)}


def cbd(eta, rho_prime, mu):
    bits = _xof(rho_prime + mu.to_bytes(2, 'little'), 64 * eta)
    out = []
    for i in range(256):
        o = 2 * eta * i
        x = sum((bits[(o + j) // 8] >> ((o + j) % 8)) & 1 for j in range(eta))
        y = sum((bits[(o + eta + j) // 8] >> ((o + eta + j) % 8)) & 1 for j in range(eta))
        out.append(x - y)
    return out


for g in data['testGroups']:
    name = g['parameterSet']
    k, ell, eta = P[name]
    tc = g['tests'][0]
    seed = bytes.fromhex(tc['seed'])
    sk = bytes.fromhex(tc['sk'])
    exp = _xof(seed + bytes((k, ell)), 128)
    rho_prime = exp[32:64]

    print(f'--- {name} k={k} eta={eta} sk={len(sk)}')
    for mu in range(k + 4):
        poly = cbd(eta, rho_prime, mu)
        for width in (eta, 13):
            packed = bitpack(width, [c % (1 << width) for c in poly])
            idx = sk.find(packed[:24])
            if idx != -1:
                print(f'   cbd(mu={mu}) width={width} -> sk offset {idx}')
                break