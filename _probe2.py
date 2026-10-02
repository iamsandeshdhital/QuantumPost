"""Find how the official vectors derive K (sk[32:64]) and the seed layout."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost.mldsa import _xof
from quantumpost.hashes import sha3_512, sha3_256, shake256

T = os.environ['TEMP'] + r'\acvp'
data = json.load(open(os.path.join(T, 'ML-DSA-keyGen-FIPS204__internalProjection.json')))
P = {'ML-DSA-44': (4, 4), 'ML-DSA-65': (6, 5), 'ML-DSA-87': (8, 7)}

for g in data['testGroups']:
    name = g['parameterSet']
    k, ell = P[name]
    tc = g['tests'][0]
    seed = bytes.fromhex(tc['seed'])
    sk = bytes.fromhex(tc['sk'])
    want_key = sk[32:64]
    want_rho = sk[:32]

    print(f'--- {name} k={k} ell={ell}')
    cands = {
        'shake(xi||k||ell)[64:96]': _xof(seed + bytes((k, ell)), 128)[64:96],
        'shake(xi||k||ell)[32:64]': _xof(seed + bytes((k, ell)), 128)[32:64],
        'sha3_512(xi||k||ell)[32:64]': sha3_512(seed + bytes((k, ell)))[32:64],
        'sha3_256(xi||k||ell)': sha3_256(seed + bytes((k, ell))),
        'shake(xi||ell||k)[64:96]': _xof(seed + bytes((ell, k)), 128)[64:96],
        'shake(xi||k)[0:32]': _xof(seed + bytes((k,)), 32),
        'shake(xi||4||k)[64:96]': _xof(seed + bytes((4, k)), 128)[64:96],
    }
    for label, val in cands.items():
        mark = 'K' if val == want_key else ('rho' if val == want_rho else '')
        if mark:
            print(f'   {label} matches {mark}')
    print('   want K ', want_key.hex())
    print('   cand K ', cands['shake(xi||k||ell)[64:96]'].hex())