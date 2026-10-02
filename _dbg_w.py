"""Which reconstruction of w differs from the committed one only by z?

UseHint(h, r) returns HighBits(r) or HighBits(r + z).  So the pair (signing
argument, verify reconstruction) must satisfy  arg = recon  or  arg = recon + z
coefficientwise.  Measure all candidate differences numerically.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa
from quantumpost.ntt import centered

Q, N = 8380417, 256
p = get_mldsa('ML-DSA-44')
pk, sk = mldsa.generate_keypair(p)
obj = mldsa._sk_decode(p, sk)

y = [mldsa._poly_uniform_gamma1(p.gamma1, b'\x07' * 32, i) for i in range(p.ell)]
c = mldsa._sample_in_ball(b'\x42' * 32)
c_hat = mldsa._ntt(c)

z = [mldsa._ntt([(a + b) % Q for a, b in
                 zip(y[i], mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i])))])
     for i in range(p.ell)]

t = []
for i in range(p.k):
    acc = list(obj['s2'][i])
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul_coeff(mldsa._matrix_entry(obj['rho'], i, j), obj['s1'][j]))]
    t.append(acc)
t1 = [[mldsa._power2round(cc)[0] for cc in poly] for poly in t]
t0 = [[mldsa._power2round(cc)[1] for cc in poly] for poly in t]
t0_hat = [mldsa._ntt(poly) for poly in t0]

Az = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.ell):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), z[j]))]
    Az.append(mldsa._inv_ntt(acc))

scaled = [mldsa._ntt([(cc * (1 << 13)) % Q for cc in t1[i]]) for i in range(p.k)]
ct1 = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, scaled[i])) for i in range(p.k)]
wapp = [[(a - b) % Q for a, b in zip(Az[i], ct1[i])] for i in range(p.k)]

# signing-side candidates
Ay = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.ell):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j),
                                     mldsa._ntt(y[j])))]
    Ay.append(mldsa._inv_ntt(acc))

cs2 = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i])) for i in range(p.k)]
csq_ell = [0] * N
for i in range(p.ell):
    csq_ell = [(a + b) % Q for a, b in
               zip(csq_ell, mldsa._inv_ntt(mldsa._ntt_mul(
                   c_hat, mldsa._ntt_mul(t0_hat[i], mldsa._ntt(y[i])))))]

zc = [mldsa._inv_ntt(zz) for zz in z]

cands = {
    'Ay - csq_ell': [[(Ay[i][j] - csq_ell[j]) % Q for j in range(N)] for i in range(p.k)],
    'Ay - csq_ell + z': [[(Ay[i][j] - csq_ell[j] + zc[i][j]) % Q for j in range(N)] for i in range(p.k)],
    'Ay - cs2 - csq + z': [[(Ay[i][j] - cs2[i][j] - csq_ell[j] + zc[i][j]) % Q for j in range(N)] for i in range(p.k)],
    'Ay - cs2 - csq': [[(Ay[i][j] - cs2[i][j] - csq_ell[j]) % Q for j in range(N)] for i in range(p.k)],
}

for label, arg in cands.items():
    zero = all(all(arg[i][j] == wapp[i][j] for j in range(N)) for i in range(p.k))
    plusz = all(all((arg[i][j] - wapp[i][j]) % Q == zc[i][j] for j in range(N)) for i in range(p.k))
    minusz = all(all((arg[i][j] - wapp[i][j]) % Q == (-zc[i][j]) % Q for j in range(N)) for i in range(p.k))
    print(f'{label:22s} ==w:{zero}  ==w+z:{plusz}  ==w-z:{minusz}')