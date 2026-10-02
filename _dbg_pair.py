"""Pin down the ML-DSA hint relation algebraically.

UseHint(h, r') recovers HighBits(r) when r = r' + z (or r = r').  So the
correct pairing requires, for every coefficient,
    hint_argument - w_approx  ==  z   (mod q)
Testing that identity directly identifies the right combination without
guessing.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa

Q, N = 8380417, 256
p = get_mldsa('ML-DSA-44')
pk, sk = mldsa.generate_keypair(p)
obj = mldsa._sk_decode(p, sk)

y = [mldsa._poly_uniform_gamma1(p.gamma1, b'\x07' * 32, i) for i in range(p.ell)]
c = mldsa._sample_in_ball(b'\x42' * 32)
c_hat = mldsa._ntt(c)

z = []
for i in range(p.ell):
    corr = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i]))
    z.append([(a + b) % Q for a, b in zip(y[i], corr)])

w = []
for i in range(p.k):
    acc = list(obj['s2'][i])
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), y[j]))]
    w.append(acc)

# t in coefficient domain, split into t1 / t0
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

# verify-side w_approx = A z - c * t1 * 2^d
wapp = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j),
                                     mldsa._ntt(z[j])))]
    scaled = mldsa._ntt([(cc * (1 << 13)) % Q for cc in t1[i]])
    acc = [(a - b) % Q for a, b in zip(acc, mldsa._ntt_mul(c_hat, scaled))]
    wapp.append(mldsa._inv_ntt(acc))

csq = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat,
       mldsa._ntt_mul(t0_hat[i], mldsa._ntt(y[i])))) for i in range(p.k)]

cands = {
    'w - csq': [[(w[i][j] - csq[i][j]) % Q for j in range(N)] for i in range(p.k)],
    'w + s2 - csq': [[(w[i][j] + obj['s2'][i][j] - csq[i][j]) % Q for j in range(N)] for i in range(p.k)],
    'w - cs2 + csq': [[(w[i][j] - mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i]))[j] + csq[i][j]) % Q
                      for j in range(N)] for i in range(p.k)],
    'w - cs2 - csq': [[(w[i][j] - mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i]))[j] - csq[i][j]) % Q
                      for j in range(N)] for i in range(p.k)],
}

for label, arg in cands.items():
    for sgn, zz in (('+z', z), ('-z', [[(-v) % Q for v in poly] for poly in z])):
        ok = all(all((arg[i][j] - wapp[i][j]) % Q == zz[i][j] for j in range(N))
                 for i in range(p.k))
        if ok:
            print(f'MATCH: arg = {label}, difference = {sgn}')
print('done')