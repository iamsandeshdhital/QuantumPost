"""Determine the exact sign/verify consistency relation for ML-DSA hints."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa

Q, N = 8380417, 256
p = get_mldsa('ML-DSA-44')
pk, sk = mldsa.generate_keypair(p)
obj = mldsa._sk_decode(p, sk)
c = mldsa._sample_in_ball(b'\x42' * 32)
y = [mldsa._poly_uniform_gamma1(p.gamma1, b'\x07' * 32, i) for i in range(p.ell)]
c_hat = mldsa._ntt(c)

z = []
for i in range(p.ell):
    corr = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i]))
    z.append([(a + b) % Q for a, b in zip(y[i], corr)])

# w = A y + s2
w = []
for i in range(p.k):
    acc = list(obj['s2'][i])
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), y[j]))]
    w.append(acc)

# sign-side: w1 = w - c*s2 + c*t0*y
cs2 = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i])) for i in range(p.k)]
ct0y = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat,
          mldsa._ntt_mul(obj['t0_hat'][i], mldsa._ntt(y[i])))) for i in range(p.k)]
w1 = [[(w[i][j] - cs2[i][j] + ct0y[i][j]) % Q for j in range(N)] for i in range(p.k)]

# verify-side: w'approx = A z - c * 2^d * t1
t1_hat = [mldsa._ntt([mldsa._power2round(c_)[0] for c_ in obj['s2'][i]]) for i in range(p.k)]
# recompute t1 properly from sk: need t = A s1 + s2
t1 = []
for i in range(p.k):
    acc = list(obj['s2'][i])
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul_coeff(mldsa._matrix_entry(obj['rho'], i, j), obj['s1'][j]))]
    t1.append([mldsa._power2round(c_)[0] for c_ in acc])
t1_hat = [mldsa._ntt(poly) for poly in t1]

wapp = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j),
                                     mldsa._ntt(z[j])))]
    scaled = mldsa._ntt([(c_ * (1 << 13)) % Q for c_ in t1[i]])
    acc = [(a - b) % Q for a, b in zip(acc, mldsa._ntt_mul(c_hat, scaled))]
    wapp.append(mldsa._inv_ntt(acc))

print('w1 == wapp :', w1 == wapp)
diff = [i for i in range(p.k) if w1[i] != wapp[i]]
if diff:
    i = diff[0]
    j = next(j for j in range(N) if w1[i][j] != wapp[i][j])
    print('first diff at', i, j)
    print('  w1 ', w1[i][j])
    print('  wapp', wapp[i][j])
    # test the variant without +c*t0*y
    w1b = [[(w[i][j2] - cs2[i][j2]) % Q for j2 in range(N)] for i in range(p.k)]
    print('w - c*s2 == wapp :', w1b == wapp)