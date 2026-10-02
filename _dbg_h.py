"""Numerically identify the hint relation: compare candidate args to w' and w'+z."""
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
z = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i])) for i in range(p.ell)]
z = [[(a + b) % Q for a, b in zip(y[i], z[i])] for i in range(p.ell)]

t = []
for i in range(p.k):
    acc = list(obj['s2'][i])
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul_coeff(mldsa._matrix_entry(obj['rho'], i, j), obj['s1'][j]))]
    t.append(acc)
t1 = [mldsa._ntt([mldsa._power2round(cc)[0] for cc in poly]) for poly in t]
t0_hat = [mldsa._ntt([mldsa._power2round(cc)[1] for cc in poly]) for poly in t]

Ay = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.ell):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), mldsa._ntt(y[j])))]
    Ay.append(mldsa._inv_ntt(acc))

Az = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.ell):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), mldsa._ntt(z[j])))]
    Az.append(mldsa._inv_ntt(acc))

ct1 = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, t1[i])) for i in range(p.k)]
wapp = [[(a - b) % Q for a, b in zip(Az[i], ct1[i])] for i in range(p.k)]

cs2 = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i])) for i in range(p.k)]
csq = [0] * N
for i in range(p.ell):
    csq = [(a + b) % Q for a, b in zip(csq, mldsa._inv_ntt(
        mldsa._ntt_mul(c_hat, mldsa._ntt_mul(t0_hat[i], mldsa._ntt(y[i])))))]

w = [[(a + b) % Q for a, b in zip(Ay[i], obj['s2'][i])] for i in range(p.k)]

cands = {
    'w - c*s2 + c*t0*y': [[(w[i][j] - cs2[i][j] + csq[j]) % Q for j in range(N)] for i in range(p.k)],
    'w + s2 - c*t0*y': [[(w[i][j] + obj['s2'][i][j] - csq[j]) % Q for j in range(N)] for i in range(p.k)],
}
for label, arg in cands.items():
    eq = all(all(arg[i][j] == wapp[i][j] for j in range(N)) for i in range(p.k))
    plusz = all(all((arg[i][j] - wapp[i][j]) % Q == z[i][j] for j in range(N)) for i in range(p.k))
    print(f'{label:22s}: arg==w\' {eq}   arg-w\'==z {plusz}')
    if not plusz and not eq:
        i, j = next((i, j) for i in range(p.k) for j in range(N)
                    if arg[i][j] != wapp[i][j] and (arg[i][j] - wapp[i][j]) % Q != z[i][j])
        print('   sample diff at', i, j, 'arg', arg[i][j], "w'", wapp[i][j], 'z', z[i][j])