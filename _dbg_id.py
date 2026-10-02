"""Find which expression satisfies arg == w_approx +/- z (coefficientwise)."""
import itertools, os, sys
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
    z.append([(a + b) % Q for a, b in
              zip(y[i], mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i])))])

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

Ay = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), mldsa._ntt(y[j])))]
    Ay.append(mldsa._inv_ntt(acc))

Az = []
for i in range(p.k):
    acc = [0] * N
    for j in range(p.k):
        acc = [(a + b) % Q for a, b in
               zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), mldsa._ntt(z[j])))]
    Az.append(mldsa._inv_ntt(acc))

terms = {
    's2': obj['s2'],
    'c*s2': [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i])) for i in range(p.k)],
    'c*t0': [mldsa._inv_ntt(mldsa._ntt_mul(c_hat, t0_hat[i])) for i in range(p.k)],
    'c*t0*y': [mldsa._inv_ntt(mldsa._ntt_mul(c_hat,
              mldsa._ntt_mul(t0_hat[i], mldsa._ntt(y[i])))) for i in range(p.k)],
}
names = list(terms)

# w_approx = A z - c * t1 * 2^d
wapp = []
for i in range(p.k):
    scaled = mldsa._ntt([(cc * (1 << 13)) % Q for cc in t1[i]])
    wapp.append([(a - b) % Q for a, b in
                 zip(Az[i], mldsa._inv_ntt(mldsa._ntt_mul(c_hat, scaled)))])

print('Ay == Az ?', Ay == Az, '(should be False)')
found = []
for r in (1, 2, 3):
    for combo in itertools.combinations(names, r):
        for signs in itertools.product((1, -1), repeat=r):
            for target, tname in ((+1, 'w+'), (-1, 'w-')):
                ok = True
                for i in range(p.k):
                    zz = target * z[i]
                    for jj in range(N):
                        val = wapp[i][jj]
                        for nm, sg in zip(combo, signs):
                            val = (val + sg * terms[nm][i][jj]) % Q
                        if val != zz[jj]:
                            ok = False
                            break
                    if not ok:
                        break
                if ok:
                    found.append((tname, combo, signs))
                    print('MATCH', tname, combo, signs)
print('matches:', len(found))