"""Instrument the ML-DSA signing loop (corrected index order and condition)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa

Q, N = 8380417, 256
p = get_mldsa('ML-DSA-44')
pk, sk = mldsa.generate_keypair(p)
obj = mldsa._sk_decode(p, sk)
message = b'hello'
rnd = os.urandom(32)

mu = mldsa._h(obj['tr'] + message)
rho_pp = mldsa._h(obj['key'] + rnd + mu)
print('bounds: gamma1-beta', p.gamma1 - p.beta,
      'gamma2-beta', p.gamma2 - p.beta, 'omega', p.omega)

kappa = 0
for attempt in range(4):
    y = [mldsa._poly_uniform_gamma1(p.gamma1, rho_pp, kappa + i) for i in range(p.ell)]
    w = []
    for i in range(p.k):
        acc = [0] * N
        for j in range(p.k):
            acc = [(a + b) % Q for a, b in
                   zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), y[j]))]
        w.append(acc)
    w1 = [mldsa._high_bits(poly) for poly in w]
    c_tilde = mldsa._h(mu + b''.join(mldsa._w1_encode(poly) for poly in w1))
    c_hat = mldsa._ntt(mldsa._sample_in_ball(c_tilde))

    z = []
    for i in range(p.ell):
        corr = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s1_hat'][i]))
        z.append([(a + b) % Q for a, b in zip(y[i], corr)])
    w_cs2 = []
    for i in range(p.k):
        corr = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['s2_hat'][i]))
        w_cs2.append([(a - b) % Q for a, b in zip(w[i], corr)])
    r0 = []
    for i in range(p.k):
        r0.extend(mldsa._decompose(c, p.gamma1, p.gamma2)[1] for c in w_cs2[i])

    okz = mldsa._max_abs([c for poly in z for c in poly]) < p.gamma1 - p.beta
    okr = mldsa._max_abs(r0) < p.gamma2 - p.beta
    print(f'attempt {attempt}: z ok={okz} ({mldsa._max_abs([c for poly in z for c in poly])})'
          f' r0 ok={okr} ({mldsa._max_abs(r0)})')

    total_hints = 0
    leaked = False
    for i in range(p.k):
        part = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['t0_hat'][i]))
        yy = mldsa._inv_ntt(mldsa._ntt_mul(c_hat, y[i]))
        csq = [(a - b) % Q for a, b in zip(part, yy)]
        combined = [(a + b) % Q for a, b in zip(w_cs2[i], csq)]
        bad = sum(1 for c in combined if mldsa._power2round(c)[1] != 0)
        if bad:
            leaked = True
        for j in range(N):
            total_hints += mldsa._make_hint(z[i][j], combined[j], p.gamma1, p.gamma2)
    print(f'   high-bit leak positions={bad}, hints={total_hints} (omega {p.omega})')
    if okz and okr and not leaked and total_hints <= p.omega:
        print('   ACCEPTED')
        break
    kappa += p.ell