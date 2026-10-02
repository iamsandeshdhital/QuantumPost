"""Empirically determine the ML-DSA hint relation that makes sign/verify agree.

FIPS 204 defines the hint on a combination of ``w``, ``c``, ``s2`` and
``t0*y``; several readings of that prose are algebraically plausible.  Rather
than guess, this script tries each candidate hint argument and checks whether
the resulting signature actually verifies under the standard verification
equation.  The candidate that verifies is the correct one.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa

Q, N = 8380417, 256


def trial(p, variant, tries=200):
    pk, sk = mldsa.generate_keypair(p)
    obj = mldsa._sk_decode(p, sk)
    message = b'consistency probe'
    rnd = os.urandom(32)
    gamma1, gamma2, beta = p.gamma1, p.gamma2, p.beta

    mu = mldsa._h(obj['tr'] + message)
    rho_pp = mldsa._h(obj['key'] + rnd + mu)
    kappa = 0
    accepted = 0
    for _ in range(tries):
        y = [mldsa._poly_uniform_gamma1(gamma1, rho_pp, kappa + i) for i in range(p.ell)]
        w = []
        for i in range(p.k):
            acc = list(obj['s2'][i])
            for j in range(p.k):
                acc = [(a + b) % Q for a, b in
                       zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), y[j]))]
            w.append(acc)
        w1 = [mldsa._high_bits(poly) for poly in w]
        c_tilde = mldsa._h(mu + b''.join(mldsa._w1_encode(poly) for poly in w1))
        c = mldsa._sample_in_ball(c_tilde)
        c_hat = mldsa._ntt(c)

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
            r0.extend(mldsa._decompose(cc, gamma1, gamma2)[1] for cc in w_cs2[i])

        if mldsa._max_abs([cc for poly in z for cc in poly]) >= gamma1 - beta:
            kappa += p.ell
            continue
        if mldsa._max_abs(r0) >= gamma2 - beta:
            kappa += p.ell
            continue

        csq = [mldsa._inv_ntt(mldsa._ntt_mul(c_hat,
               mldsa._ntt_mul(obj['t0_hat'][i], mldsa._ntt(y[i])))) for i in range(p.k)]

        if variant == 'A':       # hint on  w - c*s2 + c*t0*y
            arg = [[(w_cs2[i][j] + csq[i][j]) % Q for j in range(N)] for i in range(p.k)]
        elif variant == 'B':     # hint on  w - c*s2 + c*t0
            arg = [[(w_cs2[i][j] + mldsa._inv_ntt(mldsa._ntt_mul(c_hat, obj['t0_hat'][i]))[j]) % Q
                    for j in range(N)] for i in range(p.k)]
        elif variant == 'C':     # hint on  w + s2 - c*t0*y
            arg = [[(w[i][j] + obj['s2'][i][j] - csq[i][j]) % Q for j in range(N)]
                   for i in range(p.k)]
        else:                     # 'D': hint on w - c*t0*y  (no s2 term)
            arg = [[(w[i][j] - csq[i][j]) % Q for j in range(N)] for i in range(p.k)]

        hints = bytearray()
        count = 0
        for i in range(p.k):
            for j in range(N):
                h = mldsa._make_hint(z[j][i], arg[i][j], gamma1, gamma2)
                hints.append(h)
                count += h
        if count > p.omega:
            kappa += p.ell
            continue

        packed_z = b''.join(
            mldsa.bitpack(p.z_bits, [mldsa.centered(cc, Q) % p.gamma1 for cc in poly])
            for poly in z)
        sig = c_tilde + packed_z + bytes(hints)
        if mldsa.verify(p, pk, message, sig):
            return True, accepted + 1, count
        kappa += p.ell
    return False, tries, None


p = get_mldsa('ML-DSA-44')
for variant in ('A', 'B', 'C', 'D'):
    ok, tries, hints = trial(p, variant, tries=60)
    print(f'variant {variant}: verifies={ok} tries={tries} hints={hints}')