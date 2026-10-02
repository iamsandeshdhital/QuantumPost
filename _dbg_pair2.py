"""Decisive: test which signing hint argument verifies under my verify().

For each candidate argument the script builds the signature and asks
``mldsa.verify`` whether it accepts.  The pairing that verifies is the one this
implementation must use.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantumpost import mldsa
from quantumpost.params import get_mldsa

Q, N = 8380417, 256
p = get_mldsa('ML-DSA-44')


def build(variant):
    pk, sk = mldsa.generate_keypair(p)
    obj = mldsa._sk_decode(p, sk)
    message = b'pairing probe'
    rnd = os.urandom(32)
    gamma1, gamma2, beta = p.gamma1, p.gamma2, p.beta

    mu = mldsa._h(obj['tr'] + message)
    rho_pp = mldsa._h(obj['key'] + rnd + mu)
    kappa = 0
    for _ in range(400):
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

        csq = [0] * N
        for i in range(p.ell):
            csq = [(a + b) % Q for a, b in zip(csq, mldsa._inv_ntt(
                mldsa._ntt_mul(c_hat, mldsa._ntt_mul(obj['t0_hat'][i], mldsa._ntt(y[i])))))]
        csq_k = [0] * N
        for i in range(p.k):
            csq_k = [(a + b) % Q for a, b in zip(csq_k, mldsa._inv_ntt(
                mldsa._ntt_mul(c_hat, mldsa._ntt_mul(obj['t0_hat'][i], mldsa._ntt(y[i])))))]

        y_ntt = [mldsa._ntt(poly) for poly in y]
        z_ntt = [mldsa._ntt(poly) for poly in z]

        if variant == 'A':   # w - c*s2 + c*t0*y  (summing over ell)
            arg = [[(w_cs2[i][j] + csq[j]) % Q for j in range(N)] for i in range(p.k)]
        elif variant == 'B':  # w + s2 - c*t0*y  (reference orientation)
            arg = [[(w[i][j] + obj['s2'][i][j] - csq[j]) % Q for j in range(N)]
                   for i in range(p.k)]
        elif variant == 'C':  # A z + c t0 - c s2  == verify recon + z
            arg = []
            for i in range(p.k):
                acc = [0] * N
                for j in range(p.ell):
                    acc = [(a + b) % Q for a, b in
                           zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), z_ntt[j]))]
                add = [(a + b - c_) % Q for a, b, c_ in zip(acc, mldsa._ntt_mul(c_hat, obj['t0_hat'][i]),
                                                            mldsa._ntt_mul(c_hat, obj['s2_hat'][i]))]
                arg.append(mldsa._inv_ntt(add))
        else:                # 'D': A z + c t0 - c s2 + s2  (include s2 term)
            arg = []
            for i in range(p.k):
                acc = [0] * N
                for j in range(p.ell):
                    acc = [(a + b) % Q for a, b in
                           zip(acc, mldsa._ntt_mul(mldsa._matrix_entry(obj['rho'], i, j), z_ntt[j]))]
                add = [(a + b - c_ + d) % Q for a, b, c_, d in zip(
                    acc, mldsa._ntt_mul(c_hat, obj['t0_hat'][i]),
                    mldsa._ntt_mul(c_hat, obj['s2_hat'][i]), mldsa._ntt(obj['s2'][i]))]
                arg.append(mldsa._inv_ntt(add))

        hints = bytearray()
        count = 0
        for i in range(p.k):
            for j in range(N):
                hints.append(mldsa._make_hint(z[i][j], arg[i][j], gamma1, gamma2))
                count += hints[-1]
        if count > p.omega:
            kappa += p.ell
            continue

        packed_z = b''.join(mldsa.bitpack(p.z_bits,
                                         [mldsa.centered(cc, Q) % p.gamma1 for cc in poly])
                            for poly in z)
        sig = c_tilde + packed_z + bytes(hints)
        return mldsa.verify(p, pk, message, sig), count
    return None, None


for v in ('A', 'B', 'C', 'D'):
    ok, hints = build(v)
    print(f'variant {v}: verifies={ok} hints={hints}')