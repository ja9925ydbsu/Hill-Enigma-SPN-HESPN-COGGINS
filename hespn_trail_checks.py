"""Trail and fixed-key endpoint checks for the HESPN Cryptologia manuscript.

Place in the repository root next to hespn_reference.py and run:

    python3 hespn_trail_checks.py

This is the author-review driver used to check one-active-S-box trails and
reduced-round fixed-key endpoint behavior. It requires NumPy. Differential
endpoint tests do not observe a particular internal characteristic round by
round, and linear endpoint tests include hull effects.
"""

import sys
import time
import numpy as np

sys.path.insert(0, ".")
from hespn_reference import *

RNG_SEED = 7
key = derive_master_key_stub(
    "HillEnigmaSPN2026!",
    bytes.fromhex("0102030405060708090A0B0C0D0E0F10"),
)
seeds = get_seed_matrices(key)
S = AES_SBOX

DDT = np.zeros((256, 256), int)
for x in range(256):
    for a in range(256):
        DDT[a, S[x] ^ S[x ^ a]] += 1

LAT = np.zeros((256, 256), int)
par = np.array([bin(i).count("1") & 1 for i in range(256)])
xs = np.arange(256)
sx = np.array(S)
for u in range(256):
    pu = par[xs & u]
    for v in range(256):
        LAT[u, v] = np.sum(pu == par[sx & v]) - 128


def transpose(rows):
    g = rows_to_grid(rows)
    return grid_to_rows([[g[j][i] for j in range(8)] for i in range(8)])


def onebyte(p, d, k):
    x = d << (8 * (15 - p))
    y = rotl128(x.to_bytes(16, "big"), k)
    nz = [(i, b) for i, b in enumerate(y) if b]
    return nz[0] if len(nz) == 1 else None


NEG = -1e9


def search(R, mode):
    # score[p,d] is the best log2 weight at byte position p with value d.
    score = np.zeros((16, 256))
    score[:, 0] = NEG
    best_hist = []
    for r in range(R):
        k = K_VALUES[r]
        mats = build_rotor_matrices_for_round(key, r, seeds=seeds)
        new = np.full((16, 256), NEG)
        for p in range(16):
            for d in range(1, 256):
                if score[p, d] <= NEG / 2:
                    continue
                t = onebyte(p, d, k)
                if t is None:
                    continue
                q, e = t
                if mode == "diff":
                    a = apply_matrix_8(mats[q], e)
                    row = DDT[a]
                    w = np.where(row > 0, np.log2(np.maximum(row, 1) / 256), NEG)
                else:
                    a = apply_matrix_8(transpose(gf2_mat_inverse_8(mats[q])), e)
                    row = np.abs(LAT[a])
                    w = np.where(row > 0, np.log2(np.maximum(row, 1) / 128), NEG)
                w[0] = NEG
                pq = routing_pi(r, q)
                cand = score[p, d] + w
                new[pq] = np.maximum(new[pq], cand)
        score = new
        best_hist.append(score.max())
    return best_hist


def best_trail(R, mode):
    score = np.zeros((16, 256))
    score[:, 0] = NEG
    back = []
    for r in range(R):
        k = K_VALUES[r]
        mats = build_rotor_matrices_for_round(key, r, seeds=seeds)
        new = np.full((16, 256), NEG)
        bp = {}
        for p in range(16):
            for d in range(1, 256):
                if score[p, d] <= NEG / 2:
                    continue
                t = onebyte(p, d, k)
                if t is None:
                    continue
                q, e = t
                if mode == "diff":
                    a = apply_matrix_8(mats[q], e)
                    row = DDT[a]
                    w = np.where(row > 0, np.log2(np.maximum(row, 1) / 256), NEG)
                else:
                    a = apply_matrix_8(transpose(gf2_mat_inverse_8(mats[q])), e)
                    row = np.abs(LAT[a])
                    w = np.where(row > 0, np.log2(np.maximum(row, 1) / 128), NEG)
                w[0] = NEG
                pq = routing_pi(r, q)
                cand = score[p, d] + w
                for b in np.where(cand > new[pq])[0]:
                    new[pq, b] = cand[b]
                    bp[(pq, b)] = (p, d, q, e, a)
        back.append(bp)
        score = new
    pq, b = np.unravel_index(np.argmax(score), score.shape)
    tot = score.max()
    path = []
    for r in reversed(range(R)):
        p, d, q, e, a = back[r][(pq, b)]
        path.append((r, p, d, q, e, a, pq, b))
        pq, b = p, d
    return tot, list(reversed(path))


Sa = np.array(S, dtype=np.uint8)
RK = [np.frombuffer(derive_round_key(key, r), dtype=np.uint8) for r in range(16)]


def mat_table(rows):
    return np.array([apply_matrix_8(rows, x) for x in range(256)], dtype=np.uint8)


TAB = [
    [mat_table(m) for m in build_rotor_matrices_for_round(key, r, seeds=seeds)]
    for r in range(16)
]
PI = [[routing_pi(r, j) for j in range(16)] for r in range(16)]


def enc(P, R):
    # P is N x 16 uint8.
    st = P.copy()
    for r in range(R):
        k = K_VALUES[r]
        bits = np.unpackbits(st, axis=1)
        bits = np.roll(bits, -k, axis=1)
        st = np.packbits(bits, axis=1)
        st ^= RK[r]
        for j in range(16):
            st[:, j] = Sa[TAB[r][j][st[:, j]]]
        out = np.empty_like(st)
        for j in range(16):
            out[:, PI[r][j]] = st[:, j]
        st = out
    return st


# Validate the vectorized implementation against the reference implementation.
pt = np.frombuffer(
    bytes.fromhex("00112233445566778899AABBCCDDEEFF"), dtype=np.uint8
)[None, :].copy()
assert enc(pt, 16)[0].tobytes() == encrypt_block(pt[0].tobytes(), key)

rng = np.random.default_rng(RNG_SEED)


def lincorr(R, N, chunk=1 << 21):
    tot, path = best_trail(R, "lin")
    p0, u0 = path[0][1], path[0][2]
    pe, ve = path[-1][6], path[-1][7]
    s = 0
    n = 0
    t = time.time()
    while n < N:
        m = min(chunk, N - n)
        P = rng.integers(0, 256, (m, 16), dtype=np.uint8)
        C = enc(P, R)
        a = (
            np.unpackbits((P[:, p0] & np.uint8(u0))[:, None], axis=1).sum(1)
            + np.unpackbits((C[:, pe] & np.uint8(ve))[:, None], axis=1).sum(1)
        )
        s += int((a % 2).sum())
        n += m
    c = 1 - 2 * s / n
    return tot, c, n, time.time() - t


if __name__ == "__main__":
    print("rng seed", RNG_SEED)
    print("max DDT", DDT[1:, 1:].max(), "max |LAT|", np.abs(LAT[1:, 1:]).max())
    print("implementation validation PASS")
    for mode in ["diff", "lin"]:
        print(
            mode,
            "Markov best one-active-S-box weights (log2):",
            [round(float(x), 1) for x in search(16, mode)],
        )
    for R in [2, 3]:
        tot, path = best_trail(R, "diff")
        p0, d0 = path[0][1], path[0][2]
        pe, be = path[-1][6], path[-1][7]
        N = 1 << 22 if R == 3 else 1 << 18
        Pp = rng.integers(0, 256, (N, 16), dtype=np.uint8)
        P2 = Pp.copy()
        P2[:, p0] ^= d0
        Dd = enc(Pp, R) ^ enc(P2, R)
        exp = np.zeros(16, np.uint8)
        exp[pe] = be
        print(
            "diff",
            R,
            "rounds: model log2",
            tot,
            "right pairs",
            int(np.all(Dd == exp, axis=1).sum()),
            "of",
            N,
        )
    for R, N in [(3, 1 << 22), (4, 1 << 22), (5, 1 << 24), (6, 1 << 27)]:
        tot, c, n, dt = lincorr(R, N)
        print(
            "lin",
            R,
            "rounds: model log2|c|",
            tot,
            "empirical c",
            c,
            "log2|c|",
            round(float(np.log2(abs(c))), 2),
        )
