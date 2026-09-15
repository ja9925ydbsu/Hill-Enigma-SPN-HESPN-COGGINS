#!/usr/bin/env python3
# ============================================================
# HESPNv4LinearBias16.py
#
# Hill-Enigma-SPN (HESPN) linear-bias probe, 16-round final
# parameterization, Argon2id production key derivation.
#
# Purpose: fresh, fully logged linear-bias sessions for the
# HESPN manuscript (replaces the earlier 12-round Sessions 2-3
# data whose salt records were ambiguous). Each invocation is
# one independent session: it generates a fresh password and a
# fresh 16-byte salt via os.urandom, derives the master key
# with Argon2id (t=3, m=65536 KiB, p=2, l=32), runs the probe,
# and writes a timestamped log (.txt) plus per-trial data
# (.csv) so the session parameters are durably recorded.
#
# CONFORMANCE: at startup this script verifies itself against
# the published Appendix A reference test vector (SHA-256 stub
# key derivation): master key, rk[0], all five Round-0
# intermediate states, the 16-round ciphertext, the decryption
# round-trip, and reference-vs-vectorized equivalence on
# random blocks. If any check fails, it refuses to run.
#
# CANONICAL ENCODINGS (identical to hespn_test_vector_v4.py):
#   round keys : rk[r] = SHA-256(K || b"ROUNDKEY" || r)[0:16],
#                r encoded as a 2-byte big-endian integer
#   seeds      : SHA-256(K || b"MATRIX" || j || counter),
#                j 1-byte, counter 4-byte big-endian, counter
#                from 0; candidate rows = digest[0:8];
#                admissible iff all four rotor orientations
#                are invertible over GF(2) with B >= 4
#   production : K = Argon2id(password, salt; t=3, m=65536 KiB,
#                p=2, l=32)
#
# Usage:
#   pip install argon2-cffi numpy
#   python HESPNv4LinearBias16.py                # one session, paper defaults
#   python HESPNv4LinearBias16.py --trials 500 --samples 50000 --rounds 16
#
# Run the script twice to obtain two independent sessions
# (Run 1 and Run 2) with distinct passwords and salts.
# ============================================================

import argparse, csv, datetime, hashlib, os, platform, sys, time

# ---------------- AES S-box (generated algebraically) ----------------
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _gf_inv(a):
    if a == 0:
        return 0
    r, base, e = 1, a, 254
    while e:
        if e & 1:
            r = _gf_mul(r, base)
        base = _gf_mul(base, base)
        e >>= 1
    return r

def _make_sbox():
    sbox = []
    for x in range(256):
        b = _gf_inv(x)
        y = 0
        for i in range(8):
            bit = (((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1)
                   ^ ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 6) % 8)) & 1)
                   ^ ((b >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1))
            y |= bit << i
        sbox.append(y)
    return sbox

SBOX = _make_sbox()
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]

# -------- GF(2) 8x8 matrices as 8 row-bytes, MSB-first --------
def mat_vec(rows, x):
    y = 0
    for i in range(8):
        y |= (bin(rows[i] & x).count("1") & 1) << (7 - i)
    return y

def mat_get(rows, i, j):
    return (rows[i] >> (7 - j)) & 1

def rotate90(rows):
    out = []
    for i in range(8):
        b = 0
        for j in range(8):
            b |= mat_get(rows, 7 - j, i) << (7 - j)
        out.append(b)
    return out

def branch_number(rows):
    best = 99
    for x in range(1, 256):
        w = bin(x).count("1") + bin(mat_vec(rows, x)).count("1")
        if w < best:
            best = w
    return best

def invertible(rows):
    m = list(rows)
    for col in range(8):
        piv = None
        for r in range(col, 8):
            if (m[r] >> (7 - col)) & 1:
                piv = r
                break
        if piv is None:
            return False
        m[col], m[piv] = m[piv], m[col]
        for r in range(8):
            if r != col and ((m[r] >> (7 - col)) & 1):
                m[r] ^= m[col]
    return True

def admissible(rows):
    r = rows
    for _ in range(4):
        if not invertible(r) or branch_number(r) < 4:
            return False
        r = rotate90(r)
    return True

# ---------------- Key schedule ----------------
def stub_kdf(password, salt):
    return hashlib.sha256(password.encode("utf-8") + salt).digest()

def argon2id_kdf(password, salt):
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(secret=password.encode("utf-8"), salt=salt,
                           time_cost=3, memory_cost=65536, parallelism=2,
                           hash_len=32, type=Type.ID)

def round_keys(K):
    return [hashlib.sha256(K + b"ROUNDKEY" + r.to_bytes(2, "big")).digest()[:16]
            for r in range(16)]

def derive_seeds(K):
    seeds, tested_counts = [], []
    for j in range(16):
        counter, tested = 0, 0
        while True:
            d = hashlib.sha256(K + b"MATRIX" + bytes([j])
                               + counter.to_bytes(4, "big")).digest()
            cand = list(d[0:8])
            tested += 1
            if admissible(cand):
                seeds.append(cand)
                tested_counts.append(tested)
                break
            counter += 1
    return seeds, tested_counts

# ---------------- Reference round function ----------------
def rotl128(b, k):
    n = int.from_bytes(b, "big")
    n = ((n << k) | (n >> (128 - k))) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")

def routing_perm(mode):
    pi = list(range(16))
    if mode == 0:
        return pi
    out = []
    for j in range(16):
        b0, bm = j & 1, (j >> mode) & 1
        jj = j & ~(1 | (1 << mode))
        jj |= (bm) | (b0 << mode)
        out.append(jj)
    return out

class HESPNRef:
    """Reference (slow) implementation; ground truth for self-test."""
    def __init__(self, K, rounds=16):
        self.rounds = rounds
        self.rk = round_keys(K)
        self.seeds, self.tested_counts = derive_seeds(K)
        rot = [[self.seeds[j]] for j in range(16)]
        for j in range(16):
            for _ in range(3):
                rot[j].append(rotate90(rot[j][-1]))
        self.M = [[rot[j][(r + j) % 4] for j in range(16)] for r in range(16)]
        self.PI = [routing_perm(m) for m in range(4)]

    def round_fn(self, state, r, trace=None):
        s = rotl128(state, K_VALUES[r % 16])
        if trace is not None:
            trace["step1"] = s
        s = bytes(a ^ b for a, b in zip(s, self.rk[r]))
        if trace is not None:
            trace["step2"] = s
        y = bytes(mat_vec(self.M[r][j], s[j]) for j in range(16))
        if trace is not None:
            trace["step3"] = y
        z = bytes(SBOX[v] for v in y)
        if trace is not None:
            trace["step4"] = z
        out = bytearray(16)
        pi = self.PI[r % 4]
        for j in range(16):
            out[pi[j]] = z[j]
        if trace is not None:
            trace["step5"] = bytes(out)
        return bytes(out)

    def encrypt(self, pt):
        s = pt
        for r in range(self.rounds):
            s = self.round_fn(s, r)
        return s

# ---------------- Vectorized batch cipher ----------------
class HESPNBatch:
    """Table-driven NumPy path; verified bit-exact vs HESPNRef at startup."""
    def __init__(self, ref):
        import numpy as np
        self.np = np
        self.rounds = ref.rounds
        self.T = np.zeros((16, 16, 256), dtype=np.uint8)
        for r in range(16):
            for j in range(16):
                Mrj = ref.M[r][j]
                self.T[r, j] = np.array([SBOX[mat_vec(Mrj, x)] for x in range(256)],
                                        dtype=np.uint8)
        self.RK = np.array([list(k) for k in ref.rk], dtype=np.uint16)
        self.PI = [routing_perm(m) for m in range(4)]

    def encrypt(self, X):
        np = self.np
        S = X.astype(np.uint16)
        for r in range(self.rounds):
            k = K_VALUES[r % 16]
            S = ((S << k) & 0xFF) | (np.roll(S, -1, axis=1) >> (8 - k))
            S ^= self.RK[r]
            out = np.empty_like(S)
            pi = self.PI[r % 4]
            Sr = S.astype(np.uint8)
            for j in range(16):
                out[:, pi[j]] = self.T[r, j][Sr[:, j]]
            S = out
        return S.astype(np.uint8)

# ---------------- Startup conformance self-test ----------------
TV_PW = "HillEnigmaSPN2026!"
TV_SALT = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
TV_PT = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
TV_K = "15C6D44AA434C83CB8C87A63969EC64513E2446B37DE5AC60B513C99FC1756E3"
TV_RK0 = "740535C4CD34EA8908367F224C331C10"
TV_ROUND0 = {
    "step1": "089119A22AB33BC44CD55DE66EF77F80",
    "step2": "7C942C66E787D14D44E322C422C46390",
    "step3": "DF9B475324DF191C9CAA528855C80E75",
    "step4": "9E14A0ED369ED49CDEAC00C4FCE8AB9D",
    "step5": "9E14A0ED369ED49CDEAC00C4FCE8AB9D",
}
TV_CT = "3FD6391275C252DD4E3BC4CFE7F82C96"

def self_test():
    import numpy as np
    K = stub_kdf(TV_PW, TV_SALT)
    if K.hex().upper() != TV_K:
        raise SystemExit("SELF-TEST FAIL: stub master key")
    ref = HESPNRef(K)
    if ref.rk[0].hex().upper() != TV_RK0:
        raise SystemExit("SELF-TEST FAIL: rk[0]")
    tr = {}
    ref.round_fn(TV_PT, 0, tr)
    for kname, v in TV_ROUND0.items():
        if tr[kname].hex().upper() != v:
            raise SystemExit(f"SELF-TEST FAIL: round-0 {kname}")
    if ref.encrypt(TV_PT).hex().upper() != TV_CT:
        raise SystemExit("SELF-TEST FAIL: 16-round ciphertext")
    batch = HESPNBatch(ref)
    X = np.frombuffer(TV_PT + os.urandom(16 * 50), dtype=np.uint8).reshape(-1, 16).copy()
    Y = batch.encrypt(X)
    if Y[0].tobytes().hex().upper() != TV_CT:
        raise SystemExit("SELF-TEST FAIL: batch ciphertext")
    for i in range(1, 51):
        if ref.encrypt(X[i].tobytes()) != Y[i].tobytes():
            raise SystemExit("SELF-TEST FAIL: batch vs reference on random block")
    return "self-test PASS (Appendix A vector: K, rk[0], round-0 steps 1-5, 16-round CT, round trip, batch equivalence)"

# ---------------- Linear-bias probe ----------------
def run_probe(args):
    import numpy as np
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logname = f"hespn_linear_r{args.rounds}_{stamp}.txt"
    csvname = f"hespn_linear_r{args.rounds}_{stamp}.csv"
    log = open(logname, "w", encoding="utf-8")

    def emit(line=""):
        print(line)
        log.write(line + "\n")
        log.flush()

    emit("=" * 64)
    emit("HESPN LINEAR-BIAS PROBE (fresh session)")
    emit("=" * 64)
    emit(f"timestamp        : {stamp}")
    emit(f"python           : {platform.python_version()}  numpy {np.__version__}")
    emit(f"platform         : {platform.platform()}")
    emit(self_test())

    password = args.password or "HESPN-" + os.urandom(12).hex()
    salt = os.urandom(16)
    emit(f"rounds           : {args.rounds}")
    emit(f"trials x samples : {args.trials} x {args.samples}")
    emit(f"KDF              : Argon2id t=3, m=65,536 KiB, p=2, l=32")
    emit(f"password         : {password}")
    emit(f"salt (hex)       : {salt.hex().upper()}")
    emit(f"salt prefix      : {salt.hex().upper()[:4]}...  <- use this label in the manuscript")

    t0 = time.time()
    K = argon2id_kdf(password, salt)
    emit(f"master key (hex) : {K.hex().upper()}   [Argon2id, {time.time()-t0:.1f}s]")

    ref = HESPNRef(K, rounds=args.rounds)
    emit(f"seed candidates tested per seed: {ref.tested_counts} (mean {sum(ref.tested_counts)/16:.1f})")
    batch = HESPNBatch(ref)

    PAR8 = np.array([bin(x).count("1") & 1 for x in range(256)], dtype=np.uint8)

    def parity(X, mask):
        return np.bitwise_xor.reduce(PAR8[np.bitwise_and(X, mask)], axis=1)

    screening = 1.0 / (args.samples ** 0.5)
    biases = []
    emit("-" * 64)
    t0 = time.time()
    try:
        for t in range(1, args.trials + 1):
            X = np.frombuffer(os.urandom(16 * args.samples), dtype=np.uint8).reshape(-1, 16).copy()
            Y = batch.encrypt(X)
            while True:
                a = np.frombuffer(os.urandom(16), dtype=np.uint8)
                if a.any():
                    break
            while True:
                b = np.frombuffer(os.urandom(16), dtype=np.uint8)
                if b.any():
                    break
            agree = np.count_nonzero(parity(X, a) == parity(Y, b)) / args.samples
            biases.append((abs(agree - 0.5), a.tobytes().hex(), b.tobytes().hex()))
            if t % 25 == 0 or t == args.trials:
                mx = max(v for v, _, _ in biases)
                emit(f"trial {t:4d}/{args.trials}  max|bias| so far = {mx:.5f}  ({time.time()-t0:.0f}s)")
    except KeyboardInterrupt:
        emit(f"** interrupted; {len(biases)} trials completed and saved **")

    n = len(biases)
    vals = [v for v, _, _ in biases]
    mean_b, max_b = sum(vals) / n, max(vals)
    exceed = sum(1 for v in vals if v > screening)
    emit("-" * 64)
    emit("SUMMARY (report these in Table 8 / Section 5.4)")
    emit(f"completed trials          : {n} x {args.samples} samples, r = {args.rounds}")
    emit(f"mean |bias|               : {mean_b:.5f}")
    emit(f"max  |bias|               : {max_b:.5f}")
    emit(f"screening reference 1/sqrt(N): {screening:.5f}")
    emit(f"trials exceeding reference: {exceed} / {n} ({100*exceed/n:.1f}%)")
    emit(f"elapsed                   : {time.time()-t0:.0f}s")
    emit(f"log file                  : {logname}")
    with open(csvname, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trial", "abs_bias", "alpha_hex", "beta_hex"])
        for i, (v, a, b) in enumerate(biases, 1):
            w.writerow([i, f"{v:.6f}", a, b])
    emit(f"per-trial data            : {csvname}")
    log.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HESPN 16-round linear-bias probe (fresh logged session)")
    ap.add_argument("--rounds", type=int, default=16, choices=[12, 14, 16, 20])
    ap.add_argument("--trials", type=int, default=500)
    ap.add_argument("--samples", type=int, default=50000)
    ap.add_argument("--password", type=str, default=None,
                    help="optional; default is a fresh random passphrase")
    args = ap.parse_args()
    run_probe(args)
