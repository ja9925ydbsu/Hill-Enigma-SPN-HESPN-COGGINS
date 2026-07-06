#!/usr/bin/env python3
# ============================================================
# HESPNv4Confirm300.py
#
# Hill-Enigma-SPN (HESPN) 300-sequence NIST SP 800-22 core-
# battery confirmation run at the final 16-round parameter-
# ization. This regenerates the extended confirmation reported
# in Section 5.6 (the "RUN_D_CONFIRM_300" result), under a
# deterministic diagnostic key so the run is exactly
# reproducible and the reproducibility statement of Section 5.6
# covers it.
#
# Method (matches Section 5.6):
#   Counter-mode keystream = concatenation of encryptions of
#   sequential counter blocks 0, 1, 2, ..., partitioned into
#   SEQUENCES sequences of 10^6 bits. Each sequence is assessed
#   under the seven-test / nine-p-value core battery
#   (frequency, block frequency, runs, longest run of ones,
#   cumulative sums forward and backward, serial m=2, and
#   approximate entropy m=2). A test "fails" for a sequence
#   when its p-value < alpha (alpha = 0.01). Per-test pass
#   proportions are compared against the three-sigma acceptance
#   region; the total failing-test count is compared against
#   its expectation (alpha * SEQUENCES * 9 p-values).
#
# The confirmation key is derived deterministically (fixed
# password/salt via the SHA-256 stub) so the run reproduces
# bit-for-bit; pass --argon2 to instead use a fresh random
# Argon2id key (independent-key variant).
#
# CONFORMANCE: verifies HESPN against the Appendix A test
# vector, and the NIST battery against SP 800-22 worked
# examples (via nist_core_battery), at startup. Refuses to run
# on any mismatch.
#
# Requires: numpy; nist_core_battery.py in the same directory.
#   pip install numpy argon2-cffi
#   python HESPNv4Confirm300.py                 # 300 seq, deterministic key
#   python HESPNv4Confirm300.py --sequences 100 # 100-sequence core run
#   python HESPNv4Confirm300.py --argon2        # independent random key
# ============================================================

import argparse, datetime, hashlib, math, os, platform, sys, time

try:
    import numpy as np
except ImportError:
    sys.exit("numpy is required: pip install numpy")

import nist_core_battery as nist  # self-validates against SP 800-22 at import

# ---- reuse the verified HESPN core if present, else inline the essentials ----
# AES S-box
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
assert SBOX[0] == 0x63 and SBOX[1] == 0x7C and SBOX[0x53] == 0xED
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]

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
    seeds = []
    for j in range(16):
        counter = 0
        while True:
            d = hashlib.sha256(K + b"MATRIX" + bytes([j]) + counter.to_bytes(4, "big")).digest()
            cand = list(d[0:8])
            if admissible(cand):
                seeds.append(cand)
                break
            counter += 1
    return seeds

def rotl128(b, k):
    n = int.from_bytes(b, "big")
    n = ((n << k) | (n >> (128 - k))) & ((1 << 128) - 1)
    return n.to_bytes(16, "big")

def routing_perm(mode):
    if mode == 0:
        return list(range(16))
    out = []
    for j in range(16):
        b0, bm = j & 1, (j >> mode) & 1
        jj = j & ~(1 | (1 << mode))
        jj |= bm | (b0 << mode)
        out.append(jj)
    return out

class HESPNRef:
    def __init__(self, K, rounds=16):
        self.rounds = rounds
        self.rk = round_keys(K)
        self.seeds = derive_seeds(K)
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

class HESPNBatch:
    def __init__(self, ref):
        self.rounds = ref.rounds
        self.T = np.zeros((16, 16, 256), dtype=np.uint8)
        for r in range(16):
            for j in range(16):
                Mrj = ref.M[r][j]
                self.T[r, j] = np.array([SBOX[mat_vec(Mrj, x)] for x in range(256)], dtype=np.uint8)
        self.RK = np.array([list(k) for k in ref.rk], dtype=np.uint16)
        self.PI = [routing_perm(m) for m in range(4)]

    def encrypt(self, X):
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

# ---- self-test against Appendix A ----
TV_PW = "HillEnigmaSPN2026!"
TV_SALT = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
TV_PT = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
TV_CT = "3FD6391275C252DD4E3BC4CFE7F82C96"

def self_test():
    K = stub_kdf(TV_PW, TV_SALT)
    ref = HESPNRef(K)
    if ref.encrypt(TV_PT).hex().upper() != TV_CT:
        raise SystemExit("SELF-TEST FAIL: HESPN Appendix A vector")
    batch = HESPNBatch(ref)
    X = np.frombuffer(TV_PT + os.urandom(16 * 20), dtype=np.uint8).reshape(-1, 16).copy()
    Y = batch.encrypt(X)
    if Y[0].tobytes().hex().upper() != TV_CT:
        raise SystemExit("SELF-TEST FAIL: batch vector")
    for i in range(1, 21):
        if ref.encrypt(X[i].tobytes()) != Y[i].tobytes():
            raise SystemExit("SELF-TEST FAIL: batch vs reference")
    return ("self-test PASS (HESPN Appendix A vector + batch equivalence; "
            "NIST core battery validated against SP 800-22 worked examples)")

# ---- keystream generation ----
def keystream_bits(batch, key_index_base, nbits):
    """Counter-mode keystream: encrypt sequential counter blocks, take bits MSB-first."""
    nblocks = (nbits + 127) // 128
    ctr = np.arange(key_index_base, key_index_base + nblocks, dtype=np.uint64)
    X = np.zeros((nblocks, 16), dtype=np.uint8)
    for b in range(8):  # big-endian counter in the low 8 bytes (bytes 8..15)
        X[:, 15 - b] = (ctr >> np.uint64(8 * b)) & np.uint64(0xFF)
    C = batch.encrypt(X)
    bitarr = np.unpackbits(C, axis=1).reshape(-1)[:nbits]
    return bitarr

def run(args):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logname = f"hespn_nist_confirm_{args.sequences}seq_{stamp}.txt"
    log = open(logname, "w", encoding="utf-8")

    def emit(line=""):
        print(line)
        log.write(line + "\n")
        log.flush()

    emit("=" * 70)
    emit(f"HESPN NIST SP 800-22 CORE-BATTERY CONFIRMATION ({args.sequences} sequences)")
    emit("=" * 70)
    emit(f"timestamp : {stamp}")
    emit(f"python    : {platform.python_version()}  numpy {np.__version__}")
    emit(f"platform  : {platform.platform()}")
    emit(self_test())

    if args.argon2:
        password = "HESPN-" + os.urandom(12).hex()
        salt = os.urandom(16)
        t0 = time.time()
        K = argon2id_kdf(password, salt)
        emit(f"key mode  : Argon2id independent random key")
        emit(f"password  : {password}")
        emit(f"salt (hex): {salt.hex().upper()}  (prefix {salt.hex().upper()[:4]}...)")
        emit(f"master key: {K.hex().upper()}   [Argon2id, {time.time()-t0:.1f}s]")
    else:
        # deterministic confirmation key (exactly reproducible)
        password = "HESPN-CONFIRM-300"
        salt = bytes.fromhex("00" * 16)
        K = stub_kdf(password, salt)
        emit(f"key mode  : deterministic confirmation key (exactly reproducible)")
        emit(f"password  : {password!r}  salt: all-zero 16 bytes  (SHA-256 stub)")
        emit(f"master key: {K.hex().upper()}")

    ref = HESPNRef(K, rounds=16)
    batch = HESPNBatch(ref)

    SEQ = args.sequences
    NBITS = 10 ** 6
    alpha = 0.01
    tests = nist.CORE_TESTS  # nine p-values
    emit(f"rounds    : 16")
    emit(f"sequences : {SEQ} x {NBITS} bits (counter-mode keystream)")
    emit(f"battery   : {len(tests)} p-values, alpha = {alpha}")
    emit("-" * 70)

    # three-sigma acceptance region for pass proportion
    phat = 1 - alpha
    sigma = math.sqrt(phat * alpha / SEQ)
    lo = phat - 3 * sigma
    emit(f"pass-proportion acceptance: >= {lo:.4f} (three-sigma, expected {phat:.3f})")
    emit(f"expected acceptable min count: {math.ceil(lo * SEQ)}/{SEQ}")
    emit("-" * 70)

    counts = {t: 0 for t in tests}  # sequences passing each test
    ptvals = {t: [] for t in tests}
    t0 = time.time()
    blocks_per_seq = NBITS // 128 + 1
    for s in range(SEQ):
        base = s * blocks_per_seq  # disjoint counter ranges per sequence
        arr = keystream_bits(batch, base, NBITS)
        pv = nist.battery_pvalues_fast(arr.tolist(), arr)
        for t in tests:
            p = pv[t]
            ptvals[t].append(p)
            if p >= alpha:
                counts[t] += 1
        if (s + 1) % 25 == 0 or s + 1 == SEQ:
            emit(f"  sequence {s+1:4d}/{SEQ}  ({time.time()-t0:.0f}s)")
            with open('confirm300_checkpoint.txt','w') as ck:
                ck.write(f'done={s+1}\n')
                for tt in tests: ck.write(f'{tt} {counts[tt]}\n')

    emit("-" * 70)
    emit(f"{'test':<18}{'pass prop.':>12}{'min P_T':>12}{'verdict':>12}")
    emit("-" * 70)
    total_fail = 0
    all_ok = True
    for t in tests:
        prop = counts[t] / SEQ
        # chi-square uniformity of p-values across 10 bins -> P_T
        pt = _pvalue_uniformity(ptvals[t])
        ok = (counts[t] >= math.ceil(lo * SEQ)) and (pt >= 1e-4)
        all_ok = all_ok and ok
        total_fail += (SEQ - counts[t])
        emit(f"{t:<18}{str(counts[t])+'/'+str(SEQ):>12}{pt:>12.4f}{'OK' if ok else 'CHECK':>12}")
    emit("-" * 70)
    expected_fail = alpha * SEQ * len(tests)
    emit("SUMMARY (report in Section 5.6)")
    emit(f"total failing tests: {total_fail} / {SEQ * len(tests)}  "
         f"(expectation {expected_fail:.0f} at alpha = {alpha})")
    emit(f"all tests within acceptance region and P_T uniform: {'YES' if all_ok else 'NO'}")
    emit(f"elapsed: {time.time()-t0:.0f}s")
    emit(f"log file: {logname}")
    log.close()

def _pvalue_uniformity(pvals):
    """Chi-square goodness-of-fit of p-values to Uniform(0,1), 10 bins -> P_T."""
    bins = [0] * 10
    for p in pvals:
        idx = min(int(p * 10), 9)
        bins[idx] += 1
    n = len(pvals)
    exp = n / 10.0
    chi = sum((b - exp) ** 2 / exp for b in bins)
    return nist.igamc(9 / 2.0, chi / 2.0)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HESPN NIST SP 800-22 core-battery confirmation")
    ap.add_argument("--sequences", type=int, default=300)
    ap.add_argument("--argon2", action="store_true",
                    help="use a fresh random Argon2id key instead of the deterministic confirmation key")
    args = ap.parse_args()
    run(args)
