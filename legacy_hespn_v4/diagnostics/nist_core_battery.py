"""NIST core battery (see full docstring below).
nist_core_battery.py

Seven-test / nine-p-value core subset of NIST SP 800-22, matching the
battery described in Section 5.6 of the HESPN manuscript:

  1. Frequency (Monobit)
  2. Block Frequency (M = 128)
  3. Runs
  4. Longest Run of Ones in a Block
  5. Cumulative Sums (forward)      \  two p-values
     Cumulative Sums (backward)     /
  6. Serial (m = 2)                 -> two p-values del1 and del2 per SP 800-22
  7. Approximate Entropy (m = 2)

Each test returns one or more p-values in [0,1]; a sequence "passes" a
p-value if p >= alpha (default 0.01).

Validated at import against the worked-example bit strings and expected
p-values published in NIST SP 800-22 Rev. 1a (Section 2). If any check
deviates beyond tolerance the module raises, so a caller can trust the
statistics.

Pure standard library (math only). No third-party dependencies.
"""

import math

# -------- special functions (erfc, lower incomplete gamma via igamc) --------
def erfc(x):
    return math.erfc(x)

def _gammainc_upper_reg(a, x):
    """Regularized upper incomplete gamma Q(a,x) = Gamma(a,x)/Gamma(a)."""
    if a <= 0:
        raise ValueError
    if x <= 0:
        # d2 can be slightly negative from floating point or a degenerate
        # sequence; SP 800-22 treats chi-square<=0 as p-value 1 (perfect fit).
        return 1.0
    if x < a + 1.0:
        # series for P(a,x), then Q = 1-P
        ap = a
        s = 1.0 / a
        d = s
        for _ in range(10000):
            ap += 1.0
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-15:
                break
        return 1.0 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
    else:
        # continued fraction for Q(a,x)
        fpmin = 1e-300
        b = x + 1.0 - a
        c = 1.0 / fpmin
        d = 1.0 / b
        h = d
        for i in range(1, 10000):
            an = -i * (i - a)
            b += 2.0
            d = an * d + b
            if abs(d) < fpmin:
                d = fpmin
            c = b + an / c
            if abs(c) < fpmin:
                c = fpmin
            d = 1.0 / d
            de = d * c
            h *= de
            if abs(de - 1.0) < 1e-15:
                break
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h

def igamc(a, x):
    """NIST's igamc = Q(a,x)."""
    return _gammainc_upper_reg(a, x)

# ------------------------------ the tests ------------------------------
def _bits_to_pm1(bits):
    return [2 * b - 1 for b in bits]

def frequency(bits):
    n = len(bits)
    s = sum(_bits_to_pm1(bits))
    sobs = abs(s) / math.sqrt(n)
    return erfc(sobs / math.sqrt(2))

def block_frequency(bits, M=128):
    n = len(bits)
    N = n // M
    if N == 0:
        return 0.0
    chi = 0.0
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        pi = sum(block) / M
        chi += (pi - 0.5) ** 2
    chi *= 4.0 * M
    return igamc(N / 2.0, chi / 2.0)

def runs(bits):
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
        return 0.0
    vobs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            vobs += 1
    num = abs(vobs - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    return erfc(num / den)

def longest_run_of_ones(bits):
    n = len(bits)
    # parameters per SP 800-22 for n >= 6272 (we use M=128, K=5, N=49)
    if n < 6272:
        M, K, N = 8, 3, 16
        pi = [0.2148, 0.3672, 0.2305, 0.1875]
        vmin = 1
    elif n < 750000:
        M, K, N = 128, 5, 49
        pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        vmin = 4
    else:
        M, K, N = 10000, 6, 75
        pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
        vmin = 10
    v = [0] * (K + 1)
    for i in range(N):
        block = bits[i * M:(i + 1) * M]
        longest = cur = 0
        for b in block:
            if b == 1:
                cur += 1
                longest = max(longest, cur)
            else:
                cur = 0
        cls = min(max(longest, vmin), vmin + K) - vmin
        v[cls] += 1
    chi = 0.0
    for i in range(K + 1):
        chi += (v[i] - N * pi[i]) ** 2 / (N * pi[i])
    return igamc(K / 2.0, chi / 2.0)

def cumulative_sums(bits, mode=0):
    n = len(bits)
    x = _bits_to_pm1(bits)
    if mode == 1:
        x = x[::-1]
    z = 0
    S = 0
    for xi in x:
        S += xi
        z = max(z, abs(S))
    if z == 0:
        return 1.0
    # sum1 over odd multiples
    def Phi(v):
        return 0.5 * (1 + math.erf(v / math.sqrt(2)))
    s1 = 0.0
    k = int((-n / z + 1) / 4)
    kk = int((n / z - 1) / 4)
    for k in range(int((-n / z + 1) // 4), int((n / z - 1) // 4) + 1):
        s1 += Phi(((4 * k + 1) * z) / math.sqrt(n)) - Phi(((4 * k - 1) * z) / math.sqrt(n))
    s2 = 0.0
    for k in range(int((-n / z - 3) // 4), int((n / z - 1) // 4) + 1):
        s2 += Phi(((4 * k + 3) * z) / math.sqrt(n)) - Phi(((4 * k + 1) * z) / math.sqrt(n))
    p = 1.0 - s1 + s2
    return min(max(p, 0.0), 1.0)

def _psi2(bits, m):
    n = len(bits)
    if m == 0:
        return 0.0
    ext = bits + bits[:m - 1]
    counts = [0] * (1 << m)
    for i in range(n):
        idx = 0
        for j in range(m):
            idx = (idx << 1) | ext[i + j]
        counts[idx] += 1
    s = sum(c * c for c in counts)
    return s * (1 << m) / n - n

def serial(bits, m=2):
    n = len(bits)
    p0 = _psi2(bits, m)
    p1 = _psi2(bits, m - 1)
    p2 = _psi2(bits, m - 2)
    d1 = p0 - p1
    d2 = p0 - 2 * p1 + p2
    pv1 = igamc(2 ** (m - 2), d1 / 2.0)
    pv2 = igamc(2 ** (m - 3) if m >= 3 else 0.5, d2 / 2.0) if m >= 2 else 1.0
    # for m=2: 2^(m-3)=0.5
    pv2 = igamc(2 ** (m - 2) / 2.0, d2 / 2.0)
    return pv1, pv2

def approximate_entropy(bits, m=2):
    n = len(bits)
    def phi(mm):
        if mm == 0:
            return 0.0
        ext = bits + bits[:mm - 1]
        counts = {}
        for i in range(n):
            key = 0
            for j in range(mm):
                key = (key << 1) | ext[i + j]
            counts[key] = counts.get(key, 0) + 1
        s = 0.0
        for c in counts.values():
            p = c / n
            s += p * math.log(p)
        return s
    apen = phi(m) - phi(m + 1)
    chi = 2.0 * n * (math.log(2) - apen)
    return igamc(2 ** (m - 1), chi / 2.0)

# ------------------------------ battery ------------------------------
CORE_TESTS = [
    "frequency", "block_frequency", "runs", "longest_run",
    "cusum_fwd", "cusum_bwd", "serial_1", "serial_2", "approx_entropy",
]  # nine p-values

def battery_pvalues(bits):
    pv = {}
    pv["frequency"] = frequency(bits)
    pv["block_frequency"] = block_frequency(bits, 128)
    pv["runs"] = runs(bits)
    pv["longest_run"] = longest_run_of_ones(bits)
    pv["cusum_fwd"] = cumulative_sums(bits, 0)
    pv["cusum_bwd"] = cumulative_sums(bits, 1)
    s1, s2 = serial(bits, 2)
    pv["serial_1"] = s1
    pv["serial_2"] = s2
    pv["approx_entropy"] = approximate_entropy(bits, 2)
    return pv

# ------------------------- self-validation -------------------------
def _bitstr(s):
    return [int(c) for c in s if c in "01"]

def _validate():
    # SP 800-22 Rev 1a worked examples (Section 2), epsilon of length 100 / 128
    e100 = _bitstr("11001001000011111101101010100010001000010110100011"
                   "00001000110100110001001100011001100010100010111000")  # pi-based example
    # Frequency test expected p ~ 0.109599 for this 100-bit example
    p = frequency(e100)
    assert abs(p - 0.109599) < 1e-4, f"frequency validation p={p}"
    # Runs test expected p ~ 0.500798
    p = runs(e100)
    assert abs(p - 0.500798) < 1e-4, f"runs validation p={p}"
    # Block frequency worked example: epsilon length 100, M=10, expected ~0.706438
    p_bf = block_frequency(e100, 10)
    assert abs(p_bf - 0.706438) < 1e-3, f"block_frequency validation p={p_bf}"
    # Cusum forward worked example expected ~0.219194 (mode 0) on same 100-bit string
    p_c = cumulative_sums(e100, 0)
    assert abs(p_c - 0.219194) < 1e-3, f"cusum validation p={p_c}"
    # Approximate entropy worked example (m=2) expected ~0.235301
    p_a = approximate_entropy(e100, 2)
    assert abs(p_a - 0.235301) < 2e-3, f"apen validation p={p_a}"
    # Serial worked example: epsilon = 0011011101 (n=10, m=3); SP 800-22 expects
    # p-value1 ~ 0.808792 and p-value2 ~ 0.670320.
    e_ser = _bitstr("0011011101")
    s1, s2 = serial(e_ser, 3)
    assert abs(s1 - 0.808792) < 3e-3, f"serial1 validation p={s1}"
    assert abs(s2 - 0.670320) < 3e-3, f"serial2 validation p={s2}"
    return True

VALIDATED = _validate()

if __name__ == "__main__":
    print("NIST core battery self-validation:", "PASS" if VALIDATED else "FAIL")
    print("core p-values:", CORE_TESTS)


# ------------- vectorized fast paths (NumPy) for the hot tests -------------
# These reproduce serial(m=2) and approximate_entropy(m=2) exactly but count
# m-bit patterns with numpy instead of Python loops. Used by the batch driver.
def _counts_np(bits_np, m):
    n = bits_np.size
    if m == 0:
        return None
    ext = _np.concatenate([bits_np, bits_np[:m - 1]]) if m > 1 else bits_np
    idx = _np.zeros(n, dtype=_np.int64)
    for j in range(m):
        idx = (idx << 1) | ext[j:j + n].astype(_np.int64)
    return _np.bincount(idx, minlength=1 << m)

def _psi2_np(bits_np, m):
    n = bits_np.size
    if m == 0:
        return 0.0
    c = _counts_np(bits_np, m)
    return float((c.astype(_np.float64) ** 2).sum()) * (1 << m) / n - n

def serial_np(bits_np, m=2):
    p0 = _psi2_np(bits_np, m)
    p1 = _psi2_np(bits_np, m - 1)
    p2 = _psi2_np(bits_np, m - 2)
    d1 = p0 - p1
    d2 = p0 - 2 * p1 + p2
    pv1 = igamc(2 ** (m - 2), d1 / 2.0)
    pv2 = igamc(2 ** (m - 2) / 2.0, d2 / 2.0)
    return pv1, pv2

def approximate_entropy_np(bits_np, m=2):
    n = bits_np.size
    def phi(mm):
        if mm == 0:
            return 0.0
        c = _counts_np(bits_np, mm).astype(_np.float64)
        c = c[c > 0]
        p = c / n
        return float((p * _np.log(p)).sum())
    apen = phi(m) - phi(m + 1)
    chi = 2.0 * n * (math.log(2) - apen)
    return igamc(2 ** (m - 1), chi / 2.0)

try:
    import numpy as _np
    _HAVE_NP = True
except ImportError:
    _HAVE_NP = False

def battery_pvalues_fast(bits_list, bits_np):
    """Same nine p-values as battery_pvalues, using numpy for serial/apen."""
    pv = {}
    pv["frequency"] = frequency(bits_list)
    pv["block_frequency"] = block_frequency(bits_list, 128)
    pv["runs"] = runs(bits_list)
    pv["longest_run"] = longest_run_of_ones(bits_list)
    pv["cusum_fwd"] = cumulative_sums(bits_list, 0)
    pv["cusum_bwd"] = cumulative_sums(bits_list, 1)
    s1, s2 = serial_np(bits_np, 2)
    pv["serial_1"] = s1
    pv["serial_2"] = s2
    pv["approx_entropy"] = approximate_entropy_np(bits_np, 2)
    return pv
