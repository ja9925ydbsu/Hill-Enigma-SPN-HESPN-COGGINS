#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HESPNv4Diagnostics.py
=====================
Reproduces every characterization number quoted in Section 5.6 of the
HESPN manuscript (NIST SP 800-22 keystream evaluation and round-count
calibration).  Place this file in the same directory as HESPNv4Rerun.py
and run:

    python HESPNv4Diagnostics.py > diagnostics_output.txt

Parts (toggle with the RUN_* flags below):

  A. Controls
     A1: os.urandom keystream through the same core battery (must pass;
         validates the battery itself).
     A2: 12-round HESPN encrypting *independent random plaintexts*
         (must pass; shows the 12-round failure is structured-input
         specific, not a marginal nonuniformity of the permutation).

  B. Stride Hamming-distance distinguisher
     Mean HD( Enc(i), Enc(i+stride) ) over counter inputs.
     At 12 rounds: means 63.6-63.7 vs ideal 64.0, |z| up to ~9.5 at
     20,000 pairs.  At 16 rounds: consistent with 64.0, |z| < 3.

  C. NIST rounds sweep
     20 sequences x 10^6 bits per round count, nine p-values each
     (180 tests per configuration).  Reference result:
         12 rounds: 21/180 failing
         14 rounds:  0/180
         16 rounds:  0/180
         20 rounds:  1/180   (nominal at alpha = 0.01)

  D. 300-sequence confirmation at 16 rounds
     The authoritative, exactly reproducible confirmation is now
     produced by the standalone script HESPNv4Confirm300.py (fixed
     deterministic key): 34 failing tests of 2,700 (expectation 27),
     every per-test pass proportion inside its 3-sigma acceptance
     region (cutoff at n=300: 0.9728); runs family 296/300 = 0.987.
     This Part D remains a self-contained cross-check; because it
     derives its key via make_key("D") rather than the confirmation
     key, its exact failing-test count may differ by ordinary
     statistical fluctuation while remaining nominal.
     NOTE: generates ~4.7 GB-equivalent of keystream work; expect
     roughly 30-60 minutes depending on the machine.

Determinism: by default each part derives its keys from fixed seeds so
that reruns are exactly reproducible.  Set DETERMINISTIC = False to use
fresh os.urandom keys instead; the qualitative results are
key-independent (the 12-round bias appears for every key tested).
"""

import math
import os
import random
import statistics
import sys
import time

import importlib

# Import HESPNv4Rerun from the directory containing THIS file, regardless of
# the current working directory (IDLE, Spyder, Jupyter, etc.).
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
try:
    m = importlib.import_module("HESPNv4Rerun")
except ImportError:
    found = sorted(f for f in os.listdir(HERE) if "hespn" in f.lower())
    sys.exit(
        "Could not import HESPNv4Rerun.\n"
        f"  Looked in: {HERE}\n"
        f"  HESPN-related files found there: {found or 'none'}\n"
        "  Fix: place HESPNv4Rerun.py (exact filename, no ' (1)' suffix)\n"
        "  in that same folder and run again."
    )

# ------------------------------------------------------------------ flags
RUN_A_CONTROLS      = True
RUN_B_STRIDE        = True
RUN_C_ROUNDS_SWEEP  = True
RUN_D_CONFIRM_300   = False   # heavy; enable for the full confirmation
DETERMINISTIC       = True

SEQ_BYTES = 125_000           # 10^6 bits per sequence
ALPHA     = 0.01

def make_key(tag: str) -> bytes:
    if DETERMINISTIC:
        import hashlib
        return hashlib.sha256(b"HESPN-DIAG-2026-" + tag.encode()).digest()
    return os.urandom(32)

def battery(seqs):
    """Run the core battery on a list of sequences; return dict name->list(p)."""
    allp = {}
    for seq in seqs:
        for name, p in m.nist_core_tests(seq).items():
            allp.setdefault(name, []).append(p)
    return allp

def report(allp, label):
    n = len(next(iter(allp.values())))
    # 3-sigma proportion cutoff for this n
    phat = 1 - ALPHA
    cutoff = phat - 3 * math.sqrt(phat * ALPHA / n)
    total_fail = 0
    print(f"\n--- {label}  ({n} sequences x 10^6 bits) ---")
    print(f"{'test':<16} {'pass':>9} {'prop':>8}   (3-sigma cutoff {cutoff:.4f})")
    for name in sorted(allp):
        ps = allp[name]
        npass = sum(1 for p in ps if p >= ALPHA)
        total_fail += len(ps) - npass
        flag = "" if npass / len(ps) >= cutoff else "  <-- below cutoff"
        print(f"{name:<16} {npass:>4}/{len(ps):<4} {npass/len(ps):>8.4f}{flag}")
    print(f"total failing tests: {total_fail} / {n * len(allp)}")
    return total_fail

def ctr_stream(cipher, nblocks, rounds=None):
    if rounds is None:
        return b"".join(cipher.encrypt_block(i.to_bytes(16, "big"))
                        for i in range(nblocks))
    return b"".join(cipher.encrypt_block(i.to_bytes(16, "big"), rounds=rounds)
                    for i in range(nblocks))

# ================================================================== A
if RUN_A_CONTROLS:
    print("=" * 68)
    print("PART A - CONTROLS")
    print("=" * 68)

    # A1: urandom through the battery
    NSEQ = 12
    seqs = [os.urandom(SEQ_BYTES) for _ in range(NSEQ)]
    report(battery(seqs), "A1: os.urandom control (battery sanity)")

    # A2: 12-round HESPN on independent random plaintexts
    key = make_key("A2")
    c = m.HESPNFastCipher(key, max_rounds=24)
    rng = random.Random(99)
    blocks = NSEQ * SEQ_BYTES // 16 + 1
    t0 = time.perf_counter()
    stream = b"".join(c.encrypt_block(rng.randbytes(16), rounds=12)
                      for _ in range(blocks))
    print(f"\n[A2 keystream generated in {time.perf_counter()-t0:.0f}s]")
    seqs = [stream[i*SEQ_BYTES:(i+1)*SEQ_BYTES] for i in range(NSEQ)]
    report(battery(seqs),
           "A2: 12-round HESPN, RANDOM plaintexts (must pass -> "
           "failure below is structured-input specific)")

# ================================================================== B
if RUN_B_STRIDE:
    print("\n" + "=" * 68)
    print("PART B - STRIDE HAMMING-DISTANCE DISTINGUISHER")
    print("=" * 68)
    print("ideal: mean 64.00, sd 5.66; SEM at n=20000 ~ 0.04")
    key = make_key("B")
    c = m.HESPNFastCipher(key, max_rounds=24)
    N = 20_000
    for rounds in (12, 16):
        print(f"\nMean HD( Enc(i), Enc(i+stride) ), {rounds} rounds, "
              f"{N} pairs per stride:")
        for stride in (1, 2, 16, 256, 65536):
            hds = []
            for i in range(N):
                a = c.encrypt_block(i.to_bytes(16, "big"), rounds=rounds)
                b = c.encrypt_block((i + stride).to_bytes(16, "big"),
                                    rounds=rounds)
                hds.append(m.hamming_distance_bytes(a, b))
            mu = statistics.mean(hds)
            sd = statistics.stdev(hds)
            z = (mu - 64) / (sd / math.sqrt(N))
            print(f"  stride {stride:>6}: mean={mu:7.3f}  sd={sd:5.2f}  "
                  f"z(vs 64)={z:+7.1f}")
    print("\nreference (one 12-round key): means 63.60-63.72, z -7.0 to -9.5")
    print("reference (16 rounds):        means 63.96-64.04, |z| < 3")

# ================================================================== C
if RUN_C_ROUNDS_SWEEP:
    print("\n" + "=" * 68)
    print("PART C - NIST ROUNDS SWEEP (20 sequences per round count)")
    print("=" * 68)
    key = make_key("C")
    c = m.HESPNFastCipher(key, max_rounds=24)
    NSEQ = 20
    blocks = NSEQ * SEQ_BYTES // 16 + 1
    summary = {}
    for rounds in (12, 14, 16, 20):
        t0 = time.perf_counter()
        stream = ctr_stream(c, blocks, rounds=rounds)
        print(f"\n[{rounds}-round keystream generated in "
              f"{time.perf_counter()-t0:.0f}s]")
        seqs = [stream[i*SEQ_BYTES:(i+1)*SEQ_BYTES] for i in range(NSEQ)]
        summary[rounds] = report(battery(seqs),
                                 f"C: HESPN-CTR, {rounds} rounds")
    print("\nSweep summary (failing tests of 180):")
    for rounds, nf in summary.items():
        print(f"  {rounds:>2} rounds: {nf:>3}/180")
    print("reference: 12r 21/180, 14r 0/180, 16r 0/180, 20r 1/180")

# ================================================================== D
if RUN_D_CONFIRM_300:
    print("\n" + "=" * 68)
    print("PART D - 300-SEQUENCE CONFIRMATION AT 16 ROUNDS")
    print("=" * 68)
    key = make_key("D")
    c = m.HESPNFastCipher(key)          # 16 rounds default
    NSEQ = 300
    blocks = NSEQ * SEQ_BYTES // 16 + 1
    t0 = time.perf_counter()
    stream = ctr_stream(c, blocks)
    print(f"[keystream generated in {time.perf_counter()-t0:.0f}s]")
    seqs = [stream[i*SEQ_BYTES:(i+1)*SEQ_BYTES] for i in range(NSEQ)]
    allp = battery(seqs)
    total_fail = report(allp, "D: HESPN-CTR, 16 rounds, fresh key")
    exp = NSEQ * len(allp) * ALPHA
    print(f"expected failing tests at alpha={ALPHA}: {exp:.0f}")
    # failure clustering: how many sequences fail >= 2 tests?
    per_seq = [sum(1 for name in allp if allp[name][i] < ALPHA)
               for i in range(NSEQ)]
    multi = sum(1 for k in per_seq if k >= 2)
    print(f"sequences failing >= 2 tests: {multi} "
          f"(correlated statistics cluster on borderline sequences)")
    print("authoritative confirmation (HESPNv4Confirm300.py): "
          "34/2700 failing vs 27 expected; runs family "
          "296/300 = 0.987 vs cutoff 0.973")

print("\nDone.")
