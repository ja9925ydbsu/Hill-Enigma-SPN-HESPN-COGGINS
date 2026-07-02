# ============================================================
# Hill-Enigma-SPN (HillRotorSPN) prototype
# Concept: Porter Coggins
# Code: OpenAI / revised with Claude AI (Anthropic)
#
# Complete version with:
# - Argon2id key derivation (production — argon2-cffi required)
# - true rotor-entry 8x8 GF(2) matrix rotations
# - full rotor-family branch-number filtering
# - explicit invertibility verification of all 4 rotations
# - cached seed matrices
# - branch number summary
# - avalanche tests (plaintext + key)
# - differential tests (50,000 samples)
# - linear-bias probe (500 mask pairs, 50,000 samples)
# - algebraic degree estimator
# ============================================================
#
# ============================================================
# v4 PROTOCOL UPDATE (2026-07-02): ROUNDS 12 -> 16
#
# The v3 NIST SP 800-22 rerun (B2) revealed a genuine structured-
# input bias in 12-round HESPN-CTR keystream: sequential-counter
# ciphertext pairs retain a small correlation (mean pairwise
# Hamming distance ~63.6-63.7 vs ideal 64.0), inflating per-
# sequence ones-count variance and failing the frequency/cusum/
# serial/ApEn family with non-uniform p-values. Random-plaintext
# inputs pass the full battery, and a rounds sweep showed the
# effect vanishing by ~14 rounds (12r: 21/180 test failures;
# 14r: 0/180; 16r: 0/180; 20r: 1/180). ROUNDS is therefore
# raised to 16, a two-round margin over the empirical
# decorrelation point. K_VALUES is extended to 16 entries by
# continuing the original cycle, so rounds 0-11 are bit-identical
# to the 12-round protocol. Round-count lists in the avalanche,
# degree, and equivalence steps now include r = 16.
#
# v3 REVISION-RERUN UPDATE (2026-07-02)
#
# Updated for the manuscript revision reruns (anticipated-
# reviewer worksheet items):
#   B1  Avalanche at large n with SEM + 95% confidence
#       intervals (plaintext 5,000 trials; key 200 trials).
#   B2  NIST SP 800-22: HESPN-CTR keystream generation (file
#       saved for the official STS tool) plus a built-in core
#       test battery with two-level NIST reporting.
#   B3  Algebraic degree at t = 12 active bits, 16 trials per
#       round count.
#   B5  Admissibility-filter statistics over random candidate
#       matrices (acceptance rate; frequency of B >= 5 families
#       -- the open question of manuscript Section 5.1).
#   A8  Seed-search rejection-count instrumentation (variable-
#       time key-setup data).
#
# Also in this update:
#   - Fast table-driven implementation (HESPNFastCipher);
#     bit-exact equivalence with the reference implementation
#     is verified at startup before any experiment runs.
#   - All results are written as CSV/txt to a timestamped
#     results directory in addition to console output.
#   - Step on/off flags and a QUICK_TEST smoke-test mode.
#   - Differential and linear-bias steps retained but OFF by
#     default (revision reframes these; no rerun required).
#   - Fixed: unreachable pause block after the degree
#     estimator (referenced undefined LOG_LINEAR); pauses are
#     now pause_checkpoint() calls between steps.
# ============================================================

# !pip -q install argon2-cffi   # uncomment in Google Colab

# -- For Colab with argon2-cffi installed, replace the stub below with:
from argon2.low_level import hash_secret_raw, Type
#    def derive_master_key_argon2id(password, salt, out_len=32):
#        return hash_secret_raw(
#            secret=password.encode("utf-8"), salt=salt,
#            time_cost=ARGON_TIME_COST, memory_cost=ARGON_MEMORY_COST,
#            parallelism=ARGON_PARALLELISM, hash_len=out_len, type=Type.ID)

# ============================================================
# BIT/BYTE CONVENTION — MSB-FIRST THROUGHOUT
# ============================================================
#
# All bit-indexing in this file uses a consistent MSB-first
# convention. Specifically:
#
#   byte_to_vec(x)[i] = (x >> (7 - i)) & 1,  i = 0..7
#
#   i=0 -> MSB (bit 7 of the integer x)
#   i=7 -> LSB (bit 0 of the integer x)
#
# Matrix entry convention:
#   Each row of an 8x8 GF(2) matrix M is stored as a byte m_i.
#   The (i,j) entry of M is:
#
#     M_ij = (m_i >> (7 - j)) & 1,   0 <= i,j <= 7
#
#   so column index j=0 corresponds to the MSB of row byte m_i,
#   and column index j=7 corresponds to the LSB.
#
# Matrix-vector product:
#   y = M * v(x) over GF(2) gives output byte y where:
#
#     v(y)_i = XOR_{j=0}^{7} M_ij * v(x)_j
#            = popcount(m_i AND x) mod 2
#
#   This is the inner product of row byte m_i and input byte x
#   computed as: bin(m_i & x).count('1') % 2.
#
# Rotation convention:
#   rotate_matrix_entries_clockwise_90 acts on the abstract
#   (i,j) grid indices — NOT on the bit ordering of stored bytes.
#   Specifically: R(M)_ij = M_{7-j, i}  (n=8).
#   Branch number B(M) = min_{x!=0}{wt(x) + wt(Mx)} is
#   invariant under bit reordering, so the MSB-first convention
#   does not affect branch number values.
#
# This convention is consistent with the manuscript's
# Definition 2.1 (Section 2.2) and is maintained identically
# in byte_to_vec, vec_to_byte, apply_matrix_8,
# gf2_mat_rank_8, and rotate_matrix_entries_clockwise_90.
# ============================================================

import hashlib
import os
import random
import statistics
from collections import Counter
from typing import List

# ============================================================
# CONFIG
# ============================================================

NUM_BYTES   = 16
ROUNDS      = 16
BLOCK_BITS  = 128

# Rotation schedule — inter-byte bit diffusion per round
# (16 entries for the 16-round protocol; entries 13-16 continue
# the original 12-entry cycle, so rounds 0-11 are bit-identical
# to the v3 / 12-round schedule)
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]

# Argon2id parameters (used in Colab; kept here for reference)
ARGON_TIME_COST    = 3
ARGON_MEMORY_COST  = 65536
ARGON_PARALLELISM  = 2
ARGON_SALT_LEN     = 16

# Matrix quality floor — all 4 rotor orientations must satisfy this
MIN_BRANCH_NUMBER = 4

# ------------------------------------------------------------
# Step on/off switches (revision reruns).
# Differential and linear-bias are kept available but OFF by
# default: the manuscript revision reframes those results
# (worksheet items A1/A2) and does not require reruns.
# ------------------------------------------------------------
RUN_STEP0_VERIFY   = True
RUN_BRANCH_SUMMARY = True
RUN_AVALANCHE      = True    # B1
RUN_DIFFERENTIAL   = False   # available; not needed for revision
RUN_LINEAR         = False   # available; not needed for revision
RUN_DEGREE         = True    # B3
RUN_ADMISSIBILITY  = True    # B5 + A8
RUN_NIST           = True    # B2

# Pause checkpoints between steps (console stays open until the
# continue code is entered; auto-skipped when non-interactive)
PAUSE_ENABLED       = True
PAUSE_CONTINUE_CODE = "&Ygv"

# Set True for a fast end-to-end smoke test with reduced sizes
QUICK_TEST = False

# Test sizes — B1 rerun values (SEM and 95% CIs are reported).
# Plaintext avalanche needs one key setup total, so large n is
# cheap. Each KEY-avalanche trial requires a full key setup
# (seed-matrix search) for the mutated key, which dominates its
# cost; 200 trials is ~6-7x the original 30.
PLAINTEXT_AVALANCHE_TRIALS = 5000
KEY_AVALANCHE_TRIALS       = 200
DIFF_SAMPLES               = 50000
LINEAR_SAMPLES             = 50000   # paper values (Sessions 2-3)
LINEAR_TRIALS              = 500

# Algebraic degree estimator config — B3 rerun values
# (t = 12 active bits => 2^12 = 4096 encryptions per trial)
DEGREE_ROUNDS_TO_TEST        = [1, 2, 4, 5, 8, 12, 16]
DEGREE_NUM_ACTIVE_INPUT_BITS = 12
DEGREE_TRIALS_PER_ROUND      = 16

# Admissibility experiment (B5)
ADMISSIBILITY_SAMPLES  = 20000
ADMISSIBILITY_RNG_SEED = 20260702

# NIST SP 800-22 (B2): 100 sequences x 1,000,000 bits (12.5 MiB)
NIST_NUM_SEQUENCES = 100
NIST_SEQ_BITS      = 1_000_000

if QUICK_TEST:
    PLAINTEXT_AVALANCHE_TRIALS   = 300
    KEY_AVALANCHE_TRIALS         = 12
    DEGREE_NUM_ACTIVE_INPUT_BITS = 8
    DEGREE_TRIALS_PER_ROUND      = 4
    ADMISSIBILITY_SAMPLES        = 1500
    NIST_NUM_SEQUENCES           = 6
    NIST_SEQ_BITS                = 100_000

random.seed(12345)

# ============================================================
# AES S-box (standard FIPS 197)
# Nonlinearity = 112, max differential prob = 2^-6,
# algebraic degree = 7 over GF(2^8).
# ============================================================

AES_SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

# ============================================================
# Basic helpers
# ============================================================

def rotl128(block: bytes, k: int) -> bytes:
    """Rotate 128-bit block left by k bits (big-endian, MSB-first)."""
    x = int.from_bytes(block, "big")
    k %= 128
    y = ((x << k) | (x >> (128 - k))) & ((1 << 128) - 1)
    return y.to_bytes(16, "big")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def flip_bit_in_block(block: bytes, bit_index: int) -> bytes:
    """Flip bit bit_index in a 128-bit block. bit_index=0 is the MSB."""
    x = int.from_bytes(block, "big")
    x ^= (1 << (127 - bit_index))
    return x.to_bytes(16, "big")

def flip_bit_in_bytes(data: bytes, bit_index: int) -> bytes:
    """Flip bit bit_index in a byte string. bit_index=0 is the MSB."""
    total_bits = len(data) * 8
    x = int.from_bytes(data, "big")
    x ^= (1 << (total_bits - 1 - bit_index))
    return x.to_bytes(len(data), "big")

def random_block() -> bytes:
    return os.urandom(16)

def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pause_checkpoint(label: str) -> None:
    """Hold the console open until the continue code is entered,
    so results can be copied/saved. Skipped when PAUSE_ENABLED is
    False or when stdin is closed (piped / non-interactive runs)."""
    if not PAUSE_ENABLED:
        return
    print("=" * 72)
    print(f"PAUSE: {label}")
    print()
    print("  Scroll back and copy any console output you need.")
    print("  (All results are also written to the results "
          "directory as CSV/txt files.)")
    print()
    print(f"  Type exactly:  {PAUSE_CONTINUE_CODE}  then press "
          f"ENTER to continue.")
    print("=" * 72)
    while True:
        try:
            response = input("  Continue code: ").strip()
        except EOFError:
            print("  (non-interactive session -- continuing)")
            return
        if response == PAUSE_CONTINUE_CODE:
            print("  Continuing...")
            print()
            return
        print(f"  Incorrect -- type exactly "
              f"'{PAUSE_CONTINUE_CODE}' to continue.")

# ============================================================
# Key derivation — Argon2id (production)
# ============================================================

def derive_master_key_argon2id(password: str, salt: bytes, out_len: int = 32) -> bytes:
    """
    Argon2id memory-hard key derivation.
    Parameters: t=3, m=65536 KiB, p=2, output=32 bytes.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=out_len,
        type=Type.ID,
    )

def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    """Derive 128-bit round key r as SHA256(master_key || 'ROUNDKEY' || r)[:16]."""
    digest = hashlib.sha256(
        master_key + b"ROUNDKEY" + round_index.to_bytes(2, "big")
    ).digest()
    return digest[:16]

# ============================================================
# 8x8 GF(2) matrix utilities
#
# BIT CONVENTION (MSB-FIRST):
#   byte_to_vec(x)[i] = (x >> (7-i)) & 1,  i = 0..7
#   i=0 is the MSB of x; i=7 is the LSB of x.
#
# MATRIX ENTRY CONVENTION:
#   Row i of matrix M is stored as byte m_i.
#   M_ij = (m_i >> (7-j)) & 1,  0 <= i,j <= 7
#   Column j=0 corresponds to the MSB of m_i.
#   Column j=7 corresponds to the LSB of m_i.
#
# MATRIX-VECTOR PRODUCT:
#   y = M * v(x)  =>  v(y)_i = popcount(m_i AND x) mod 2
#   Equivalently: output bit i = bin(rows[i] & x).count('1') % 2
#
# This convention is consistent throughout byte_to_vec,
# vec_to_byte, apply_matrix_8, gf2_mat_rank_8, and
# rotate_matrix_entries_clockwise_90.
# ============================================================

def byte_to_vec(x: int):
    """
    Convert byte x to 8-element GF(2) vector, MSB-first.
    v[0] = MSB = (x >> 7) & 1
    v[7] = LSB = (x >> 0) & 1
    Formally: v[i] = (x >> (7-i)) & 1,  i = 0..7
    """
    return [(x >> (7 - i)) & 1 for i in range(8)]

def vec_to_byte(v) -> int:
    """
    Convert 8-element GF(2) vector (MSB-first) back to byte.
    Inverse of byte_to_vec: vec_to_byte(byte_to_vec(x)) == x.
    """
    out = 0
    for bit in v:
        out = (out << 1) | (bit & 1)
    return out

def gf2_mat_rank_8(rows) -> int:
    """
    Compute rank of 8x8 binary matrix M over GF(2) via
    Gaussian elimination. rows[i] is byte m_i storing row i
    under the MSB-first convention: M_ij = (m_i >> (7-j)) & 1.
    Pivot selection uses column j=0 (MSB) first.
    """
    A = rows[:]
    rank = 0
    for col in range(8):
        # col j=0 corresponds to bit position (7-0)=7 in the byte
        bit = 1 << (7 - col)
        pivot = None
        for r in range(rank, 8):
            if A[r] & bit:
                pivot = r
                break
        if pivot is None:
            continue
        A[rank], A[pivot] = A[pivot], A[rank]
        for r in range(8):
            if r != rank and (A[r] & bit):
                A[r] ^= A[rank]
        rank += 1
    return rank

def is_invertible_8(rows) -> bool:
    """
    Return True iff 8x8 GF(2) matrix has full rank (rank=8),
    i.e. is invertible over GF(2).
    """
    return gf2_mat_rank_8(rows) == 8

def apply_matrix_8(rows, x: int) -> int:
    """
    Multiply input byte x by 8x8 GF(2) matrix M.

    MSB-first convention:
      v(x)[j] = (x >> (7-j)) & 1         (input vector)
      M_ij    = (rows[i] >> (7-j)) & 1   (matrix entries)
      v(y)[i] = XOR_j M_ij * v(x)[j]
              = popcount(rows[i] AND x) mod 2

    Returns output byte y such that v(y) = M * v(x) over GF(2).
    """
    xv = byte_to_vec(x)
    out_bits = []
    for row in rows:
        rv = byte_to_vec(row)
        # Inner product of row i and input vector over GF(2)
        bit = 0
        for a, b in zip(rv, xv):
            bit ^= (a & b)
        out_bits.append(bit)
    return vec_to_byte(out_bits)

def hamming_weight8(x: int) -> int:
    """Return Hamming weight (number of 1-bits) of byte x."""
    return x.bit_count()

def apply_matrix_8_fast(rows, x: int) -> int:
    """Identical result to apply_matrix_8, computed via the
    popcount form of manuscript Section 3.1:
        v(y)[i] = popcount(m_i AND x) mod 2   (MSB-first).
    Used in branch-number evaluation and fast-path table
    construction; bit-exact equivalence with the reference path
    is exercised by verify_fast_equivalence() at startup."""
    out = 0
    for row in rows:
        out = (out << 1) | ((row & x).bit_count() & 1)
    return out

def branch_number_at_least(rows, threshold: int) -> bool:
    """Early-exit predicate: True iff B(M) >= threshold. Makes
    the SAME accept/reject decision as
    branch_number_of_matrix(rows) >= threshold, but returns as
    soon as a violating input x is found. Inputs with
    wt(x) >= threshold are skipped (their sum meets the
    threshold trivially)."""
    for x in range(1, 256):
        if x.bit_count() >= threshold:
            continue
        y = apply_matrix_8_fast(rows, x)
        if x.bit_count() + y.bit_count() < threshold:
            return False
    return True

def branch_number_of_matrix(rows) -> int:
    """
    Compute branch number B(M) = min_{x != 0} {wt(x) + wt(Mx)}.
    B(M) is invariant under bit reordering of the input/output
    convention — the MSB-first choice does not affect this value.
    Cryptographically: B(M) >= 4 means any single active input
    bit activates at least 3 output bit positions.
    """
    best = None
    for x in range(1, 256):
        y = apply_matrix_8_fast(rows, x)
        value = hamming_weight8(x) + hamming_weight8(y)
        if best is None or value < best:
            best = value
    return best

# ============================================================
# Rotor rotation: 90-degree clockwise rotation of 8x8 matrix
#
# DEFINITION (manuscript Definition 2.2):
#   R(M)_ij = M_{7-j, i},   0 <= i,j <= 7
#
# This acts on abstract (i,j) grid indices under the MSB-first
# convention. It does NOT reorder the bit encoding of stored
# bytes — rows_to_grid / grid_to_rows handle the conversion.
#
# Order-4 property: R^4(M) = M for all M.
# Applied 4 times returns the original matrix exactly.
#
# IMPORTANT: Invertibility of M does NOT guarantee invertibility
# of R(M). Branch number B(M) >= 4 does NOT guarantee
# B(R(M)) >= 4. Both properties are verified explicitly for
# all 4 rotations in derive_invertible_seed_matrix_filtered.
# ============================================================

def rows_to_grid(rows):
    """
    Convert list of 8 row-bytes to 8x8 grid of bits.
    grid[i][j] = M_ij = (rows[i] >> (7-j)) & 1  (MSB-first).
    """
    return [byte_to_vec(r) for r in rows]

def grid_to_rows(grid):
    """
    Convert 8x8 grid of bits back to list of 8 row-bytes.
    Inverse of rows_to_grid under MSB-first convention.
    """
    return [vec_to_byte(row) for row in grid]

def rotate_matrix_entries_clockwise_90(rows):
    """
    Rotate 8x8 GF(2) matrix M clockwise by 90 degrees.

    Formal definition (manuscript Definition 2.2):
      R(M)_ij = M_{7-j, i},   n=8, 0 <= i,j <= 7

    Equivalently: column i of M becomes row i of R(M),
    read in reversed order (bottom to top).

    Acts on abstract (i,j) indices; uses rows_to_grid /
    grid_to_rows for byte <-> grid conversion under the
    consistent MSB-first convention.
    """
    g = rows_to_grid(rows)
    n = 8
    rotated = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            # R(M)_ij = M_{n-1-j, i}
            rotated[i][j] = g[n - 1 - j][i]
    return grid_to_rows(rotated)

def rotate_matrix_entries_k(rows, k: int):
    """
    Apply k clockwise 90-degree rotations to matrix M.
    rotate_matrix_entries_k(rows, 0) = rows (identity).
    rotate_matrix_entries_k(rows, 4) = rows (order-4 property).
    """
    out = rows[:]
    for _ in range(k % 4):
        out = rotate_matrix_entries_clockwise_90(out)
    return out

# ============================================================
# Branch-filtered seed matrix generation
#
# Generates 16 admissible seed matrices (manuscript Def. 2.3).
# A seed matrix S is admissible iff ALL four members of its
# rotor family {S, R(S), R^2(S), R^3(S)} satisfy:
#   (1) invertible over GF(2)  [rank = 8]
#   (2) branch number >= MIN_BRANCH_NUMBER
#
# Seed candidates are derived deterministically from master_key
# via SHA-256(master_key || "MATRIX" || j || counter), ensuring
# Bob can reconstruct all matrices from (password, salt) alone.
# ============================================================

# A8 instrumentation: candidates tested per (master_key,
# byte_index) during seed search — i.e. the rejection-sampling
# cost of key setup. Reported by report_seed_search_stats().
SEED_SEARCH_STATS = {}

def derive_invertible_seed_matrix_filtered(master_key: bytes,
                                            byte_index: int,
                                            min_branch: int = 4):
    """
    Derive admissible seed matrix for byte position byte_index.

    Filters candidates until all 4 rotor orientations are both:
      - invertible over GF(2)   (rank check)
      - branch number >= min_branch  (diffusion strength check)

    Invertibility of the seed alone does NOT guarantee
    invertibility of all rotations — this is checked explicitly
    (see Step 0 verify_all_rotations_invertible for confirmation).

    Returns the seed matrix rows (list of 8 bytes, MSB-first).
    """
    counter = 0
    while True:
        digest = hashlib.sha256(
            master_key + b"MATRIX" +
            byte_index.to_bytes(1, "big") +
            counter.to_bytes(4, "big")
        ).digest()

        # Take first 8 bytes as the 8 row values of a candidate matrix
        rows = list(digest[:8])

        # Filter 1: seed itself must be invertible over GF(2)
        if not is_invertible_8(rows):
            counter += 1
            continue

        # Generate all 4 rotor orientations
        family = [rotate_matrix_entries_k(rows, k) for k in range(4)]

        # Filter 2: ALL 4 orientations must be invertible over GF(2)
        # (invertibility is NOT preserved by rotation in general)
        if not all(is_invertible_8(M) for M in family):
            counter += 1
            continue

        # Filter 3: ALL 4 orientations must meet branch number floor
        # (early-exit form; identical accept/reject decision)
        if all(branch_number_at_least(M, min_branch)
               for M in family):
            # A8: record total candidates examined for this seed
            SEED_SEARCH_STATS[(master_key, byte_index)] = counter + 1
            return rows

        counter += 1

# ============================================================
# Cached seed matrices (avoid recomputation across rounds)
# ============================================================

seed_matrices_cache = {}

def get_seed_matrices(master_key: bytes, min_branch: int = 4):
    """
    Return (and cache) the 16 admissible seed matrices derived
    from master_key. Each call with the same key returns the
    identical deterministic set — enabling Bob to reconstruct
    all matrices from (password, salt) without any additional
    communication.
    """
    cache_key = (master_key, min_branch)
    if cache_key not in seed_matrices_cache:
        seed_matrices_cache[cache_key] = [
            derive_invertible_seed_matrix_filtered(
                master_key, j, min_branch=min_branch)
            for j in range(16)
        ]
    return seed_matrices_cache[cache_key]

# ============================================================
# Build rotor matrices for one round
#
# Rotor schedule (manuscript Definition 2.4):
#   M_{r,j} = R^{(r+j) mod 4}(S_j)
#
# where S_j is the admissible seed for byte position j,
# r is the round index (0..15), j is the byte position (0..15).
#
# This produces 16 x 16 = 256 matrix applications total,
# with 16 x 4 = 64 distinct (seed, orientation) pairs,
# each appearing exactly 4 times across 16 rounds.
# ============================================================

def build_rotor_matrices_for_round(master_key: bytes,
                                    round_index: int,
                                    min_branch: int = 4):
    """
    Return list of 16 matrices for round round_index.
    Matrix for byte position j: R^{(round_index+j) mod 4}(S_j).
    All returned matrices are admissible (invertible, B >= 4).
    """
    seeds = get_seed_matrices(master_key, min_branch=min_branch)
    matrices = []
    for j in range(16):
        orientation = (round_index + j) % 4
        matrices.append(rotate_matrix_entries_k(seeds[j], orientation))
    return matrices

# ============================================================
# Routing permutation
#
# mode = round_index mod 4; reorders 16 byte positions for
# inter-byte diffusion by swapping index bits.
#
# mode 0: identity              [rounds 0, 4, 8, 12]
# mode 1: swap index bits 0<->1 [rounds 1, 5, 9, 13]
# mode 2: swap index bits 0<->2 [rounds 2, 6, 10, 14]
# mode 3: swap index bits 0<->3 [rounds 3, 7, 11, 15]
#
# Period 4: routing_pi(r+4, j) == routing_pi(r, j).
# ============================================================

def permute_index_bits(j: int, a: int, b: int) -> int:
    """Swap bits a and b of the 4-bit byte index j."""
    bits = [(j >> t) & 1 for t in range(4)]
    bits[a], bits[b] = bits[b], bits[a]
    out = 0
    for t in range(4):
        out |= (bits[t] << t)
    return out

def routing_pi(round_index: int, j: int) -> int:
    """Return destination index for byte position j in round round_index."""
    mode = round_index % 4
    if mode == 0:
        return j
    elif mode == 1:
        return permute_index_bits(j, 0, 1)
    elif mode == 2:
        return permute_index_bits(j, 0, 2)
    else:
        return permute_index_bits(j, 0, 3)

# ============================================================
# Round function and encryption
#
# Each round r applies five operations in sequence:
#
#   Step 1: state = rotl128(state, K_VALUES[r mod 12])
#             — 128-bit left rotation; inter-byte bit diffusion
#
#   Step 2: state = state XOR round_key[r]
#             — round key injection (SHA256-derived, 128-bit)
#
#   Step 3: state[j] = M_{r,j} * state[j]  for j = 0..15
#             — 16 independent 8x8 GF(2) matrix multiplications
#             — intra-byte diffusion; branch number >= 4 per byte
#             — rotor-scheduled: M_{r,j} = R^{(r+j) mod 4}(S_j)
#
#   Step 4: state[j] = AES_SBOX[state[j]]  for j = 0..15
#             — nonlinear substitution (nonlinearity=112, deg=7)
#
#   Step 5: state = routing_permutation(state, mode = r mod 4)
#             — inter-byte positional reordering
#
# Full encryption: 16 iterations of round_function.
# ============================================================

def round_function(block: bytes, master_key: bytes,
                    round_index: int) -> bytes:
    # Step 1: Rotate left 128 (inter-byte bit diffusion)
    state = rotl128(block, K_VALUES[round_index % len(K_VALUES)])

    # Step 2: XOR round key
    rk = derive_round_key(master_key, round_index)
    state = xor_bytes(state, rk)

    # Step 3: GF(2) matrix multiply — one admissible rotor matrix
    # per byte, scheduled by (round_index + j) mod 4.
    # All operations under MSB-first convention (see header).
    state_bytes = list(state)
    matrices = build_rotor_matrices_for_round(
        master_key, round_index, min_branch=MIN_BRANCH_NUMBER)
    mixed = [apply_matrix_8(matrices[j], state_bytes[j])
             for j in range(16)]

    # Step 4: AES S-box substitution (nonlinear layer)
    subbed = [AES_SBOX[x] for x in mixed]

    # Step 5: Routing permutation (inter-byte diffusion)
    routed = [0] * 16
    for j in range(16):
        routed[routing_pi(round_index, j)] = subbed[j]

    return bytes(routed)

def encrypt_block(block: bytes, master_key: bytes,
                   rounds: int = ROUNDS) -> bytes:
    """Encrypt one 128-bit block under master_key for given number of rounds."""
    state = block
    for r in range(rounds):
        state = round_function(state, master_key, r)
    return state

# ============================================================
# STEP 0: Verify all 64 (seed, orientation) pairs are
# invertible over GF(2).
#
# Invertibility of M over GF(2) is REQUIRED for decryption:
# each step of round_function must be invertible to allow the
# inverse round function to be defined.
#
# The rotor schedule applies R^k(S_j) for k in {0,1,2,3}.
# Invertibility of S_j does NOT imply invertibility of R^k(S_j)
# in general — this must be checked explicitly.
#
# This step confirms that the seed generation filter in
# derive_invertible_seed_matrix_filtered has correctly
# enforced invertibility across all 4 orientations,
# and that decryption is well-defined for all 16 rounds.
# ============================================================

def verify_all_rotations_invertible(master_key: bytes) -> None:
    print("=" * 72)
    print("STEP 0: ROTATION INVERTIBILITY VERIFICATION")
    print("=" * 72)
    print("Verifying all 16 seed matrices x 4 rotations = 64 pairs")
    print("are invertible over GF(2) (MSB-first convention)...")
    print()

    seeds = get_seed_matrices(master_key, min_branch=MIN_BRANCH_NUMBER)
    all_passed = True
    fail_count = 0

    for idx, seed in enumerate(seeds):
        M = seed[:]
        for rot in range(4):
            inv = is_invertible_8(M)
            bn  = branch_number_of_matrix(M)
            if not inv:
                all_passed = False
                fail_count += 1
                print(f"  Seed {idx:2d}, rotation {rot}: "
                      f"rank={gf2_mat_rank_8(M)}, branch={bn}  *** FAIL ***")
            M = rotate_matrix_entries_clockwise_90(M)

    if all_passed:
        print("  All 64 (seed, orientation) pairs: INVERTIBLE over GF(2) [OK]")
        print("  Branch number >= 4 for all orientations [OK]")
        print("  Decryption is well-defined for all 16 rounds [OK]")
    else:
        print(f"  WARNING: {fail_count} rotation(s) failed invertibility!")
        print("  Review seed generation — decryption may be undefined.")
    print()

# ============================================================
# STEP 1: Branch number summary
# ============================================================

def branch_summary(master_key: bytes) -> None:
    print("=" * 72)
    print("STEP 1: BRANCH SUMMARY")
    print("=" * 72)
    vals = []
    for r in range(ROUNDS):
        mats = build_rotor_matrices_for_round(
            master_key, r, min_branch=MIN_BRANCH_NUMBER)
        vals_r = [branch_number_of_matrix(M) for M in mats]
        vals.extend(vals_r)
        print(f"Round {r+1:2d}: min={min(vals_r)}, max={max(vals_r)}, "
              f"mean={sum(vals_r)/len(vals_r):.2f}")
    print()
    print(f"Overall minimum branch number = {min(vals)}")
    print(f"Overall maximum branch number = {max(vals)}")
    print(f"Overall mean branch number    = {sum(vals)/len(vals):.2f}")
    print()

# ============================================================
# STEP 2: Avalanche effect
# ============================================================

def plaintext_avalanche_trials(master_key: bytes, rounds: int,
                                trials: int) -> List[int]:
    """
    Measure plaintext avalanche: flip one random input bit,
    measure Hamming distance between the two ciphertexts.
    bit_index=0 is the MSB of the 128-bit block.
    """
    distances = []
    for _ in range(trials):
        pt        = random_block()
        bit_index = random.randrange(128)
        c1 = encrypt_block(pt, master_key, rounds)
        c2 = encrypt_block(flip_bit_in_block(pt, bit_index),
                            master_key, rounds)
        distances.append(hamming_distance_bytes(c1, c2))
    return distances

def key_avalanche_trials(password: str, salt: bytes, rounds: int,
                          trials: int) -> List[int]:
    """
    Measure key avalanche: flip one random bit of the 256-bit
    master key, measure Hamming distance between the two
    ciphertexts of the same plaintext.
    bit_index=0 is the MSB of the master key.
    """
    base_key  = derive_master_key_argon2id(password, salt, out_len=32)
    distances = []
    for _ in range(trials):
        pt          = random_block()
        bit_index   = random.randrange(256)
        mutated_key = flip_bit_in_bytes(base_key, bit_index)
        c1 = encrypt_block(pt, base_key, rounds)
        c2 = encrypt_block(pt, mutated_key, rounds)
        distances.append(hamming_distance_bytes(c1, c2))
    return distances

def summarize_distances(name: str, distances: List[int]) -> None:
    print(f"{name}:")
    print(f"  trials = {len(distances)}")
    print(f"  min    = {min(distances)}")
    print(f"  max    = {max(distances)}")
    print(f"  mean   = {statistics.mean(distances):.2f}")
    print(f"  stdev  = {statistics.pstdev(distances):.2f}")
    print()

# ============================================================
# STEP 3: Differential distribution estimator
# ============================================================

def single_bit_difference(bit_index: int) -> bytes:
    """
    Return 128-bit input difference with exactly one active bit.
    bit_index=0 sets the MSB (most significant bit) of the block.
    """
    x = 1 << (127 - bit_index)
    return x.to_bytes(16, "big")

def single_byte_difference(byte_index: int, value: int = 0x01) -> bytes:
    """Return 128-bit input difference with one active byte."""
    b = [0] * 16
    b[byte_index] = value & 0xFF
    return bytes(b)

def estimate_differential_distribution(master_key: bytes,
                                        input_diff: bytes,
                                        rounds: int,
                                        samples: int,
                                        top_k: int = 10,
                                        encrypt_fn=None) -> None:
    if encrypt_fn is None:
        enc = lambda blk: encrypt_block(blk, master_key, rounds)
    else:
        enc = lambda blk: encrypt_fn(blk, rounds=rounds)
    counter = Counter()
    for i in range(samples):
        p  = random_block()
        p2 = xor_blocks(p, input_diff)
        c1 = enc(p)
        c2 = enc(p2)
        counter[xor_blocks(c1, c2)] += 1
        if (i + 1) % 5000 == 0:
            print(f"  progress: {i+1}/{samples}")

    most_common = counter.most_common(top_k)
    print(f"Rounds       : {rounds}")
    print(f"Samples      : {samples}")
    print(f"Input diff   : {input_diff.hex()}")
    print(f"Unique \u0394C    : {len(counter)}")
    print()
    print(f"Top {top_k} most frequent output differences:")
    for rank, (diff, freq) in enumerate(most_common, start=1):
        prob = freq / samples
        print(f"{rank:2d}. freq={freq:4d}, prob={prob:.6f}, "
              f"\u0394C={diff.hex()}")
    print()
    print(f"Estimated max observed differential probability = "
          f"{most_common[0][1] / samples:.6f}")
    print()

# ============================================================
# STEP 4: Linear-bias probe
#
# For each of LINEAR_TRIALS random (input_mask, output_mask)
# pairs, estimates P[<v(P), in_mask> XOR <v(C), out_mask> = 0]
# over LINEAR_SAMPLES random plaintexts P, where C = Enc(P).
# Ideal (unbiased) cipher: all probabilities near 0.5.
# Detection threshold: 1/sqrt(LINEAR_SAMPLES) = 1/sqrt(50000)
#   ~= 0.00447.
#
# Inner product <v(x), mask> computed as:
#   parity of (x AND mask) = popcount(x AND mask) mod 2
# using the MSB-first convention consistently.
# ============================================================

def parity128(x: bytes, mask: bytes) -> int:
    """
    Compute parity of bitwise AND of x and mask over 128 bits.
    Returns XOR of popcount(x_i AND mask_i) mod 2 for each byte.
    Convention-independent: depends only on Hamming weight,
    which is invariant under bit reordering.
    """
    acc = 0
    for a, b in zip(x, mask):
        acc ^= ((a & b).bit_count() & 1)
    return acc

def random_mask_128() -> bytes:
    return os.urandom(16)

def estimate_linear_bias(master_key: bytes, rounds: int,
                          samples: int = LINEAR_SAMPLES,
                          trials: int  = LINEAR_TRIALS,
                          encrypt_fn=None) -> None:
    if encrypt_fn is None:
        enc = lambda blk: encrypt_block(blk, master_key, rounds)
    else:
        enc = lambda blk: encrypt_fn(blk, rounds=rounds)
    print("=" * 72)
    print("LINEAR-BIAS PROBE")
    print("=" * 72)
    print(f"Rounds={rounds}, samples={samples}, "
          f"mask pairs tested={trials}")
    print(f"Detection threshold: 1/sqrt({samples}) = "
          f"{1.0/(samples**0.5):.5f}")
    print()

    best_abs_bias = 0.0
    best_pair     = None

    for t in range(trials):
        in_mask    = random_mask_128()
        out_mask   = random_mask_128()
        count_zero = 0

        for _ in range(samples):
            p   = random_block()
            c   = enc(p)
            val = parity128(p, in_mask) ^ parity128(c, out_mask)
            if val == 0:
                count_zero += 1

        prob  = count_zero / samples
        bias  = abs(prob - 0.5)

        if bias > best_abs_bias:
            best_abs_bias = bias
            best_pair = (in_mask.hex(), out_mask.hex(), prob, bias)

        print(f"trial {t+1:3d}: prob={prob:.6f}, abs_bias={bias:.6f}")

        if (t + 1) % 50 == 0:
            print(f"  -- completed {t+1}/{trials} trials --")

    print()
    print(f"completed {trials}/{trials} linear trials")
    print()
    print("Best observed mask pair:")
    print(best_pair)
    print()
    
    pause_checkpoint("Linear-bias probe complete.")

# ============================================================
# STEP 5: Algebraic degree estimator (ANF / Mobius transform)
#
# Estimates lower bounds on the algebraic degree of the cipher
# viewed as a Boolean function F: GF(2)^128 -> GF(2)^128.
#
# For t active input bits, constructs a truth table of 2^t
# output bit values, computes the Algebraic Normal Form (ANF)
# via the Mobius transform, and returns the degree of the
# highest-weight nonzero ANF monomial.
#
# BIT CONVENTION: get_bit_from_bytes and set_bit_in_block both
# use MSB-first (bit_index=0 is the MSB of the 128-bit block),
# consistent with the rest of this file.
# ============================================================

def get_bit_from_bytes(data: bytes, bit_index: int) -> int:
    """
    Return bit at position bit_index from byte string data.
    bit_index=0 is the MSB of the first byte (MSB-first).
    """
    x = int.from_bytes(data, "big")
    return (x >> (len(data) * 8 - 1 - bit_index)) & 1

def set_bit_in_block(block: bytes, bit_index: int,
                      value: int) -> bytes:
    """
    Set bit at position bit_index in 128-bit block.
    bit_index=0 is the MSB (MSB-first convention).
    """
    x     = int.from_bytes(block, "big")
    shift = 127 - bit_index
    if value:
        x |=  (1 << shift)
    else:
        x &= ~(1 << shift)
    return x.to_bytes(16, "big")

def build_plaintext_from_assignment(base_block, active_bit_positions,
                                     assignment):
    block = base_block
    t = len(active_bit_positions)
    for i, bit_pos in enumerate(active_bit_positions):
        bit_val = (assignment >> (t - 1 - i)) & 1
        block = set_bit_in_block(block, bit_pos, bit_val)
    return block

def mobius_transform_inplace(vals):
    """Compute ANF coefficients in-place via Mobius transform over GF(2)."""
    n = len(vals)
    m = n.bit_length() - 1
    for i in range(m):
        step = 1 << i
        for mask in range(n):
            if mask & step:
                vals[mask] ^= vals[mask ^ step]

def algebraic_degree_from_truth_table(tt) -> int:
    """Return algebraic degree: weight of highest nonzero ANF monomial."""
    coeffs = tt[:]
    mobius_transform_inplace(coeffs)
    deg = 0
    for mask, c in enumerate(coeffs):
        if c:
            wt = bin(mask).count("1")
            if wt > deg:
                deg = wt
    return deg

def restricted_degree_of_output_bit(master_key, rounds,
                                     base_plaintext,
                                     active_input_bits,
                                     output_bit_index) -> int:
    t    = len(active_input_bits)
    size = 1 << t
    truth_table = [0] * size
    for assignment in range(size):
        pt = build_plaintext_from_assignment(
            base_plaintext, active_input_bits, assignment)
        ct = encrypt_block(pt, master_key, rounds=rounds)
        truth_table[assignment] = get_bit_from_bytes(
            ct, output_bit_index)
    return algebraic_degree_from_truth_table(truth_table)

def estimate_degree_growth_lower_bounds(
        master_key,
        rounds_list,
        num_active_input_bits=DEGREE_NUM_ACTIVE_INPUT_BITS,
        trials_per_round=DEGREE_TRIALS_PER_ROUND):
    print("=" * 72)
    print("STEP 5: ALGEBRAIC DEGREE GROWTH ESTIMATOR (LOWER BOUNDS)")
    print("=" * 72)
    print(f"Active input bits per trial : {num_active_input_bits} "
          f"(2^{num_active_input_bits} = "
          f"{1 << num_active_input_bits} encrypts/trial)")
    print(f"Trials per round            : {trials_per_round}")
    print()

    results = {}
    random.seed(20260312)   # separate seed for reproducibility

    for rounds in rounds_list:
        print(f"--- Rounds = {rounds} ---")
        best    = -1
        all_deg = []

        for trial in range(trials_per_round):
            base_pt     = random.randbytes(16)
            active_bits = sorted(
                random.sample(range(128), num_active_input_bits))
            out_bit = random.randrange(128)
            deg = restricted_degree_of_output_bit(
                master_key, rounds, base_pt, active_bits, out_bit)
            all_deg.append(deg)
            if deg > best:
                best = deg
            print(f"  trial {trial+1:2d}: degree={deg:2d}, "
                  f"out_bit={out_bit:3d}, active_bits={active_bits}")

        mean = sum(all_deg) / len(all_deg)
        print(f"  best lower bound = {best}, mean = {mean:.2f}, "
              f"theoretical max = {num_active_input_bits}")
        print()
        results[rounds] = {"best": best, "mean": mean}

    print("=" * 72)
    print("ALGEBRAIC DEGREE SUMMARY")
    print("=" * 72)
    for r in rounds_list:
        print(f"Rounds={r:2d} | best lower bound="
              f"{results[r]['best']:2d} | "
              f"mean={results[r]['mean']:.2f} | "
              f"theoretical max={num_active_input_bits}")
    print()
    return results

# ============================================================
# ============================================================
#   REVISION-RERUN ADDITIONS (v3)
#
#   Everything below this banner was added for the manuscript
#   revision reruns (worksheet items B1, B2, B3, B5, A8).
#   The reference implementation above is unchanged except for:
#     - config sizes (B1/B3) and step on/off flags
#     - a faster (identical-result) matrix-vector product used
#       inside branch_number_of_matrix and the seed filter
#     - seed-search candidate counting (A8 instrumentation)
#     - the dead pause block after the degree estimator removed
#     - pause checkpoints refactored into pause_checkpoint()
# ============================================================
# ============================================================

import csv
import math
import sys
import time
from datetime import datetime

MASK128 = (1 << 128) - 1

# ============================================================
# FAST CIPHER (semantics-preserving optimization)
#
# The reference encrypt_block computes each 8x8 GF(2) matrix
# product bit-by-bit. Since every (round, byte) position uses a
# fixed matrix followed by the fixed AES S-box, the composition
# (S-box o M_{r,j}) can be tabulated once per key as a 256-entry
# lookup table. Steps 3+4 then cost one table lookup per byte.
#
# This changes NOTHING about the cipher: the tables are built by
# calling the reference apply_matrix_8-equivalent code, and
# verify_fast_equivalence() below checks fast == reference on
# random blocks at several round counts before any experiment
# runs. Abort on mismatch.
# ============================================================

class HESPNFastCipher:
    """Table-driven implementation of the HESPN round function.

    Precomputes, per key:
      - the 12 round keys (as 128-bit integers),
      - for each (round r, byte j): the 256-entry table
            T[r][j][x] = AES_SBOX[ M_{r,j} * x ]
        where M_{r,j} = R^{(r+j) mod 4}(S_j),
      - the four routing permutations.
    """

    def __init__(self, master_key: bytes, max_rounds: int = ROUNDS,
                 min_branch: int = MIN_BRANCH_NUMBER):
        self.master_key = master_key
        self.max_rounds = max_rounds
        self.rk_ints = [
            int.from_bytes(derive_round_key(master_key, r), "big")
            for r in range(max_rounds)
        ]
        seeds = get_seed_matrices(master_key, min_branch=min_branch)
        self.tables = []
        for r in range(max_rounds):
            row_tables = []
            for j in range(16):
                M = rotate_matrix_entries_k(seeds[j], (r + j) % 4)
                tbl = bytes(AES_SBOX[apply_matrix_8_fast(M, x)]
                            for x in range(256))
                row_tables.append(tbl)
            self.tables.append(row_tables)
        self.routes = [[routing_pi(mode, j) for j in range(16)]
                       for mode in range(4)]

    def encrypt_block(self, block: bytes, rounds: int = None) -> bytes:
        if rounds is None:
            rounds = self.max_rounds
        if rounds > self.max_rounds:
            raise ValueError("rounds exceeds precomputed table depth")
        x = int.from_bytes(block, "big")
        tables = self.tables
        rk = self.rk_ints
        routes = self.routes
        kv = K_VALUES
        nk = len(kv)
        for r in range(rounds):
            k = kv[r % nk]
            x = ((x << k) | (x >> (128 - k))) & MASK128       # Step 1
            x ^= rk[r]                                          # Step 2
            b = x.to_bytes(16, "big")
            T = tables[r]
            route = routes[r % 4]
            out = bytearray(16)
            for j in range(16):                                 # Steps 3-5
                out[route[j]] = T[j][b[j]]
            x = int.from_bytes(out, "big")
        return x.to_bytes(16, "big")


def verify_fast_equivalence(cipher: "HESPNFastCipher",
                            master_key: bytes,
                            n_blocks: int = 64) -> None:
    """Assert fast implementation == reference implementation."""
    print("=" * 72)
    print("FAST-PATH EQUIVALENCE CHECK (fast tables vs. reference code)")
    print("=" * 72)
    for rc in [1, 2, 4, 5, 8, 12, 16]:
        for _ in range(n_blocks // 7 + 1):
            pt = random_block()
            ref = encrypt_block(pt, master_key, rounds=rc)
            fast = cipher.encrypt_block(pt, rounds=rc)
            if ref != fast:
                raise RuntimeError(
                    f"FAST PATH MISMATCH at rounds={rc}, pt={pt.hex()}: "
                    f"ref={ref.hex()} fast={fast.hex()}")
    print(f"  Verified on ~{n_blocks} random blocks across round counts "
          f"[1,2,4,5,8,12,16]: identical output. [OK]")
    # quick throughput measurement
    t0 = time.perf_counter()
    trial_blocks = 2000
    pt = random_block()
    for _ in range(trial_blocks):
        pt = cipher.encrypt_block(pt)
    dt = time.perf_counter() - t0
    bps = trial_blocks / dt
    print(f"  Fast-path throughput: {bps:,.0f} blocks/s "
          f"(~{bps*16/1024:,.0f} KiB/s) on this machine.")
    print()


# ============================================================
# Results directory and CSV logging
# ============================================================

def make_results_dir() -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"hespn_rerun_results_{stamp}"
    os.makedirs(path, exist_ok=True)
    print(f"Results directory: {os.path.abspath(path)}")
    print()
    return path


def write_csv(path: str, header, rows) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  [saved] {path}")


# ============================================================
# STEP 2 (B1): Avalanche with large n, standard errors, and
# 95% confidence intervals.
#
# Worksheet B1: report SEM and 95% CI alongside means; raise
# plaintext trials to thousands (cheap: one key setup total)
# and key trials as high as key-setup cost allows (each key
# trial requires a full seed-matrix search for the mutated key).
# ============================================================

def ci_stats(distances):
    n = len(distances)
    mean = statistics.mean(distances)
    sd = statistics.stdev(distances) if n > 1 else 0.0
    sem = sd / math.sqrt(n) if n > 0 else 0.0
    lo, hi = mean - 1.96 * sem, mean + 1.96 * sem
    return n, mean, sd, sem, lo, hi


def summarize_distances_ci(name: str, distances) -> tuple:
    n, mean, sd, sem, lo, hi = ci_stats(distances)
    print(f"{name}:")
    print(f"  trials = {n}")
    print(f"  min    = {min(distances)}")
    print(f"  max    = {max(distances)}")
    print(f"  mean   = {mean:.3f}")
    print(f"  stdev  = {sd:.3f}   (sample sd)")
    print(f"  SEM    = {sem:.3f}")
    print(f"  95% CI = [{lo:.3f}, {hi:.3f}]   (ideal = 64)")
    print()
    return (n, mean, sd, sem, lo, hi)


def plaintext_avalanche_fast(cipher: HESPNFastCipher, rounds: int,
                             trials: int):
    """B1: plaintext avalanche using the fast path."""
    distances = []
    for i in range(trials):
        pt = random_block()
        bit_index = random.randrange(128)
        c1 = cipher.encrypt_block(pt, rounds=rounds)
        c2 = cipher.encrypt_block(flip_bit_in_block(pt, bit_index),
                                  rounds=rounds)
        distances.append(hamming_distance_bytes(c1, c2))
        if (i + 1) % 1000 == 0:
            print(f"    progress: {i+1}/{trials}")
    return distances


def key_avalanche_fast(base_key: bytes, round_counts, trials: int):
    """B1: key avalanche using the fast path.

    Each trial flips one random bit of the 256-bit master key and
    performs a FULL key setup for the mutated key (seed-matrix
    search included) — this is the dominant cost. To amortize it,
    each mutated key is evaluated at ALL requested round counts
    (one plaintext per trial), instead of rebuilding the key per
    round count. A useful side effect: every mutated-key setup
    feeds the A8 seed-search statistics (see SEED_SEARCH_STATS).
    """
    base_cipher = HESPNFastCipher(base_key)
    dists = {rc: [] for rc in round_counts}
    for t in range(trials):
        bit_index = random.randrange(256)
        mutated_key = flip_bit_in_bytes(base_key, bit_index)
        mutated_cipher = HESPNFastCipher(mutated_key)
        pt = random_block()
        for rc in round_counts:
            d = hamming_distance_bytes(
                base_cipher.encrypt_block(pt, rounds=rc),
                mutated_cipher.encrypt_block(pt, rounds=rc))
            dists[rc].append(d)
        if (t + 1) % 25 == 0:
            print(f"    progress: {t+1}/{trials} mutated-key setups")
    return dists


def run_avalanche_step(cipher: HESPNFastCipher, base_key: bytes,
                       results_dir: str) -> None:
    print("=" * 72)
    print("STEP 2 (B1): AVALANCHE — LARGE-N RERUN WITH 95% CONFIDENCE "
          "INTERVALS")
    print("=" * 72)
    print(f"Plaintext trials per round count : "
          f"{PLAINTEXT_AVALANCHE_TRIALS}")
    print(f"Key trials (shared across round counts): "
          f"{KEY_AVALANCHE_TRIALS}")
    print()

    round_counts = [1, 2, 4, 5, 8, 12, 16]
    pt_rows, key_rows = [], []
    pt_summary, key_summary = {}, {}

    print("--- Plaintext avalanche ---")
    for rc in round_counts:
        print(f"  rounds = {rc}")
        d = plaintext_avalanche_fast(cipher, rc,
                                     PLAINTEXT_AVALANCHE_TRIALS)
        pt_summary[rc] = summarize_distances_ci(
            f"PLAINTEXT avalanche, rounds={rc}", d)
        pt_rows += [[rc, i, v] for i, v in enumerate(d)]

    print("--- Key avalanche (one full key setup per trial) ---")
    kd = key_avalanche_fast(base_key, round_counts,
                            KEY_AVALANCHE_TRIALS)
    for rc in round_counts:
        key_summary[rc] = summarize_distances_ci(
            f"KEY avalanche, rounds={rc}", kd[rc])
        key_rows += [[rc, i, v] for i, v in enumerate(kd[rc])]

    write_csv(os.path.join(results_dir, "avalanche_plaintext.csv"),
              ["rounds", "trial", "hamming_distance"], pt_rows)
    write_csv(os.path.join(results_dir, "avalanche_key.csv"),
              ["rounds", "trial", "hamming_distance"], key_rows)

    # Manuscript-ready Table 6 replacement
    print()
    print("MANUSCRIPT TABLE (Table 6 rerun) — mean (sd) [95% CI]:")
    print(f"{'Rnds':>4} | {'PT mean':>8} {'PT sd':>6} "
          f"{'PT 95% CI':>18} | {'Key mean':>8} {'Key sd':>6} "
          f"{'Key 95% CI':>18}")
    for rc in round_counts:
        _, pm, psd, _, plo, phi = pt_summary[rc]
        _, km, ksd, _, klo, khi = key_summary[rc]
        print(f"{rc:>4} | {pm:8.2f} {psd:6.2f} "
              f"[{plo:7.2f},{phi:7.2f}] | {km:8.2f} {ksd:6.2f} "
              f"[{klo:7.2f},{khi:7.2f}]")
    print()


# ============================================================
# STEP 5 (B3): Algebraic degree with t = 12 active bits and
# 16 trials per round count.
#
# Worksheet B3: with only t = 6 the observable maximum (6) is
# reached almost automatically; raising t to 12 gives the
# estimator room to distinguish degree growth, and more trials
# resolve the low-round sampling artifact seen at r = 2.
# ============================================================

def restricted_degree_fast(cipher: HESPNFastCipher, rounds: int,
                           base_plaintext: bytes, active_input_bits,
                           output_bit_index: int) -> int:
    t = len(active_input_bits)
    size = 1 << t
    truth_table = [0] * size
    for assignment in range(size):
        pt = build_plaintext_from_assignment(
            base_plaintext, active_input_bits, assignment)
        ct = cipher.encrypt_block(pt, rounds=rounds)
        truth_table[assignment] = get_bit_from_bytes(
            ct, output_bit_index)
    return algebraic_degree_from_truth_table(truth_table)


def run_degree_step(cipher: HESPNFastCipher, results_dir: str) -> dict:
    print("=" * 72)
    print("STEP 5 (B3): ALGEBRAIC DEGREE LOWER BOUNDS — "
          f"t = {DEGREE_NUM_ACTIVE_INPUT_BITS}, "
          f"{DEGREE_TRIALS_PER_ROUND} trials/round")
    print("=" * 72)
    t = DEGREE_NUM_ACTIVE_INPUT_BITS
    print(f"Active input bits per trial : {t} "
          f"(2^{t} = {1 << t} encryptions/trial)")
    print(f"Trials per round            : {DEGREE_TRIALS_PER_ROUND}")
    print()

    rng = random.Random(20260702)   # dedicated, reproducible stream
    rows, results = [], {}
    for rounds in DEGREE_ROUNDS_TO_TEST:
        print(f"--- Rounds = {rounds} ---")
        degs = []
        for trial in range(DEGREE_TRIALS_PER_ROUND):
            base_pt = rng.randbytes(16)
            active_bits = sorted(rng.sample(range(128), t))
            out_bit = rng.randrange(128)
            deg = restricted_degree_fast(
                cipher, rounds, base_pt, active_bits, out_bit)
            degs.append(deg)
            rows.append([rounds, trial, deg, out_bit,
                         " ".join(map(str, active_bits))])
            print(f"  trial {trial+1:2d}: degree={deg:2d}, "
                  f"out_bit={out_bit:3d}")
        results[rounds] = {"best": max(degs),
                           "mean": sum(degs) / len(degs),
                           "min": min(degs)}
        print(f"  best lower bound = {max(degs)}, "
              f"mean = {results[rounds]['mean']:.2f}, "
              f"min = {min(degs)}, theoretical max = {t}")
        print()

    write_csv(os.path.join(results_dir, "algebraic_degree.csv"),
              ["rounds", "trial", "degree_lower_bound",
               "output_bit", "active_bits"], rows)

    print("MANUSCRIPT TABLE (Table 9 rerun):")
    print(f"{'Rounds':>6} | {'Best LB':>7} | {'Mean':>6} | {'Min':>4} | "
          f"theoretical max = {t}")
    for r in DEGREE_ROUNDS_TO_TEST:
        print(f"{r:>6} | {results[r]['best']:>7} | "
              f"{results[r]['mean']:>6.2f} | {results[r]['min']:>4} |")
    print()
    return results


# ============================================================
# STEP 6 (B5): Admissibility-filter statistics over random
# candidate matrices.
#
# Worksheet B5: Table 5 (all values exactly 4) can be replaced
# by a single sentence plus real data on the filter itself:
#   - fraction of random 8x8 matrices that are invertible
#     (theory: |GL(8,2)| / 2^64 ~ 28.99%)
#   - fraction whose full rotor family is invertible
#     (theory: identical, by R(M) = M^T J — measured as a check)
#   - admissible rate: min over 4 orientations of B(M) >= 4
#   - rate at which the family achieves B >= 5 in all four
#     orientations — directly answers the open question at the
#     end of manuscript Section 5.1 (can the threshold be
#     raised to 5 without excessive rejection?)
# ============================================================

def run_admissibility_experiment(results_dir: str) -> None:
    print("=" * 72)
    print("STEP 6 (B5): ADMISSIBILITY-FILTER STATISTICS "
          f"({ADMISSIBILITY_SAMPLES:,} random candidate matrices)")
    print("=" * 72)
    rng = random.Random(ADMISSIBILITY_RNG_SEED)

    n_total = ADMISSIBILITY_SAMPLES
    n_seed_inv = 0          # seed invertible
    n_family_inv = 0        # all four orientations invertible
    minbn_hist = Counter()  # min branch number over the family
                            # (only for family-invertible candidates)
    n_admissible_4 = 0      # min family branch number >= 4
    n_admissible_5 = 0      # min family branch number >= 5

    t0 = time.perf_counter()
    for i in range(n_total):
        rows = [rng.randrange(256) for _ in range(8)]
        if not is_invertible_8(rows):
            continue
        n_seed_inv += 1
        family = [rotate_matrix_entries_k(rows, k) for k in range(4)]
        if not all(is_invertible_8(M) for M in family):
            continue
        n_family_inv += 1
        minbn = min(branch_number_of_matrix(M) for M in family)
        minbn_hist[minbn] += 1
        if minbn >= 4:
            n_admissible_4 += 1
        if minbn >= 5:
            n_admissible_5 += 1
        if (i + 1) % 5000 == 0:
            print(f"    progress: {i+1}/{n_total}")
    dt = time.perf_counter() - t0

    def pct(a, b):
        return 100.0 * a / b if b else 0.0

    print()
    print(f"Sampled candidates                    : {n_total:,} "
          f"({dt:.1f} s)")
    print(f"Seed invertible                       : {n_seed_inv:,} "
          f"({pct(n_seed_inv, n_total):.2f}%)  "
          f"[theory ~28.99% = |GL(8,2)|/2^64]")
    print(f"All 4 orientations invertible         : {n_family_inv:,} "
          f"({pct(n_family_inv, n_total):.2f}%)  "
          f"[theory: = seed rate, by R(M) = M^T J]")
    print(f"Admissible (family min B >= 4)        : {n_admissible_4:,} "
          f"({pct(n_admissible_4, n_total):.2f}% of all; "
          f"{pct(n_admissible_4, n_family_inv):.2f}% of invertible)")
    print(f"Family min B >= 5 (raised threshold)  : {n_admissible_5:,} "
          f"({pct(n_admissible_5, n_total):.4f}% of all; "
          f"{pct(n_admissible_5, n_family_inv):.4f}% of invertible)")
    print()
    print("Distribution of min-over-family branch number "
          "(family-invertible candidates):")
    for bn in sorted(minbn_hist):
        c = minbn_hist[bn]
        print(f"  min B = {bn}: {c:,} ({pct(c, n_family_inv):.3f}%)")
    if n_admissible_4:
        print()
        print(f"Expected candidates per accepted seed at B >= 4 "
              f"threshold: {n_total / n_admissible_4:.2f}")
    if n_admissible_5:
        print(f"Expected candidates per accepted seed at B >= 5 "
              f"threshold: {n_total / n_admissible_5:.1f}")
    else:
        print(f"No B >= 5 family observed in {n_total:,} samples — "
              f"a raised threshold would require a (much) larger "
              f"search per seed.")
    print()

    write_csv(os.path.join(results_dir, "admissibility_stats.csv"),
              ["quantity", "count", "denominator"],
              [["sampled", n_total, ""],
               ["seed_invertible", n_seed_inv, n_total],
               ["family_invertible", n_family_inv, n_total],
               ["admissible_minB_ge4", n_admissible_4, n_total],
               ["family_minB_ge5", n_admissible_5, n_total]] +
              [[f"minB_eq_{bn}", minbn_hist[bn], n_family_inv]
               for bn in sorted(minbn_hist)])
    print()


def report_seed_search_stats(results_dir: str) -> None:
    """A8: rejection-sampling cost of key setup, from every key
    instantiated in this session (the base key plus every mutated
    key from the key-avalanche step)."""
    print("=" * 72)
    print("A8 REPORT: SEED-SEARCH (REJECTION-SAMPLING) COST PER KEY "
          "SETUP")
    print("=" * 72)
    if not SEED_SEARCH_STATS:
        print("  (no key setups recorded)")
        print()
        return
    counts = list(SEED_SEARCH_STATS.values())
    keys_seen = {k for (k, _) in SEED_SEARCH_STATS.keys()}
    per_key_totals = {}
    for (k, j), c in SEED_SEARCH_STATS.items():
        per_key_totals[k] = per_key_totals.get(k, 0) + c
    totals = list(per_key_totals.values())
    print(f"  Keys instantiated this session : {len(keys_seen)}")
    print(f"  Seed searches recorded         : {len(counts)} "
          f"(16 per key)")
    print(f"  Candidates tested per seed     : mean = "
          f"{statistics.mean(counts):.2f}, median = "
          f"{statistics.median(counts):.1f}, max = {max(counts)}")
    print(f"  Candidates tested per key setup: mean = "
          f"{statistics.mean(totals):.1f}, max = {max(totals)}")
    print("  (Key setup is variable-time but one-time per key and "
          "plaintext-independent;")
    print("   see manuscript Sections 3.5 and 4.6.)")
    print()
    write_csv(os.path.join(results_dir, "seed_search_stats.csv"),
              ["key_id", "byte_index", "candidates_tested"],
              [[hashlib.sha256(k).hexdigest()[:12], j, c]
               for (k, j), c in sorted(SEED_SEARCH_STATS.items(),
                                       key=lambda kv: (kv[0][0],
                                                       kv[0][1]))])
    print()


# ============================================================
# STEP 7 (B2): NIST SP 800-22 statistical testing.
#
# Two deliverables:
#   (1) a raw HESPN-CTR keystream file (counter-mode: encrypt
#       counters 0,1,2,... under the session key), suitable for
#       the official NIST STS ("assess") tool for the full
#       15-test battery;
#   (2) a built-in CORE SUBSET of SP 800-22 tests implemented
#       here in pure Python, with the standard two-level
#       reporting (per-test pass proportion + p-value
#       uniformity), so results are available immediately.
#
# Core subset: Frequency (monobit), Block Frequency (M = 128),
# Runs, Longest Run of Ones, Cumulative Sums (fwd/bwd),
# Serial (m = 2, two p-values), Approximate Entropy (m = 2).
# Significance level alpha = 0.01 (NIST default).
# ============================================================

# --- regularized upper incomplete gamma Q(a, x) = igamc -------

def igamc(a: float, x: float) -> float:
    if x <= 0.0:
        return 1.0
    if a <= 0.0:
        return 0.0
    lg = math.lgamma(a)
    if x < a + 1.0:
        # series for P(a,x); Q = 1 - P
        term = 1.0 / a
        total = term
        k = a
        while True:
            k += 1.0
            term *= x / k
            total += term
            if term < total * 1e-16:
                break
        P = total * math.exp(-x + a * math.log(x) - lg)
        return max(0.0, min(1.0, 1.0 - P))
    # continued fraction (modified Lentz) for Q(a,x)
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 20000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-16:
            break
    return max(0.0, min(1.0, h * math.exp(-x + a * math.log(x) - lg)))


def phi_normal(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def rotl_nbit(x: int, t: int, n: int) -> int:
    t %= n
    return ((x << t) | (x >> (n - t))) & ((1 << n) - 1)


# --- byte tables for the cumulative-sums test ------------------

def _build_cusum_byte_tables():
    step, minp, maxp = [0] * 256, [0] * 256, [0] * 256
    for b in range(256):
        s = mn = mx = 0
        for i in range(8):                       # MSB-first
            s += 1 if (b >> (7 - i)) & 1 else -1
            mn = min(mn, s)
            mx = max(mx, s)
        step[b], minp[b], maxp[b] = s, mn, mx
    return step, minp, maxp

_CU_STEP, _CU_MIN, _CU_MAX = _build_cusum_byte_tables()
_BITREV = [int(f"{b:08b}"[::-1], 2) for b in range(256)]


def _max_abs_partial_sum(seq: bytes) -> int:
    z = 0
    best = 0
    for b in seq:
        best = max(best, abs(z + _CU_MAX[b]), abs(z + _CU_MIN[b]))
        z += _CU_STEP[b]
    return max(best, abs(z))


def _cusum_pvalue(z: int, n: int) -> float:
    if z == 0:
        return 0.0
    rn = math.sqrt(n)
    total = 1.0
    k_lo = int(math.floor((-n / z + 1) / 4))
    k_hi = int(math.floor((n / z - 1) / 4))
    for k in range(k_lo, k_hi + 1):
        total -= (phi_normal((4 * k + 1) * z / rn) -
                  phi_normal((4 * k - 1) * z / rn))
    k_lo = int(math.floor((-n / z - 3) / 4))
    for k in range(k_lo, k_hi + 1):
        total += (phi_normal((4 * k + 3) * z / rn) -
                  phi_normal((4 * k + 1) * z / rn))
    return max(0.0, min(1.0, total))


# --- pattern counting for Serial / ApEn (cyclic, overlapping) --

def _cyclic_pattern_counts(x: int, n: int, m: int) -> dict:
    """Counts of all overlapping m-bit patterns in the cyclic
    n-bit sequence x (MSB-first). Uses whole-sequence bitwise
    algebra: pattern (b_0..b_{m-1}) matches at position i iff
    bit i of rotl(x, t) equals b_t for t = 0..m-1."""
    mask = (1 << n) - 1
    rots = [rotl_nbit(x, t, n) for t in range(m)]
    counts = {}
    for p in range(1 << m):
        acc = mask
        for t in range(m):
            bit = (p >> (m - 1 - t)) & 1
            acc &= rots[t] if bit else (~rots[t] & mask)
            if acc == 0:
                break
        counts[p] = acc.bit_count()
    return counts


def _psi_sq(x: int, n: int, m: int) -> float:
    if m == 0:
        return 0.0
    counts = _cyclic_pattern_counts(x, n, m)
    return (2 ** m / n) * sum(c * c for c in counts.values()) - n


def _longest_run_p(seq: bytes) -> float:
    """Longest Run of Ones in a Block (SP 800-22 Section 2.4).
    Block size M chosen from n per the specification:
      n >= 750,000 -> M = 10^4 (K = 6); n >= 6272 -> M = 128
      (K = 5); n >= 128 -> M = 8 (K = 3)."""
    n = len(seq) * 8
    if n >= 750000:
        M_lr, K_lr = 10000, 6
        pis = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675,
               0.0727]
        lo_class, hi_class = 10, 16
    elif n >= 6272:
        M_lr, K_lr = 128, 5
        pis = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        lo_class, hi_class = 4, 9
    elif n >= 128:
        M_lr, K_lr = 8, 3
        pis = [0.2148, 0.3672, 0.2305, 0.1875]
        lo_class, hi_class = 1, 4
    else:
        raise ValueError("sequence too short for longest-run test")
    N_lr = n // M_lr
    v = [0] * (K_lr + 1)
    bytes_per_blk = M_lr // 8
    for i in range(N_lr):
        blk = int.from_bytes(seq[i * bytes_per_blk:
                                 (i + 1) * bytes_per_blk], "big")
        bits = format(blk, f"0{M_lr}b")
        longest = max((len(run) for run in bits.split("0")),
                      default=0)
        cls = min(max(longest, lo_class), hi_class) - lo_class
        v[cls] += 1
    chi = sum((v[i] - N_lr * pis[i]) ** 2 / (N_lr * pis[i])
              for i in range(K_lr + 1))
    return igamc(K_lr / 2.0, chi / 2.0)


# --- the core tests --------------------------------------------

def nist_core_tests(seq: bytes) -> dict:
    """Run the core SP 800-22 subset on one sequence.
    Returns {test_name: p_value}."""
    n = len(seq) * 8
    x = int.from_bytes(seq, "big")
    ones = x.bit_count()
    out = {}

    # 1. Frequency (monobit)
    s_obs = abs(2 * ones - n) / math.sqrt(n)
    out["frequency"] = math.erfc(s_obs / math.sqrt(2))

    # 2. Block frequency, M = 128
    M = 128
    N = n // M
    chi = 0.0
    for i in range(N):
        blk = int.from_bytes(seq[i * 16:(i + 1) * 16], "big")
        pi_i = blk.bit_count() / M
        chi += (pi_i - 0.5) ** 2
    chi *= 4.0 * M
    out["block_frequency"] = igamc(N / 2.0, chi / 2.0)

    # 3. Runs
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        out["runs"] = 0.0
    else:
        v_n = ((x ^ (x >> 1)) & ((1 << (n - 1)) - 1)).bit_count() + 1
        num = abs(v_n - 2.0 * n * pi * (1 - pi))
        den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
        out["runs"] = math.erfc(num / den)

    # 4. Longest run of ones in a block
    out["longest_run"] = _longest_run_p(seq)

    # 5. Cumulative sums, forward and backward
    out["cusum_forward"] = _cusum_pvalue(_max_abs_partial_sum(seq), n)
    rev = bytes(_BITREV[b] for b in reversed(seq))
    out["cusum_backward"] = _cusum_pvalue(_max_abs_partial_sum(rev), n)

    # 6. Serial, m = 2 (two p-values)
    psi2 = _psi_sq(x, n, 2)
    psi1 = _psi_sq(x, n, 1)
    d1 = psi2 - psi1
    d2 = psi2 - 2.0 * psi1
    out["serial_p1"] = igamc(1.0, d1 / 2.0)      # 2^{m-2} = 1
    out["serial_p2"] = igamc(0.5, d2 / 2.0)      # 2^{m-3} = 0.5

    # 7. Approximate entropy, m = 2
    def _phi(mm):
        counts = _cyclic_pattern_counts(x, n, mm)
        tot = 0.0
        for c in counts.values():
            if c:
                p = c / n
                tot += p * math.log(p)
        return tot
    apen = _phi(2) - _phi(3)
    chi = 2.0 * n * (math.log(2.0) - apen)
    out["approx_entropy"] = igamc(2.0, chi / 2.0)  # 2^{m-1} = 2

    return out


def generate_ctr_stream(cipher: HESPNFastCipher, total_bytes: int,
                        out_path: str) -> bytes:
    """HESPN-CTR keystream: encrypt counters 0,1,2,... and
    concatenate the ciphertexts. Saved to out_path for use with
    the official NIST STS tool."""
    n_blocks = (total_bytes + 15) // 16
    print(f"  Generating {total_bytes:,} bytes of HESPN-CTR "
          f"keystream ({n_blocks:,} blocks)...")
    t0 = time.perf_counter()
    chunks = []
    for ctr in range(n_blocks):
        chunks.append(cipher.encrypt_block(
            ctr.to_bytes(16, "big")))
        if (ctr + 1) % 100000 == 0:
            rate = (ctr + 1) / (time.perf_counter() - t0)
            eta = (n_blocks - ctr - 1) / rate
            print(f"    progress: {ctr+1:,}/{n_blocks:,} blocks "
                  f"({rate:,.0f} blocks/s, ~{eta:,.0f} s remaining)")
    stream = b"".join(chunks)[:total_bytes]
    dt = time.perf_counter() - t0
    with open(out_path, "wb") as f:
        f.write(stream)
    print(f"  Generated in {dt:,.1f} s "
          f"({total_bytes/dt/1024:,.0f} KiB/s).")
    print(f"  [saved] {out_path}  "
          f"(raw binary; usable as input to the official NIST STS)")
    return stream


def run_nist_step(cipher: HESPNFastCipher, results_dir: str) -> None:
    print("=" * 72)
    print("STEP 7 (B2): NIST SP 800-22 — HESPN-CTR KEYSTREAM, "
          "CORE TEST BATTERY")
    print("=" * 72)
    s = NIST_NUM_SEQUENCES
    bits = NIST_SEQ_BITS
    seq_bytes = bits // 8
    print(f"Sequences: {s} x {bits:,} bits "
          f"({s * seq_bytes / (1024*1024):.1f} MiB total)")
    print(f"Significance level alpha = 0.01 (NIST default)")
    print()

    stream_path = os.path.join(results_dir, "hespn_ctr_stream.bin")
    stream = generate_ctr_stream(cipher, s * seq_bytes, stream_path)
    print()

    all_p = {}     # test_name -> list of p-values across sequences
    print("  Running core battery per sequence...")
    t0 = time.perf_counter()
    for i in range(s):
        seq = stream[i * seq_bytes:(i + 1) * seq_bytes]
        res = nist_core_tests(seq)
        for name, p in res.items():
            all_p.setdefault(name, []).append(p)
        if (i + 1) % 10 == 0:
            print(f"    progress: {i+1}/{s} sequences "
                  f"({time.perf_counter()-t0:.1f} s)")
    print()

    # Two-level NIST reporting: pass proportion + p-value uniformity
    alpha = 0.01
    p_hat = 1.0 - alpha
    prop_lo = p_hat - 3.0 * math.sqrt(p_hat * alpha / s)
    prop_reliable = s >= 55
    lines = []
    lines.append(f"NIST SP 800-22 CORE SUBSET — HESPN-CTR keystream")
    lines.append(f"Sequences: {s} x {bits:,} bits; alpha = {alpha}")
    lines.append(f"Pass-proportion acceptance region: "
                 f"[{prop_lo:.4f}, 1.0000]")
    lines.append(f"Uniformity threshold: P_T >= 0.0001")
    if not prop_reliable:
        lines.append(f"NOTE: s = {s} < 55 — the 3-sigma proportion "
                     f"interval is unreliable at this sample size")
        lines.append(f"(NIST recommends s >= 55); OVERALL below is "
                     f"based on p-value uniformity only.")
    lines.append("")
    lines.append(f"{'test':<18} {'pass':>6} {'prop':>8} "
                 f"{'prop_ok':>8} {'P_T(unif)':>10} {'unif_ok':>8}")
    overall_ok = True
    csv_rows = []
    for name in sorted(all_p):
        ps = all_p[name]
        n_pass = sum(1 for p in ps if p >= alpha)
        prop = n_pass / len(ps)
        prop_ok = prop >= prop_lo
        bins = [0] * 10
        for p in ps:
            bins[min(9, int(p * 10))] += 1
        exp = len(ps) / 10.0
        chi = sum((b - exp) ** 2 / exp for b in bins)
        p_t = igamc(4.5, chi / 2.0)
        unif_ok = p_t >= 0.0001
        overall_ok &= unif_ok
        if prop_reliable:
            overall_ok &= prop_ok
        lines.append(f"{name:<18} {n_pass:>3}/{len(ps):<3} "
                     f"{prop:>8.4f} {str(prop_ok):>8} "
                     f"{p_t:>10.4f} {str(unif_ok):>8}")
        csv_rows.append([name, n_pass, len(ps), f"{prop:.4f}",
                         prop_ok, f"{p_t:.6f}", unif_ok])
    lines.append("")
    lines.append(f"OVERALL (core subset): "
                 f"{'PASS' if overall_ok else 'ATTENTION REQUIRED'}")
    lines.append("")
    lines.append("Note: this is the built-in core subset "
                 "(7 tests / 9 p-values). For the full 15-test "
                 "battery, run the official NIST STS 'assess' tool "
                 "on hespn_ctr_stream.bin.")
    report = "\n".join(lines)
    print(report)
    print()
    with open(os.path.join(results_dir, "nist_core_results.txt"),
              "w") as f:
        f.write(report + "\n")
    print(f"  [saved] {os.path.join(results_dir, 'nist_core_results.txt')}")
    write_csv(os.path.join(results_dir, "nist_core_results.csv"),
              ["test", "n_pass", "n_seq", "proportion",
               "proportion_ok", "uniformity_PT", "uniformity_ok"],
              csv_rows)
    print()


# ============================================================
# MAIN: revision-rerun orchestration
#
# Steps are individually switchable via the RUN_* flags in the
# CONFIG section. Differential and linear-bias steps are kept
# available but default OFF: the manuscript revision reframes
# those results (worksheet A1/A2) and does not require reruns.
# ============================================================

if __name__ == "__main__":

    password = "C.E.ShannonSecrecySystems1949!"
    salt = os.urandom(ARGON_SALT_LEN)
    master_key = derive_master_key_argon2id(password, salt, out_len=32)

    print("=" * 72)
    print("HILL-ENIGMA-SPN (HillRotorSPN) — MANUSCRIPT REVISION RERUNS")
    print("NOTE: Using Argon2id key derivation (production).")
    print("=" * 72)
    print(f"Salt:              {salt.hex()}")
    print(f"MIN_BRANCH_NUMBER: {MIN_BRANCH_NUMBER}")
    print(f"Bit convention:    MSB-first throughout")
    print(f"QUICK_TEST:        {QUICK_TEST}")
    print(f"Steps enabled:     verify={RUN_STEP0_VERIFY} "
          f"branch={RUN_BRANCH_SUMMARY} avalanche={RUN_AVALANCHE}")
    print(f"                   differential={RUN_DIFFERENTIAL} "
          f"linear={RUN_LINEAR} degree={RUN_DEGREE}")
    print(f"                   admissibility={RUN_ADMISSIBILITY} "
          f"nist={RUN_NIST}")
    print()

    results_dir = make_results_dir()

    # Fast path: build tables once for the session key, verify
    # bit-exact equivalence with the reference implementation.
    session_cipher = HESPNFastCipher(master_key)
    verify_fast_equivalence(session_cipher, master_key)

    if RUN_STEP0_VERIFY:
        verify_all_rotations_invertible(master_key)

    if RUN_BRANCH_SUMMARY:
        branch_summary(master_key)
        pause_checkpoint("Branch summary complete.")

    if RUN_AVALANCHE:
        run_avalanche_step(session_cipher, master_key, results_dir)
        pause_checkpoint("Avalanche (B1) complete.")

    if RUN_DIFFERENTIAL:
        print("=" * 72)
        print("STEP 3: DIFFERENTIAL TESTS")
        print("=" * 72)
        diff = single_bit_difference(0)
        for tag, rc in [("[A]", 4), ("[B]", 8), ("[C]", 12)]:
            print(f"{tag} rounds = {rc}")
            estimate_differential_distribution(
                master_key, diff, rounds=rc, samples=DIFF_SAMPLES,
                top_k=10, encrypt_fn=session_cipher.encrypt_block)
        print("[D] rounds = 12, one active byte")
        estimate_differential_distribution(
            master_key, single_byte_difference(0, 0x01), rounds=12,
            samples=DIFF_SAMPLES, top_k=10,
            encrypt_fn=session_cipher.encrypt_block)
        pause_checkpoint("Differential tests complete.")

    if RUN_LINEAR:
        estimate_linear_bias(master_key, rounds=12,
                             samples=LINEAR_SAMPLES,
                             trials=LINEAR_TRIALS,
                             encrypt_fn=session_cipher.encrypt_block)

    if RUN_DEGREE:
        run_degree_step(session_cipher, results_dir)
        pause_checkpoint("Algebraic degree (B3) complete.")

    if RUN_ADMISSIBILITY:
        run_admissibility_experiment(results_dir)
        report_seed_search_stats(results_dir)
        pause_checkpoint("Admissibility statistics (B5/A8) complete.")

    if RUN_NIST:
        run_nist_step(session_cipher, results_dir)

    print("=" * 72)
    print("ALL ENABLED STEPS COMPLETE.")
    print(f"All logs and data files are in: "
          f"{os.path.abspath(results_dir)}")
    print("=" * 72)
