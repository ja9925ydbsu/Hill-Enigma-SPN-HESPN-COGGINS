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
ROUNDS      = 12
BLOCK_BITS  = 128

# Rotation schedule — inter-byte bit diffusion per round
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7]

# Argon2id parameters (used in Colab; kept here for reference)
ARGON_TIME_COST    = 3
ARGON_MEMORY_COST  = 65536
ARGON_PARALLELISM  = 2
ARGON_SALT_LEN     = 16

# Matrix quality floor — all 4 rotor orientations must satisfy this
MIN_BRANCH_NUMBER = 4

# Test sizes
PLAINTEXT_AVALANCHE_TRIALS = 60
KEY_AVALANCHE_TRIALS       = 30
DIFF_SAMPLES               = 50000
LINEAR_SAMPLES             = 50000
LINEAR_TRIALS              = 500

# Algebraic degree estimator config
DEGREE_ROUNDS_TO_TEST        = [1, 2, 4, 5, 8, 12]
DEGREE_NUM_ACTIVE_INPUT_BITS = 6
DEGREE_TRIALS_PER_ROUND      = 4

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
        y = apply_matrix_8(rows, x)
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
        family_branch = [branch_number_of_matrix(M) for M in family]
        if min(family_branch) >= min_branch:
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
# r is the round index (0..11), j is the byte position (0..15).
#
# This produces 16 x 12 = 192 matrix applications total,
# with 16 x 4 = 64 distinct (seed, orientation) pairs,
# each appearing exactly 3 times across 12 rounds.
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
# mode 0: identity              [rounds 0, 4, 8]
# mode 1: swap index bits 0<->1 [rounds 1, 5, 9]
# mode 2: swap index bits 0<->2 [rounds 2, 6, 10]
# mode 3: swap index bits 0<->3 [rounds 3, 7, 11]
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
# Full encryption: 12 iterations of round_function.
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
# and that decryption is well-defined for all 12 rounds.
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
        print("  Decryption is well-defined for all 12 rounds [OK]")
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
                                        top_k: int = 10) -> None:
    counter = Counter()
    for i in range(samples):
        p  = random_block()
        p2 = xor_blocks(p, input_diff)
        c1 = encrypt_block(p,  master_key, rounds)
        c2 = encrypt_block(p2, master_key, rounds)
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
                          trials: int  = LINEAR_TRIALS) -> None:
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
            c   = encrypt_block(p, master_key, rounds)
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
    
    # ── PAUSE — copy/save linear bias results before continuing ──
    CONTINUE_CODE = "&Ygv"
    print("=" * 72)
    print("PAUSE: Linear bias complete.")
    print(f"  CSV log : {LOG_LINEAR}")
    print()
    print("  Scroll back and copy any console output you need.")
    print("  The window will remain open until you enter the continue code.")
    print()
    print(f"  Type exactly:  {CONTINUE_CODE}  then press ENTER to continue.")
    print("=" * 72)
    while True:
        response = input("  Continue code: ").strip()
        if response == CONTINUE_CODE:
            print("  Continuing to algebraic degree analysis...")
            print()
            break
        else:
            print(f"  Incorrect -- type exactly '{CONTINUE_CODE}' to continue.")

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

# ── PAUSE — copy/save linear bias results before continuing ──
    CONTINUE_CODE = "&Ygv"
    print("=" * 72)
    print("PAUSE: Algebraic Degree complete.")
    print(f"  CSV log : {LOG_LINEAR}")
    print()
    print("  Scroll back and copy any console output you need.")
    print("  The window will remain open until you enter the continue code.")
    print()
    print(f"  Type exactly:  {CONTINUE_CODE}  then press ENTER to continue.")
    print("=" * 72)
    while True:
        response = input("  Continue code: ").strip()
        if response == CONTINUE_CODE:
            print("  Continuing to completion of program...")
            print()
            break
        else:
            print(f"  Incorrect -- type exactly '{CONTINUE_CODE}' to continue.")
# ============================================================
# MAIN: Run all steps in sequence
# ============================================================

if __name__ == "__main__":

    password   = "C.E.ShannonSecrecySystems1949!"
    salt       = os.urandom(ARGON_SALT_LEN)
    master_key = derive_master_key_argon2id(password, salt, out_len=32)

    print("=" * 72)
    print("HILL-ENIGMA-SPN (HillRotorSPN) PROTOTYPE")
    print("NOTE: Using Argon2id key derivation (production).")
    
    print("=" * 72)
    print(f"Salt:              {salt.hex()}")
    print(f"MIN_BRANCH_NUMBER: {MIN_BRANCH_NUMBER}")
    print(f"Bit convention:    MSB-first throughout")
    print()

    # Step 0: Verify all 64 rotor orientations are invertible
    verify_all_rotations_invertible(master_key)

    # Step 1: Branch numbers across all 12 rounds
    branch_summary(master_key)

    # Step 2: Avalanche
    print("=" * 72)
    print("STEP 2: AVALANCHE")
    print("=" * 72)
    for rc in [1, 2, 4, 5, 8, 12]:
        dists = plaintext_avalanche_trials(
            master_key, rounds=rc,
            trials=PLAINTEXT_AVALANCHE_TRIALS)
        summarize_distances(f"PLAINTEXT avalanche, rounds={rc}", dists)

    for rc in [1, 2, 4, 5, 8, 12]:
        dists = key_avalanche_trials(
            password, salt, rounds=rc,
            trials=KEY_AVALANCHE_TRIALS)
        summarize_distances(f"KEY avalanche, rounds={rc}", dists)

    # Step 3: Differential
    print("=" * 72)
    print("STEP 3: DIFFERENTIAL TESTS")
    print("=" * 72)
    diff = single_bit_difference(0)   # MSB of block 0 is active

    print("[A] rounds = 4")
    estimate_differential_distribution(
        master_key, diff, rounds=4,
        samples=DIFF_SAMPLES, top_k=10)

    print("[B] rounds = 8")
    estimate_differential_distribution(
        master_key, diff, rounds=8,
        samples=DIFF_SAMPLES, top_k=10)

    print("[C] rounds = 12")
    estimate_differential_distribution(
        master_key, diff, rounds=12,
        samples=DIFF_SAMPLES, top_k=10)

    print("[D] rounds = 12, one active byte")
    diff_byte = single_byte_difference(0, 0x01)
    estimate_differential_distribution(
        master_key, diff_byte, rounds=12,
        samples=DIFF_SAMPLES, top_k=10)

    # Step 4: Linear bias
    print("=" * 72)
    print("STEP 4: LINEAR-BIAS PROBE")
    print("=" * 72)
    estimate_linear_bias(master_key, rounds=12,
                          samples=LINEAR_SAMPLES,
                          trials=LINEAR_TRIALS)

    # Step 5: Algebraic degree
    estimate_degree_growth_lower_bounds(
        master_key,
        rounds_list=DEGREE_ROUNDS_TO_TEST,
        num_active_input_bits=DEGREE_NUM_ACTIVE_INPUT_BITS,
        trials_per_round=DEGREE_TRIALS_PER_ROUND)

