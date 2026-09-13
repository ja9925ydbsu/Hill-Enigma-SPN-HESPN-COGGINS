# ============================================================
# hespn_test_vector_v4.py
# Hill-Enigma-SPN (HESPN) reference test-vector generator
# 16-round protocol (v4), SHA-256 stub key derivation.
# Standard library only. Prints the complete key schedule
# (16 round keys), all 16 seed matrices with branch numbers,
# round-0 step-by-step intermediate states, the 16-round
# ciphertext, and a full decryption round-trip check.
#
# CANONICAL ENCODINGS (normative for all HESPN implementations):
#   round keys : rk[r] = SHA-256(K || b"ROUNDKEY" || r)[0:16],
#                r encoded as a 2-byte big-endian integer
#   seeds      : SHA-256(K || b"MATRIX" || j || counter),
#                j 1-byte, counter 4-byte big-endian
#   stub KDF   : K = SHA-256(password_utf8 || salt)  [test only;
#                HESPN itself accepts a 256-bit master key K]
# ============================================================

import hashlib

NUM_BYTES  = 16
ROUNDS     = 16
K_VALUES   = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]
MIN_BRANCH_NUMBER = 4


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


def rotl128(block: bytes, k: int) -> bytes:
    """Rotate 128-bit block left by k bits (big-endian, MSB-first)."""
    x = int.from_bytes(block, "big")
    k %= 128
    y = ((x << k) | (x >> (128 - k))) & ((1 << 128) - 1)
    return y.to_bytes(16, "big")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    """Derive 128-bit round key r as SHA256(master_key || 'ROUNDKEY' || r)[:16]."""
    digest = hashlib.sha256(
        master_key + b"ROUNDKEY" + round_index.to_bytes(2, "big")
    ).digest()
    return digest[:16]


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
    """Return True iff the 8x8 GF(2) matrix has full rank."""
    return gf2_mat_rank_8(rows) == 8

def apply_matrix_8(rows, x: int) -> int:
    """
    Multiply input byte x by 8x8 GF(2) matrix M using the
    manuscript's MSB-first convention.
    """
    xv = byte_to_vec(x)
    out_bits = []
    for row in rows:
        rv = byte_to_vec(row)
        bit = 0
        for a, b in zip(rv, xv):
            bit ^= (a & b)
        out_bits.append(bit)
    return vec_to_byte(out_bits)

def hamming_weight8(x: int) -> int:
    return x.bit_count()

def apply_matrix_8_fast(rows, x: int) -> int:
    """Popcount-equivalent fast path for apply_matrix_8."""
    out = 0
    for row in rows:
        out = (out << 1) | ((row & x).bit_count() & 1)
    return out

def branch_number_at_least(rows, threshold: int) -> bool:
    """Early-exit predicate for B(M) >= threshold."""
    for x in range(1, 256):
        if x.bit_count() >= threshold:
            continue
        y = apply_matrix_8_fast(rows, x)
        if x.bit_count() + y.bit_count() < threshold:
            return False
    return True

def branch_number_of_matrix(rows) -> int:
    """Compute B(M) = min_{x != 0} wt(x) + wt(Mx)."""
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
# DEFINITION (manuscript Section 3.2):
#   R(M)_ij = M_{7-j, i},   0 <= i,j <= 7
#
# Algebraically, R(M) = M^T J, where J is the antidiagonal
# identity (coordinate-reversal) permutation matrix. Therefore
# invertibility is preserved automatically by rotation. The four
# orientations realize only the two independent local branch
# numbers B(M) and B(M^T). The implementation nevertheless
# rechecks all four orientations defensively as a consistency test.
# ============================================================

def rows_to_grid(rows):
    return [byte_to_vec(r) for r in rows]

def grid_to_rows(grid):
    return [vec_to_byte(row) for row in grid]

def rotate_matrix_entries_clockwise_90(rows):
    """Rotate M clockwise: R(M)_ij = M_{7-j,i}."""
    g = rows_to_grid(rows)
    n = 8
    rotated = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            rotated[i][j] = g[n - 1 - j][i]
    return grid_to_rows(rotated)

def rotate_matrix_entries_k(rows, k: int):
    out = rows[:]
    for _ in range(k % 4):
        out = rotate_matrix_entries_clockwise_90(out)
    return out


SEED_SEARCH_STATS = {}


def derive_invertible_seed_matrix_filtered(master_key: bytes,
                                            byte_index: int,
                                            min_branch: int = 4):
    """
    Derive the admissible seed for one byte position.

    Seed invertibility algebraically guarantees invertibility of
    every orientation because R(M)=M^T J. The repeated rank checks
    below are retained only as defensive representation checks.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(
            master_key + b"MATRIX" +
            byte_index.to_bytes(1, "big") +
            counter.to_bytes(4, "big")
        ).digest()
        rows = list(digest[:8])
        if not is_invertible_8(rows):
            counter += 1
            continue
        family = [rotate_matrix_entries_k(rows, k) for k in range(4)]
        if not all(is_invertible_8(M) for M in family):
            counter += 1
            continue
        if all(branch_number_at_least(M, min_branch)
               for M in family):
            SEED_SEARCH_STATS[(master_key, byte_index)] = counter + 1
            return rows
        counter += 1


seed_matrices_cache = {}

def get_seed_matrices(master_key: bytes, min_branch: int = 4):
    """Return/cache the 16 deterministic admissible seed matrices."""
    cache_key = (master_key, min_branch)
    if cache_key not in seed_matrices_cache:
        seed_matrices_cache[cache_key] = [
            derive_invertible_seed_matrix_filtered(
                master_key, j, min_branch=min_branch)
            for j in range(16)
        ]
    return seed_matrices_cache[cache_key]


def build_rotor_matrices_for_round(master_key: bytes,
                                    round_index: int,
                                    min_branch: int = 4):
    """Return M_{r,j}=R^{(r+j) mod 4}(S_j) for j=0..15."""
    seeds = get_seed_matrices(master_key, min_branch=min_branch)
    matrices = []
    for j in range(16):
        orientation = (round_index + j) % 4
        matrices.append(rotate_matrix_entries_k(seeds[j], orientation))
    return matrices


def permute_index_bits(j: int, a: int, b: int) -> int:
    bits = [(j >> t) & 1 for t in range(4)]
    bits[a], bits[b] = bits[b], bits[a]
    out = 0
    for t in range(4):
        out |= (bits[t] << t)
    return out

def routing_pi(round_index: int, j: int) -> int:
    mode = round_index % 4
    if mode == 0:
        return j
    elif mode == 1:
        return permute_index_bits(j, 0, 1)
    elif mode == 2:
        return permute_index_bits(j, 0, 2)
    else:
        return permute_index_bits(j, 0, 3)


def round_function(block: bytes, master_key: bytes,
                    round_index: int) -> bytes:
    state = rotl128(block, K_VALUES[round_index % len(K_VALUES)])
    rk = derive_round_key(master_key, round_index)
    state = xor_bytes(state, rk)
    state_bytes = list(state)
    matrices = build_rotor_matrices_for_round(
        master_key, round_index, min_branch=MIN_BRANCH_NUMBER)
    mixed = [apply_matrix_8(matrices[j], state_bytes[j])
             for j in range(16)]
    subbed = [AES_SBOX[x] for x in mixed]
    routed = [0] * 16
    for j in range(16):
        routed[routing_pi(round_index, j)] = subbed[j]
    return bytes(routed)

def encrypt_block(block: bytes, master_key: bytes,
                   rounds: int = ROUNDS) -> bytes:
    state = block
    for r in range(rounds):
        state = round_function(state, master_key, r)
    return state


def derive_master_key_stub(password: str, salt: bytes) -> bytes:
    """SHA-256 stub for reproducible test vectors only.

    HESPN itself accepts a 256-bit master key. Any application-level
    password KDF is external to the construction studied here.
    """
    return hashlib.sha256(password.encode("utf-8") + salt).digest()

def rotr128(block: bytes, k: int) -> bytes:
    x = int.from_bytes(block, "big"); k %= 128
    y = ((x >> k) | (x << (128 - k))) & ((1 << 128) - 1)
    return y.to_bytes(16, "big")

INV_SBOX = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    INV_SBOX[_v] = _i

def gf2_mat_inverse_8(rows):
    A = rows[:]; I = [1 << (7 - i) for i in range(8)]
    for col in range(8):
        bit = 1 << (7 - col)
        piv = next(r for r in range(col, 8) if A[r] & bit)
        A[col], A[piv] = A[piv], A[col]
        I[col], I[piv] = I[piv], I[col]
        for r in range(8):
            if r != col and (A[r] & bit):
                A[r] ^= A[col]; I[r] ^= I[col]
    return I

def decrypt_block(ct: bytes, master_key: bytes,
                  rounds: int = ROUNDS) -> bytes:
    state = ct
    for r in reversed(range(rounds)):
        mats = build_rotor_matrices_for_round(master_key, r)
        inv_mats = [gf2_mat_inverse_8(M) for M in mats]
        unrouted = bytes(state[routing_pi(r, j)] for j in range(16))
        s = [INV_SBOX[x] for x in unrouted]
        s = bytes(apply_matrix_8(inv_mats[j], s[j]) for j in range(16))
        s = xor_bytes(s, derive_round_key(master_key, r))
        state = rotr128(s, K_VALUES[r % len(K_VALUES)])
    return state

def main():
    password = "HillEnigmaSPN2026!"
    salt = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    pt = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    K = derive_master_key_stub(password, salt)

    print("=" * 68)
    print("HESPN v4 REFERENCE TEST VECTOR (16 rounds, SHA-256 stub KDF)")
    print("=" * 68)
    print(f"Password   : {password}")
    print(f"Salt       : {salt.hex().upper()}")
    print(f"Master key : {K.hex().upper()}")
    print()
    print("Round keys rk[r] = SHA-256(K || 'ROUNDKEY' || r_be16)[0:16]:")
    for r in range(ROUNDS):
        print(f"  rk[{r:2d}] = {derive_round_key(K, r).hex().upper()}")
    print()
    print("Seed matrices (rows as hex bytes, MSB-first) and family")
    print("branch numbers min over the 4 orientations:")
    seeds = get_seed_matrices(K, min_branch=MIN_BRANCH_NUMBER)
    for j, S in enumerate(seeds):
        fam = [rotate_matrix_entries_k(S, k) for k in range(4)]
        bns = [branch_number_of_matrix(M) for M in fam]
        print(f"  S[{j:2d}] = {' '.join(f'{b:02X}' for b in S)}   "
              f"B(family) = {bns}  min = {min(bns)}")
    print()
    print("Round 0 step-by-step (r = 0, k = 7, routing mode 0):")
    s1 = rotl128(pt, K_VALUES[0])
    rk0 = derive_round_key(K, 0)
    s2 = xor_bytes(s1, rk0)
    mats = build_rotor_matrices_for_round(K, 0)
    s3 = bytes(apply_matrix_8(mats[j], s2[j]) for j in range(16))
    s4 = bytes(AES_SBOX[x] for x in s3)
    s5 = bytearray(16)
    for j in range(16):
        s5[routing_pi(0, j)] = s4[j]
    print(f"  Plaintext          : {pt.hex().upper()}")
    print(f"  After Step 1 rotl7 : {s1.hex().upper()}")
    print(f"  After Step 2 XOR   : {s2.hex().upper()}")
    print(f"  After Step 3 mat   : {s3.hex().upper()}")
    print(f"  After Step 4 S-box : {s4.hex().upper()}")
    print(f"  After Step 5 route : {bytes(s5).hex().upper()}")
    print()
    state = pt
    for r in range(ROUNDS):
        state = round_function(state, K, r)
        print(f"  After round {r+1:2d}     : {state.hex().upper()}")
    ct = state
    print()
    print(f"Ciphertext (16 rounds): {ct.hex().upper()}")
    rt = decrypt_block(ct, K, ROUNDS)
    print(f"Decryption round-trip : "
          f"{'PASS' if rt == pt else 'FAIL'}  ({rt.hex().upper()})")

if __name__ == "__main__":
    main()
