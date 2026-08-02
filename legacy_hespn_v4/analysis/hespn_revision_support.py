#!/usr/bin/env python3
"""
HESPN Revision Support Code
============================
Generates:
1. Additional test vectors (all-zero, all-0xFF)
2. Round 8 intermediate state for implementer verification
3. MILP model skeleton for 2-round active-S-box bound
4. Statistical verification utilities
5. Branch number verification for admissible seeds
6. DIAGNOSTIC: Comparison against Appendix A Table A1

K_VALUES Note:
--------------
The manuscript Section 4.1 specifies the full 16-element array:
K_VALUES = [7,3,1,5,3,1,5,7,1,3,5,7,7,3,1,5]
Each of {1,3,5,7} appears exactly four times across 16 rounds.
"""

import hashlib
import struct
import math
from typing import List, Tuple, Optional, Dict

# ============================================================
# CONSTANTS
# ============================================================

# AES S-box (FIPS 197)
AES_SBOX = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
])

INV_AES_SBOX = bytearray(256)
for i, v in enumerate(AES_SBOX):
    INV_AES_SBOX[v] = i
INV_AES_SBOX = bytes(INV_AES_SBOX)

# Full 16-element K_VALUES as specified in corrected Section 4.1
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]


# ============================================================
# CORE UTILITIES
# ============================================================

def rotl128(block: int, k: int) -> int:
    """Rotate 128-bit block left by k positions."""
    k = k % 128
    return ((block << k) | (block >> (128 - k))) & ((1 << 128) - 1)

def rotr128(block: int, k: int) -> int:
    """Rotate 128-bit block right by k positions."""
    k = k % 128
    return ((block >> k) | (block << (128 - k))) & ((1 << 128) - 1)

def bytes_to_block(b: bytes) -> int:
    """Convert 16 bytes to 128-bit integer (big-endian)."""
    return int.from_bytes(b, 'big')

def block_to_bytes(block: int) -> bytes:
    """Convert 128-bit integer to 16 bytes (big-endian)."""
    return block.to_bytes(16, 'big')

def block_to_hex(block: int) -> str:
    """Format 128-bit block as uppercase hex string."""
    return block_to_bytes(block).hex().upper()

def block_to_byte_list(block: int) -> List[int]:
    """Convert 128-bit block to list of 16 bytes."""
    return list(block.to_bytes(16, 'big'))

def byte_list_to_block(byte_list: List[int]) -> int:
    """Convert list of 16 bytes to 128-bit block."""
    return int.from_bytes(bytes(byte_list), 'big')

def apply_matrix(byte: int, matrix: List[int]) -> int:
    """Apply 8x8 GF(2) matrix to byte. MSB-first per Section 3.1."""
    result = 0
    for i in range(8):
        parity = bin(matrix[i] & byte).count('1') & 1
        result |= (parity << (7 - i))
    return result

def routing_perm(byte_list: List[int], mode: int) -> List[int]:
    """Apply routing permutation. mode in {0,1,2,3}. Self-inverse per Section 4.3."""
    result = [0] * 16
    for j in range(16):
        if mode == 0:
            new_j = j
        elif mode == 1:
            new_j = (j & 0b1100) | ((j & 0b0010) >> 1) | ((j & 0b0001) << 1)
        elif mode == 2:
            new_j = (j & 0b1010) | ((j & 0b0001) << 2) | ((j & 0b0100) >> 2)
        elif mode == 3:
            new_j = (j & 0b0110) | ((j & 0b0001) << 3) | ((j & 0b1000) >> 3)
        result[new_j] = byte_list[j]
    return result

def gf2_matrix_inv(matrix: List[int]) -> List[int]:
    """Compute inverse of 8x8 GF(2) matrix via Gaussian elimination (MSB-first)."""
    aug = []
    for i in range(8):
        row = [(matrix[i] >> (7 - j)) & 1 for j in range(8)]
        identity = [1 if j == i else 0 for j in range(8)]
        aug.append(row + identity)

    for col in range(8):
        pivot = None
        for row in range(col, 8):
            if aug[row][col] == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is singular")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for row in range(8):
            if row != col and aug[row][col] == 1:
                for k in range(16):
                    aug[row][k] ^= aug[col][k]

    inv = []
    for i in range(8):
        inv_byte = 0
        for j in range(8):
            inv_byte |= (aug[i][8 + j] << (7 - j))
        inv.append(inv_byte)
    return inv

def rotate_matrix_90(matrix: List[int]) -> List[int]:
    """Rotate matrix 90 degrees clockwise: R(M) = M^T * J (Section 3.4)."""
    result = [0] * 8
    for i in range(8):
        for j in range(8):
            bit = (matrix[7 - j] >> (7 - i)) & 1
            result[i] |= (bit << (7 - j))
    return result

def compute_branch_number(matrix: List[int]) -> int:
    """Compute branch number B(M) = min_{x!=0} (wt(x) + wt(Mx))."""
    min_bn = 16
    for x in range(1, 256):
        wt_x = bin(x).count('1')
        y = apply_matrix(x, matrix)
        wt_y = bin(y).count('1')
        bn = wt_x + wt_y
        if bn < min_bn:
            min_bn = bn
    return min_bn

def is_admissible_seed(seed: List[int]) -> bool:
    """Check if seed is admissible: all 4 orientations invertible with B >= 4."""
    m = seed[:]
    for _ in range(4):
        try:
            gf2_matrix_inv(m)
            bn = compute_branch_number(m)
            if bn < 4:
                return False
        except ValueError:
            return False
        m = rotate_matrix_90(m)
    return True


# ============================================================
# KEY DERIVATION AND SCHEDULE
# ============================================================

def sha256_stub_key_derivation(password: str, salt_hex: str) -> bytes:
    """SHA-256 stub for reproducible test vectors (Appendix A)."""
    salt = bytes.fromhex(salt_hex.replace(' ', ''))
    h = hashlib.sha256()
    h.update(password.encode('utf-8'))
    h.update(salt)
    return h.digest()

def derive_round_key(master_key: bytes, round_idx: int) -> bytes:
    """Derive round key: SHA256(K || 'ROUNDKEY' || r)[:16] (Section 4.6)."""
    h = hashlib.sha256()
    h.update(master_key)
    h.update(b'ROUNDKEY')
    h.update(struct.pack('>H', round_idx))
    return h.digest()[:16]

def derive_seed_matrix(master_key: bytes, seed_idx: int, counter: int = 0) -> List[int]:
    """Derive candidate seed matrix from master key (Section 4.6)."""
    h = hashlib.sha256()
    h.update(master_key)
    h.update(b'MATRIX')
    h.update(bytes([seed_idx]))
    h.update(struct.pack('>I', counter))
    return list(h.digest()[:8])

def generate_admissible_seeds(master_key: bytes, max_attempts: int = 10000) -> Tuple[List[List[int]], List[int]]:
    """Generate 16 admissible seed matrices with rejection counts."""
    seeds = []
    rejection_counts = []
    for seed_idx in range(16):
        found = False
        for counter in range(max_attempts):
            candidate = derive_seed_matrix(master_key, seed_idx, counter)
            if is_admissible_seed(candidate):
                seeds.append(candidate)
                rejection_counts.append(counter)
                found = True
                break
        if not found:
            raise RuntimeError(f"No admissible seed for index {seed_idx}")
    return seeds, rejection_counts

def get_rotor_matrix(seed: List[int], orientation: int) -> List[int]:
    """Get matrix at given orientation (0-3)."""
    m = seed[:]
    for _ in range(orientation % 4):
        m = rotate_matrix_90(m)
    return m


# ============================================================
# ENCRYPTION / DECRYPTION
# ============================================================

def hespn_encrypt_block(plaintext: int, master_key: bytes, seeds: List[List[int]],
                        track_intermediates: bool = False) -> Tuple[int, Optional[List[Dict]]]:
    """Encrypt a single 128-bit block. Returns (ciphertext, intermediates) if track_intermediates=True."""
    state = plaintext
    intermediates = [] if track_intermediates else None

    for r in range(16):
        k = K_VALUES[r]  # Full 16-element array, indexed by round
        mode = r % 4

        state = rotl128(state, k)
        if track_intermediates:
            intermediates.append({'round': r, 'step': 1, 'after_rotl': block_to_hex(state)})

        rk = bytes_to_block(derive_round_key(master_key, r))
        state ^= rk
        if track_intermediates:
            intermediates[-1]['after_key'] = block_to_hex(state)

        byte_list = block_to_byte_list(state)
        new_bytes = []
        for j in range(16):
            orientation = (r + j) % 4
            M = get_rotor_matrix(seeds[j], orientation)
            new_bytes.append(apply_matrix(byte_list[j], M))
        state = byte_list_to_block(new_bytes)
        if track_intermediates:
            intermediates[-1]['after_matrix'] = block_to_hex(state)

        byte_list = block_to_byte_list(state)
        sboxed = [AES_SBOX[b] for b in byte_list]
        state = byte_list_to_block(sboxed)
        if track_intermediates:
            intermediates[-1]['after_sbox'] = block_to_hex(state)

        byte_list = block_to_byte_list(state)
        routed = routing_perm(byte_list, mode)
        state = byte_list_to_block(routed)
        if track_intermediates:
            intermediates[-1]['after_routing'] = block_to_hex(state)

    return state, intermediates

def hespn_decrypt_block(ciphertext: int, master_key: bytes, seeds: List[List[int]]) -> int:
    """Decrypt a single 128-bit block."""
    state = ciphertext

    for r in range(15, -1, -1):
        k = K_VALUES[r]
        mode = r % 4

        byte_list = block_to_byte_list(state)
        routed = routing_perm(byte_list, mode)
        state = byte_list_to_block(routed)

        byte_list = block_to_byte_list(state)
        inv_sboxed = [INV_AES_SBOX[b] for b in byte_list]
        state = byte_list_to_block(inv_sboxed)

        byte_list = block_to_byte_list(state)
        new_bytes = []
        for j in range(16):
            orientation = (r + j) % 4
            M = get_rotor_matrix(seeds[j], orientation)
            M_inv = gf2_matrix_inv(M)
            new_bytes.append(apply_matrix(byte_list[j], M_inv))
        state = byte_list_to_block(new_bytes)

        rk = bytes_to_block(derive_round_key(master_key, r))
        state ^= rk

        state = rotr128(state, k)

    return state


# ============================================================
# MILP MODEL SKELETON
# ============================================================

def generate_milp_skeleton():
    """Generate MILP model skeleton for 2-round active-S-box bound."""
    milp_code = """
\"\"\"
HESPN 2-Round Active-S-Box MILP Model
======================================
Variables, constraints, and objective for bounding active S-boxes.
Based on: Boura & Coggia [39], ToSC 2020.
\"\"\"

from pulp import LpProblem, LpVariable, LpMinimize, lpSum, LpBinary, LpStatus

def build_hespn_2round_milp():
    prob = LpProblem("HESPN_2Round_ActiveSBox", LpMinimize)
    x = {}; y = {}; z = {}; s = {}
    for r in range(2):
        for j in range(16):
            x[r,j] = LpVariable(f"x_{r}_{j}", cat=LpBinary)
            y[r,j] = LpVariable(f"y_{r}_{j}", cat=LpBinary)
            z[r,j] = LpVariable(f"z_{r}_{j}", cat=LpBinary)
            s[r,j] = LpVariable(f"s_{r}_{j}", cat=LpBinary)

    prob += lpSum(s[r,j] for r in range(2) for j in range(16))

    prob += x[0,0] == 1
    for j in range(1, 16):
        prob += x[0,j] == 0

    for r in range(2):
        for j in range(16):
            prob += y[r,j] >= x[r,j]

    for r in range(2):
        for j in range(16):
            prob += z[r,j] == y[r,j]
            prob += s[r,j] == y[r,j]

    routing = {0: lambda j: j, 1: lambda j: (j & 0b1100) | ((j & 0b0010) >> 1) | ((j & 0b0001) << 1)}
    for r in range(1):
        for j in range(16):
            src = routing[r](j)
            prob += x[r+1, j] >= z[r, src]

    prob += lpSum(x[1,j] for j in range(16)) >= 2 * z[0,0]

    return prob

# prob = build_hespn_2round_milp()
# prob.solve()
# print(f"Status: {LpStatus[prob.status]}")
# print(f"Minimum active S-boxes: {prob.objective.value()}")
"""
    return milp_code


# ============================================================
# STATISTICAL UTILITIES
# ============================================================

def proportion_test(n_trials: int, n_successes: int, p_null: float = 0.99, alpha: float = 0.01) -> Dict:
    """Two-level proportion test per NIST SP 800-22 Section 4.2."""
    prop = n_successes / n_trials
    lower = p_null - 3 * math.sqrt(p_null * (1 - p_null) / n_trials)
    upper = p_null + 3 * math.sqrt(p_null * (1 - p_null) / n_trials)
    z = (prop - p_null) / math.sqrt(p_null * (1 - p_null) / n_trials)
    return {'proportion': prop, 'lower_bound': lower, 'upper_bound': upper,
            'pass': lower <= prop <= upper, 'z_score': z}

def nist_sts_proportion_summary(n_sequences: int, n_failures: int, n_tests_per_seq: int = 9, alpha: float = 0.01):
    """Summarize NIST SP 800-22 proportion results."""
    total_tests = n_sequences * n_tests_per_seq
    expected_failures = total_tests * alpha
    z = (n_failures - expected_failures) / math.sqrt(expected_failures * (1 - alpha))
    p_value = 0.5 * (1 + math.erf(-abs(z) / math.sqrt(2)))
    print(f"NIST SP 800-22 Proportion Summary")
    print(f"  Sequences: {n_sequences}, Tests per sequence: {n_tests_per_seq}")
    print(f"  Total tests: {total_tests}")
    print(f"  Observed failures: {n_failures}")
    print(f"  Expected failures (alpha={alpha}): {expected_failures:.1f}")
    print(f"  Z-score: {z:.3f}")
    print(f"  Two-sided p-value: {p_value:.4f}")
    print(f"  Interpretation: {'Consistent with randomness' if abs(z) < 2 else 'Potential concern'}")


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("HESPN MANUSCRIPT REVISION SUPPORT OUTPUT")
    print("=" * 70)

    password = "HillEnigmaSPN2026!"
    salt_hex = "0102030405060708090A0B0C0D0E0F10"
    master_key = sha256_stub_key_derivation(password, salt_hex)
    seeds, rejection_counts = generate_admissible_seeds(master_key)

    all_bn = []
    for r in range(16):
        for j in range(16):
            orientation = (r + j) % 4
            M = get_rotor_matrix(seeds[j], orientation)
            bn = compute_branch_number(M)
            all_bn.append(bn)
            assert bn >= 4

    # ============================================================
    # 1. TEST VECTORS
    # ============================================================
    print("\n" + "=" * 70)
    print("TABLE A1: REFERENCE TEST VECTORS (SHA-256 Stub)")
    print("=" * 70)
    print(f"Password: {password}")
    print(f"Salt (hex): {salt_hex}")
    print(f"Master Key: {master_key.hex().upper()}")
    print()

    test_vectors = [
        ("All-Zero", "00000000000000000000000000000000"),
        ("All-0xFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        ("Original", "00112233445566778899AABBCCDDEEFF"),
    ]

    for name, pt_hex in test_vectors:
        plaintext = bytes_to_block(bytes.fromhex(pt_hex))
        ciphertext, _ = hespn_encrypt_block(plaintext, master_key, seeds)
        decrypted = hespn_decrypt_block(ciphertext, master_key, seeds)
        print(f"{name}:")
        print(f"  Plaintext:  {pt_hex}")
        print(f"  Ciphertext: {block_to_hex(ciphertext)}")
        print(f"  Decryption: {'PASS ✓' if decrypted == plaintext else 'FAIL ✗'}")
        print()

    # ============================================================
    # 2. DIAGNOSTIC: Compare against Appendix A Table A1
    # ============================================================
    print("=" * 70)
    print("DIAGNOSTIC: Comparison against Appendix A Table A1")
    print("=" * 70)

    rk0_expected = "740535C4CD34EA8908367F224C331C10"
    rk0_actual = derive_round_key(master_key, 0).hex().upper()
    print(f"\n(1) Round Key 0 Comparison:")
    print(f"    Expected (Table A1): {rk0_expected}")
    print(f"    Actual:               {rk0_actual}")
    print(f"    Match: {'✓ KEY EXPANSION OK' if rk0_actual == rk0_expected else '✗ KEY EXPANSION DIFFERS'}")

    print(f"\n(2) Round 0 Step-by-Step Comparison (plaintext = 00112233445566778899AABBCCDDEEFF):")

    orig_plaintext = bytes_to_block(bytes.fromhex("00112233445566778899AABBCCDDEEFF"))
    _, r0_inter = hespn_encrypt_block(orig_plaintext, master_key, seeds, track_intermediates=True)
    r0 = r0_inter[0]

    expected = {
        'after_rotl':    "089119A22AB33BC44CD55DE66EF77F80",
        'after_key':     "7C942C66E787D14D44E322C422C46390",
        'after_matrix':  "DF9B475324DF191C9CAA528855C80E75",
        'after_sbox':    "9E14A0ED369ED49CDEAC00C4FCE8AB9D",
        'after_routing': "9E14A0ED369ED49CDEAC00C4FCE8AB9D",
    }

    step_names = {
        'after_rotl':    'Step 1 rotl128(b, 7)',
        'after_key':     'Step 2 XOR rk[0]',
        'after_matrix':  'Step 3 GF(2) mat-vec × 16',
        'after_sbox':    'Step 4 AES S-box × 16',
        'after_routing': 'Step 5 Routing (mode 0)',
    }

    all_match = True
    for key in ['after_rotl', 'after_key', 'after_matrix', 'after_sbox', 'after_routing']:
        actual = r0[key]
        exp = expected[key]
        match = (actual == exp)
        if not match:
            all_match = False
        status = "✓ MATCH" if match else "✗ DIFFER"
        print(f"\n    {step_names[key]}:")
        print(f"      Expected: {exp}")
        print(f"      Actual:   {actual}")
        print(f"      Status:   {status}")

    print(f"\n    OVERALL: {'ALL STEPS MATCH ✓' if all_match else 'SOME STEPS DIFFER ✗'}")

    ct_expected = "3FD6391275C252DD4E3BC4CFE7F82C96"
    ct_actual = block_to_hex(ciphertext)
    print(f"\n(3) Full 16-round ciphertext:")
    print(f"    Expected: {ct_expected}")
    print(f"    Actual:   {ct_actual}")
    print(f"    Match: {'✓' if ct_actual == ct_expected else '✗'}")

    # ============================================================
    # 3. ROUND 8 INTERMEDIATE STATE
    # ============================================================
    print("\n" + "=" * 70)
    print("ROUND 8 INTERMEDIATE STATE (All-Zero Plaintext)")
    print("=" * 70)

    zero_plaintext = bytes_to_block(bytes.fromhex("00000000000000000000000000000000"))
    _, intermediates = hespn_encrypt_block(zero_plaintext, master_key, seeds, track_intermediates=True)

    r8 = intermediates[8]
    print(f"Round 8 (r=8, k={K_VALUES[8]}, mode={8%4}):")
    print(f"  After Step 1 rotl128:  {r8['after_rotl']}")
    print(f"  After Step 2 XOR rk8:  {r8['after_key']}")
    print(f"  After Step 3 GF(2)×16: {r8['after_matrix']}")
    print(f"  After Step 4 AES S-box: {r8['after_sbox']}")
    print(f"  After Step 5 Routing:  {r8['after_routing']}")

    # ============================================================
    # 4. SEED MATRIX VERIFICATION
    # ============================================================
    print("\n" + "=" * 70)
    print("SEED MATRIX VERIFICATION")
    print("=" * 70)
    print(f"Rejection counts: {rejection_counts}")
    print(f"Mean rejections: {sum(rejection_counts)/len(rejection_counts):.1f}")
    print(f"Max rejections: {max(rejection_counts)}")
    print(f"All 256 matrices: B >= 4 ✓ (min={min(all_bn)}, max={max(all_bn)}, mean={sum(all_bn)/len(all_bn):.2f})")

    # ============================================================
    # 5. STATISTICAL VERIFICATION
    # ============================================================
    print("\n" + "=" * 70)
    print("NIST SP 800-22 STATISTICAL VERIFICATION")
    print("=" * 70)
    nist_sts_proportion_summary(300, 34, n_tests_per_seq=9, alpha=0.01)

    print()
    print("100-sequence runs/serial proportion test (96/100 passing):")
    result = proportion_test(100, 96, p_null=0.99, alpha=0.01)
    print(f"  Observed proportion: {result['proportion']:.3f}")
    print(f"  3-sigma bound: [{result['lower_bound']:.4f}, {result['upper_bound']:.4f}]")
    print(f"  Pass: {'Yes' if result['pass'] else 'No'} (z = {result['z_score']:.3f})")

    # ============================================================
    # 6. MILP MODEL OUTPUT
    # ============================================================
    print("\n" + "=" * 70)
    print("MILP MODEL SKELETON (saved to hespn_2round_milp.py)")
    print("=" * 70)
    milp_code = generate_milp_skeleton()
    with open("hespn_2round_milp.py", "w", encoding="utf-8") as f:
        f.write(milp_code)
    print("Saved to hespn_2round_milp.py")
    print("To use: pip install pulp; python hespn_2round_milp.py")

    print("\n" + "=" * 70)
    print("REVISION SUPPORT GENERATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
