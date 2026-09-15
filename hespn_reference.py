"""Reference implementation for the HESPN construction manuscript.

HESPN is the Hill Enigma Substitution-Permutation Network. The word
"Enigma" refers only to the public stepping inspiration used to select
successive geometric orientations of each Hill-derived matrix. HESPN has
no reflector, no Enigma rotor wiring, and no self-inverse signal path.

The construction accepts a 256-bit master key K. The SHA-256 password
stub in ``main`` exists only to make the published test vector reproducible.
"""

from __future__ import annotations
import hashlib

NUM_BYTES = 16
ROUNDS = 16
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]
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
0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16]
INV_SBOX = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    INV_SBOX[_v] = _i

def rotl128(block: bytes, k: int) -> bytes:
    x = int.from_bytes(block, "big"); k %= 128
    return (((x << k) | (x >> (128-k))) & ((1 << 128)-1)).to_bytes(16, "big")

def rotr128(block: bytes, k: int) -> bytes:
    x = int.from_bytes(block, "big"); k %= 128
    return (((x >> k) | (x << (128-k))) & ((1 << 128)-1)).to_bytes(16, "big")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def derive_master_key_stub(password: str, salt: bytes) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + salt).digest()

def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    return hashlib.sha256(master_key + b"ROUNDKEY" + round_index.to_bytes(2, "big")).digest()[:16]

def byte_to_vec(x: int):
    return [(x >> (7-i)) & 1 for i in range(8)]

def vec_to_byte(v) -> int:
    out = 0
    for bit in v: out = (out << 1) | (bit & 1)
    return out

def gf2_mat_rank_8(rows) -> int:
    a = list(rows); rank = 0
    for col in range(8):
        bit = 1 << (7-col)
        pivot = next((r for r in range(rank, 8) if a[r] & bit), None)
        if pivot is None: continue
        a[rank], a[pivot] = a[pivot], a[rank]
        for r in range(8):
            if r != rank and (a[r] & bit): a[r] ^= a[rank]
        rank += 1
    return rank

def is_invertible_8(rows) -> bool:
    return gf2_mat_rank_8(rows) == 8

def apply_matrix_8_fast(rows, x: int) -> int:
    out = 0
    for row in rows: out = (out << 1) | ((row & x).bit_count() & 1)
    return out

def apply_matrix_8(rows, x: int) -> int:
    return apply_matrix_8_fast(rows, x)

def hamming_weight8(x: int) -> int:
    return x.bit_count()

def branch_number_at_least(rows, threshold: int) -> bool:
    for x in range(1, 256):
        wx = x.bit_count()
        if wx >= threshold: continue
        if wx + apply_matrix_8_fast(rows, x).bit_count() < threshold: return False
    return True

def branch_number_of_matrix(rows) -> int:
    return min(x.bit_count() + apply_matrix_8_fast(rows, x).bit_count() for x in range(1,256))

def rows_to_grid(rows): return [byte_to_vec(r) for r in rows]
def grid_to_rows(grid): return [vec_to_byte(row) for row in grid]

def rotate_matrix_entries_clockwise_90(rows):
    """R(M)_ij = M_(7-j,i), equivalently R(M) = M^T J.

    Transpose and J are invertible, so every rotation of an invertible seed
    is invertible. Defensive assertions below still catch implementation errors.
    """
    g = rows_to_grid(rows)
    return grid_to_rows([[g[7-j][i] for j in range(8)] for i in range(8)])

def rotate_matrix_entries_k(rows, k: int):
    out = list(rows)
    for _ in range(k % 4): out = rotate_matrix_entries_clockwise_90(out)
    return out

SEED_SEARCH_STATS = {}

def derive_invertible_seed_matrix_filtered(master_key: bytes, byte_index: int, min_branch: int = 4):
    """Rejection-sample an invertible seed whose M and M^T meet the B floor."""
    counter = 0
    while True:
        digest = hashlib.sha256(master_key + b"MATRIX" + byte_index.to_bytes(1,"big") + counter.to_bytes(4,"big")).digest()
        seed = list(digest[:8])
        if not is_invertible_8(seed): counter += 1; continue
        r1 = rotate_matrix_entries_clockwise_90(seed)
        if not branch_number_at_least(seed, min_branch): counter += 1; continue
        if not branch_number_at_least(r1, min_branch): counter += 1; continue
        family = [rotate_matrix_entries_k(seed,k) for k in range(4)]
        assert all(is_invertible_8(m) for m in family)
        assert all(branch_number_at_least(m,min_branch) for m in family)
        SEED_SEARCH_STATS[byte_index] = counter + 1
        return seed

def get_seed_matrices(master_key: bytes, min_branch: int = 4):
    return [derive_invertible_seed_matrix_filtered(master_key,j,min_branch) for j in range(NUM_BYTES)]

def build_rotor_matrices_for_round(master_key: bytes, round_index: int, min_branch: int = 4, seeds=None):
    if seeds is None: seeds = get_seed_matrices(master_key,min_branch)
    return [rotate_matrix_entries_k(seeds[j], (round_index+j)%4) for j in range(NUM_BYTES)]

def permute_index_bits(j: int, a: int, b: int) -> int:
    bits = [(j >> t) & 1 for t in range(4)]; bits[a], bits[b] = bits[b], bits[a]
    return sum(bits[t] << t for t in range(4))

def routing_pi(round_index: int, j: int) -> int:
    mode = round_index % 4
    if mode == 0: return j
    if mode == 1: return permute_index_bits(j,0,1)
    if mode == 2: return permute_index_bits(j,0,2)
    return permute_index_bits(j,0,3)

def round_function(block: bytes, master_key: bytes, round_index: int, seeds=None) -> bytes:
    state = rotl128(block,K_VALUES[round_index])
    state = xor_bytes(state,derive_round_key(master_key,round_index))
    mats = build_rotor_matrices_for_round(master_key,round_index,seeds=seeds)
    mixed = bytes(apply_matrix_8(mats[j],state[j]) for j in range(NUM_BYTES))
    subbed = bytes(AES_SBOX[x] for x in mixed)
    routed = bytearray(NUM_BYTES)
    for j in range(NUM_BYTES): routed[routing_pi(round_index,j)] = subbed[j]
    return bytes(routed)

def encrypt_block(block: bytes, master_key: bytes, rounds: int = ROUNDS) -> bytes:
    seeds = get_seed_matrices(master_key); state = block
    for r in range(rounds): state = round_function(state,master_key,r,seeds=seeds)
    return state

def gf2_mat_inverse_8(rows):
    a = list(rows); ident = [1 << (7-i) for i in range(8)]
    for col in range(8):
        bit = 1 << (7-col); pivot = next(r for r in range(col,8) if a[r] & bit)
        a[col],a[pivot] = a[pivot],a[col]; ident[col],ident[pivot] = ident[pivot],ident[col]
        for r in range(8):
            if r != col and (a[r] & bit): a[r] ^= a[col]; ident[r] ^= ident[col]
    return ident

def decrypt_block(ct: bytes, master_key: bytes, rounds: int = ROUNDS) -> bytes:
    seeds = get_seed_matrices(master_key); state = ct
    for r in reversed(range(rounds)):
        mats = build_rotor_matrices_for_round(master_key,r,seeds=seeds)
        unrouted = bytes(state[routing_pi(r,j)] for j in range(NUM_BYTES))
        unsubbed = bytes(INV_SBOX[x] for x in unrouted)
        inv_mats = [gf2_mat_inverse_8(m) for m in mats]
        unmixed = bytes(apply_matrix_8(inv_mats[j],unsubbed[j]) for j in range(NUM_BYTES))
        state = rotr128(xor_bytes(unmixed,derive_round_key(master_key,r)),K_VALUES[r])
    return state

def reference_vector():
    password = "HillEnigmaSPN2026!"; salt = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    pt = bytes.fromhex("00112233445566778899AABBCCDDEEFF"); key = derive_master_key_stub(password,salt)
    seeds = get_seed_matrices(key); rk0 = derive_round_key(key,0)
    s1 = rotl128(pt,K_VALUES[0]); s2 = xor_bytes(s1,rk0)
    mats0 = build_rotor_matrices_for_round(key,0,seeds=seeds)
    s3 = bytes(apply_matrix_8(mats0[j],s2[j]) for j in range(NUM_BYTES)); s4 = bytes(AES_SBOX[x] for x in s3)
    s5 = bytearray(NUM_BYTES)
    for j in range(NUM_BYTES): s5[routing_pi(0,j)] = s4[j]
    state = pt; round_states = []
    for r in range(ROUNDS): state = round_function(state,key,r,seeds=seeds); round_states.append(state)
    return {"password":password,"salt":salt,"master_key":key,"plaintext":pt,"seeds":seeds,
            "round_keys":[derive_round_key(key,r) for r in range(ROUNDS)],"round0":[s1,s2,s3,s4,bytes(s5)],
            "round_states":round_states,"ciphertext":state}

def main():
    v = reference_vector()
    print("="*68); print("HESPN REFERENCE TEST VECTOR (16 rounds, SHA-256 test stub)"); print("="*68)
    print(f"Password   : {v['password']}"); print(f"Salt       : {v['salt'].hex().upper()}")
    print(f"Master key : {v['master_key'].hex().upper()}"); print(f"Plaintext  : {v['plaintext'].hex().upper()}")
    print("\nRound keys:")
    for r,rk in enumerate(v["round_keys"]): print(f"  rk[{r:02d}] = {rk.hex().upper()}")
    print("\nSeed matrices and branch-number families:")
    for j,seed in enumerate(v["seeds"]):
        family = [rotate_matrix_entries_k(seed,k) for k in range(4)]; bns = [branch_number_of_matrix(m) for m in family]
        print(f"  S[{j:02d}] = {' '.join(f'{x:02X}' for x in seed)}  B={bns}")
    labels = ["rotl7","XOR rk0","matrix","S-box","routing"]; print("\nRound 0 intermediates:")
    for label,state in zip(labels,v["round0"]): print(f"  {label:8s}: {state.hex().upper()}")
    print("\nRound outputs:")
    for r,state in enumerate(v["round_states"],start=1): print(f"  r={r:02d}: {state.hex().upper()}")
    ct = v["ciphertext"]; print(f"\nCiphertext : {ct.hex().upper()}")
    print(f"Round trip : {'PASS' if decrypt_block(ct,v['master_key']) == v['plaintext'] else 'FAIL'}")

if __name__ == "__main__": main()
