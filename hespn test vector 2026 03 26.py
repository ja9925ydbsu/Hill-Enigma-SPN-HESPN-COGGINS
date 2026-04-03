Python 3.14.3 (tags/v3.14.3:323c59a, Feb  3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)] on win32
Enter "help" below or click "Help" above for more information.
>>> """
... HESPN Test Vector Generator
... ============================
... Generates a fully reproducible test vector for Hill-Enigma-SPN (HESPN):
...   - Fixed plaintext, password, and salt
...   - Plaintext: 00112233445566778899AABBCCDDEEFF
...   - Password: HillEnigmaSPN2026!
...   - Salt: 0102030405060708090A0B0C0D0E0F10
...   - Ciphertext: 0AB959D45F16C435752E5BC7EF6706DF
...   - Master key and all 12 round keys
...   - All 16 seed matrices with branch numbers
...   - Intermediate states after every step of Round 0
...   - Ciphertext after all 12 rounds
...   - Decryption verification (round-trip check)
...  
... Key derivation: SHA-256 stub (replaces Argon2id for reproducibility;
... the round function, rotor scheduling, S-box layer, and routing
... permutation are identical to the production Argon2id implementation).
...  
... Cipher specification: Coggins 2026 (manuscript Sections 2-3).
... """
...  
... import hashlib
... import struct
...  
... # AES S-box
... AES_SBOX = [
...     0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
...     0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
...     0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
...     0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
...     0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
AES_SBOX_INV = [0]*256
for _i, _v in enumerate(AES_SBOX):
    AES_SBOX_INV[_v] = _i
 
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7]
ROUNDS = 12
 
# GF(2) helpers
def popcount(x):
    return bin(x).count('1')
 
def gf2_mat_vec(matrix_rows, x_byte):
    """v(y)[i] = popcount(m_i AND x) mod 2, MSB-first (Section 2.1)."""
    result = 0
    for i, row in enumerate(matrix_rows):
        result |= ((popcount(row & x_byte) % 2) << (7 - i))
    return result
 
def gf2_mat_inv(matrix_rows):
    """
    GF(2) matrix inverse via Gaussian elimination.
    Column j of row i is bit (7-j) of the row byte (MSB-first).
    """
    n = 8
    M = list(matrix_rows)
    I = [1 << (n - 1 - i) for i in range(n)]   # MSB-first identity
    for col in range(n):
        col_bit = 1 << (n - 1 - col)            # bit for column col
        pivot = next((r for r in range(col, n) if M[r] & col_bit), None)
        if pivot is None:
            raise ValueError(f"Matrix singular at column {col}")
        M[col], M[pivot] = M[pivot], M[col]
        I[col], I[pivot] = I[pivot], I[col]
        for row in range(n):
            if row != col and (M[row] & col_bit):
                M[row] ^= M[col]
                I[row] ^= I[col]
    return I
 
def branch_number(matrix_rows):
    """B(M) = min_{x!=0} (wt(x) + wt(Mx))."""
    return min(
        bin(x).count('1') + bin(gf2_mat_vec(matrix_rows, x)).count('1')
        for x in range(1, 256)
    )
 
def rotate_matrix_90cw(matrix_rows):
    """R(M)_{ij} = M_{(7-j),i}  =>  R(M) = M^T J  (Section 2.4)."""
    result = []
    for i in range(8):
        row_val = 0
        for j in range(8):
            row_val |= (((matrix_rows[7-j] >> (7-i)) & 1) << (7-j))
        result.append(row_val)
    return result
 
def rotate_matrix_k(matrix_rows, k):
    m = list(matrix_rows)
    for _ in range(k % 4):
        m = rotate_matrix_90cw(m)
    return m
 
def rotl128(block_bytes, k):
    k = k % 128
    val = int.from_bytes(block_bytes, 'big')
    return (((val << k) | (val >> (128-k))) & ((1<<128)-1)).to_bytes(16, 'big')
 
def rotr128(block_bytes, k):
    return rotl128(block_bytes, 128 - (k % 128))
 
def routing_permutation(state, mode):
    """4-mode byte index permutation (Section 3.3). Each mode is self-inverse."""
    out = bytearray(16)
    for j in range(16):
        if   mode == 0: new_j = j
        elif mode == 1:
            b0,b1 = (j>>0)&1,(j>>1)&1
            new_j = (j&0b1100)|(b0<<1)|b1
        elif mode == 2:
            b0,b2 = (j>>0)&1,(j>>2)&1
            new_j = (j&0b1010)|(b0<<2)|b2
        else:
            b0,b3 = (j>>0)&1,(j>>3)&1
            new_j = (j&0b0110)|(b0<<3)|b3
        out[new_j] = state[j]
    return bytes(out)
 
# Key derivation (SHA-256 stub)
def derive_master_key(password, salt):
    data = password.encode('utf-8') + salt
    return hashlib.sha256(data).digest() + hashlib.sha256(data+b'\x01').digest()
 
def derive_round_keys(master_key):
    return [hashlib.sha256(master_key+b'ROUNDKEY'+struct.pack('<I',r)).digest()[:16]
            for r in range(ROUNDS)]
 
def is_admissible(matrix_rows):
    m = list(matrix_rows)
    for _ in range(4):
        try: gf2_mat_inv(m)
        except ValueError: return False
        if branch_number(m) < 4: return False
        m = rotate_matrix_90cw(m)
    return True
 
def derive_seed_matrix(master_key, j):
    counter = 0
    while True:
        h = hashlib.sha256(master_key+b'MATRIX'+struct.pack('<I',j)+struct.pack('<I',counter)).digest()
        rows = list(h[:8])
        if is_admissible(rows): return rows
        counter += 1
 
def key_setup(password, salt):
    mk = derive_master_key(password, salt)
    return mk, derive_round_keys(mk), [derive_seed_matrix(mk,j) for j in range(16)]
 
def round_function(state, r, round_keys, seed_matrices, verbose=False):
    k, mode = K_VALUES[r%12], r%4
    s1 = rotl128(state, k)
    if verbose: print(f"  Step 1  rotl128(b, {k}):           {s1.hex().upper()}")
    rk = round_keys[r]
    s2 = bytes(a^b for a,b in zip(s1, rk))
    if verbose:
        print(f"  Step 2  XOR rk[{r}]:                {s2.hex().upper()}")
        print(f"          rk[{r}] =                   {rk.hex().upper()}")
    s3 = bytes(gf2_mat_vec(rotate_matrix_k(seed_matrices[j],(r+j)%4), s2[j]) for j in range(16))
    if verbose: print(f"  Step 3  GF(2) mat-vec (x16):     {s3.hex().upper()}")
    s4 = bytes(AES_SBOX[b] for b in s3)
    if verbose: print(f"  Step 4  AES S-box (x16):          {s4.hex().upper()}")
    s5 = routing_permutation(s4, mode)
    if verbose: print(f"  Step 5  Routing (mode {mode}):           {s5.hex().upper()}")
    return s5
 
def encrypt(plaintext, round_keys, seed_matrices, verbose_round=None):
    state = plaintext
    for r in range(ROUNDS):
        v = (r == verbose_round)
        if v: print(f"\n  Round {r}  (k={K_VALUES[r]}, mode={r%4})\n  Input:  {state.hex().upper()}")
        state = round_function(state, r, round_keys, seed_matrices, verbose=v)
        if v: print(f"  Output: {state.hex().upper()}")
    return state
 
def decrypt(ciphertext, round_keys, seed_matrices):
    state = ciphertext
    for r in range(ROUNDS-1, -1, -1):
        k, mode = K_VALUES[r%12], r%4
        state = routing_permutation(state, mode)
        state = bytes(AES_SBOX_INV[b] for b in state)
        state = bytes(gf2_mat_vec(gf2_mat_inv(rotate_matrix_k(seed_matrices[j],(r+j)%4)), state[j]) for j in range(16))
        state = bytes(a^b for a,b in zip(state, round_keys[r]))
        state = rotr128(state, k)
    return state
 
# ============================================================
# TEST VECTOR OUTPUT
# ============================================================
if __name__ == "__main__":
    PASSWORD      = "HillEnigmaSPN2026!"
    SALT_HEX      = "0102030405060708090a0b0c0d0e0f10"
    PLAINTEXT_HEX = "00112233445566778899aabbccddeeff"
 
    salt      = bytes.fromhex(SALT_HEX)
    plaintext = bytes.fromhex(PLAINTEXT_HEX)
    SEP = "="*72
 
    print(SEP)
    print("HILL-ENIGMA-SPN (HESPN) -- REFERENCE TEST VECTOR")
    print("Key derivation: SHA-256 stub (production Argon2id version is")
    print("structurally identical for all cipher operations)")
    print(SEP)
    print(f"\nINPUTS")
    print(f"  Password  : {PASSWORD!r}")
    print(f"  Salt      : {SALT_HEX.upper()}")
    print(f"  Plaintext : {PLAINTEXT_HEX.upper()}")
 
    print(f"\n{SEP}\nKEY SETUP\n{SEP}")
    master_key, round_keys, seed_matrices = key_setup(PASSWORD, salt)
    mk = master_key.hex().upper()
    print(f"  Master key : {mk[:32]}\n               {mk[32:]}")
    print(f"\n  Round keys  (rk[r] = SHA256(K || 'ROUNDKEY' || r)[:16]):")
    for i,rk in enumerate(round_keys):
        print(f"    rk[{i:2d}]  k={K_VALUES[i]}  mode={i%4}  :  {rk.hex().upper()}")
    print(f"\n  Seed matrices  (8 row bytes, MSB-first):")
    for j,m in enumerate(seed_matrices):
        print(f"    S[{j:2d}] : {' '.join(f'{b:02X}' for b in m)}   B={branch_number(m)}")
 
    print(f"\n{SEP}\nROUND 0 -- STEP-BY-STEP INTERMEDIATE STATES\n{SEP}")
    print(f"  Plaintext (Round 0 input) : {plaintext.hex().upper()}")
    encrypt(plaintext, round_keys, seed_matrices, verbose_round=0)
 
    ciphertext = encrypt(plaintext, round_keys, seed_matrices)
    print(f"\n{SEP}\nFULL ENCRYPTION -- 12 ROUNDS\n{SEP}")
    print(f"  Plaintext  : {PLAINTEXT_HEX.upper()}")
    print(f"  Ciphertext : {ciphertext.hex().upper()}")
 
    decrypted = decrypt(ciphertext, round_keys, seed_matrices)
    ok = decrypted == plaintext
    print(f"\n{SEP}\nDECRYPTION VERIFICATION\n{SEP}")
    print(f"  Ciphertext : {ciphertext.hex().upper()}")
    print(f"  Decrypted  : {decrypted.hex().upper()}")
    print(f"  Expected   : {PLAINTEXT_HEX.upper()}")
    print(f"  Result     : {'PASS' if ok else 'FAIL'}")
 
    # Appendix table
    s0 = plaintext
    k0 = K_VALUES[0]
    s1 = rotl128(s0, k0)
    s2 = bytes(a^b for a,b in zip(s1, round_keys[0]))
    s3 = bytes(gf2_mat_vec(rotate_matrix_k(seed_matrices[j], j%4), s2[j]) for j in range(16))
    s4 = bytes(AES_SBOX[b] for b in s3)
    s5 = routing_permutation(s4, 0)
 
    print(f"\n{SEP}\nAPPENDIX TABLE -- copy into manuscript\n{SEP}")
    print(f"""
Table A1. Reference test vector for HESPN (SHA-256 stub key derivation).
 
  Parameter                Value
  -----------------------  ------------------------------------------------
  Password                 {PASSWORD!r}
  Salt (hex)               {SALT_HEX.upper()}
  Plaintext (hex)          {PLAINTEXT_HEX.upper()}
  Master key (256-bit)     {master_key.hex().upper()[:32]}
                           {master_key.hex().upper()[32:]}
  rk[0] (128-bit)          {round_keys[0].hex().upper()}
  -----------------------  ------------------------------------------------
  Round 0 input            {s0.hex().upper()}
  After Step 1 rotl128(b,{k0}) {s1.hex().upper()}
  After Step 2 XOR rk[0]  {s2.hex().upper()}
  After Step 3 GF(2) x16  {s3.hex().upper()}
  After Step 4 S-box x16  {s4.hex().upper()}
  After Step 5 Routing(0) {s5.hex().upper()}
  -----------------------  ------------------------------------------------
  Ciphertext (12 rounds)   {ciphertext.hex().upper()}
  Decryption check         {"PASS" if ok else "FAIL"}
  -----------------------  ------------------------------------------------
