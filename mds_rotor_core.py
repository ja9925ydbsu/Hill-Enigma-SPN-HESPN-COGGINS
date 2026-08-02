#!/usr/bin/env python3
"""Core primitives for the GF(2^8) MDS-rotor SPN study.

The module deliberately separates the new cross-byte experiment from the
published byte-local HESPN v4 implementation.  It reuses HESPN's general
research conventions (AES S-box, SHA-256 domain-separated round keys,
deterministic experiments, and explicit test/audit output), but replaces the
8x8 GF(2) per-byte layer with a 4x4 MDS matrix over GF(2^8).

Research code only.  It is not production cryptography.
"""
from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

STATE_ROWS = 4
STATE_COLS = 4
STATE_BYTES = 16
AES_POLY = 0x11B
ROUNDS_DEFAULT = 16

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
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    INV_SBOX[_v] = _i

# Two reference MDS matrices are provided.  AES_MDS is highly symmetric and
# therefore useful as a control.  The default CAUCHY_MDS is deliberately
# asymmetric, avoiding the possibility that the four geometric orientations
# collapse to trivial row/column relabellings of a circulant matrix.
AES_MDS: tuple[tuple[int, ...], ...] = (
    (0x02, 0x03, 0x01, 0x01),
    (0x01, 0x02, 0x03, 0x01),
    (0x01, 0x01, 0x02, 0x03),
    (0x03, 0x01, 0x01, 0x02),
)

# Cauchy matrix M[i,j] = (x_i XOR y_j)^(-1) for
# x=(00,01,02,03), y=(10,20,40,80), using the AES field polynomial.
CAUCHY_MDS: tuple[tuple[int, ...], ...] = (
    (0x74, 0x3A, 0x1D, 0x83),
    (0xB4, 0x6E, 0xFE, 0x7E),
    (0xAA, 0x5A, 0x37, 0x7F),
    (0x4B, 0xF1, 0x67, 0x80),
)

BASE_MDS = CAUCHY_MDS

Matrix = tuple[tuple[int, ...], ...]
Schedule = Callable[[int, int], int]


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in AES GF(2^8)."""
    a &= 0xFF
    b &= 0xFF
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return out


def gf_pow(a: int, exponent: int) -> int:
    result = 1
    base = a & 0xFF
    while exponent:
        if exponent & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exponent >>= 1
    return result


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse in GF(2^8)")
    return gf_pow(a, 254)


def matrix_vector_mul(matrix: Matrix, vector: Sequence[int]) -> tuple[int, ...]:
    if len(matrix) != len(vector):
        raise ValueError("matrix/vector dimension mismatch")
    return tuple(
        _xor_all(gf_mul(coef, value) for coef, value in zip(row, vector))
        for row in matrix
    )


def _xor_all(values: Iterable[int]) -> int:
    out = 0
    for value in values:
        out ^= value
    return out


def matrix_mul(a: Matrix, b: Matrix) -> Matrix:
    if len(a[0]) != len(b):
        raise ValueError("matrix dimensions do not conform")
    bt = tuple(zip(*b))
    return tuple(
        tuple(_xor_all(gf_mul(x, y) for x, y in zip(row, col)) for col in bt)
        for row in a
    )


def matrix_transpose(matrix: Matrix) -> Matrix:
    return tuple(tuple(row) for row in zip(*matrix))


def identity_matrix(n: int) -> Matrix:
    return tuple(tuple(1 if i == j else 0 for j in range(n)) for i in range(n))


def matrix_inverse(matrix: Matrix) -> Matrix:
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("matrix must be square")
    a = [list(row) + list(identity_matrix(n)[i]) for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if a[r][col] != 0), None)
        if pivot is None:
            raise ValueError("matrix is singular over GF(2^8)")
        a[col], a[pivot] = a[pivot], a[col]
        inv_pivot = gf_inv(a[col][col])
        a[col] = [gf_mul(v, inv_pivot) for v in a[col]]
        for r in range(n):
            if r == col:
                continue
            factor = a[r][col]
            if factor:
                a[r] = [x ^ gf_mul(factor, y) for x, y in zip(a[r], a[col])]
    return tuple(tuple(row[n:]) for row in a)


def determinant(matrix: Matrix) -> int:
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("matrix must be square")
    a = [list(row) for row in matrix]
    det = 1
    # In characteristic two, row swaps introduce no sign change because -1=1.
    for col in range(n):
        pivot = next((r for r in range(col, n) if a[r][col]), None)
        if pivot is None:
            return 0
        a[col], a[pivot] = a[pivot], a[col]
        pivot_value = a[col][col]
        det = gf_mul(det, pivot_value)
        inv_pivot = gf_inv(pivot_value)
        for r in range(col + 1, n):
            factor = gf_mul(a[r][col], inv_pivot)
            if factor:
                for j in range(col, n):
                    a[r][j] ^= gf_mul(factor, a[col][j])
    return det


def submatrix(matrix: Matrix, rows: Sequence[int], cols: Sequence[int]) -> Matrix:
    return tuple(tuple(matrix[r][c] for c in cols) for r in rows)


def is_mds(matrix: Matrix) -> bool:
    """Return True iff every square minor is nonsingular.

    For an n x n diffusion matrix over a field, this criterion is equivalent to
    the associated [2n,n,n+1] linear code being MDS and therefore to symbol-level
    branch number n+1.
    """
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        return False
    indices = range(n)
    for size in range(1, n + 1):
        for rows in itertools.combinations(indices, size):
            for cols in itertools.combinations(indices, size):
                if determinant(submatrix(matrix, rows, cols)) == 0:
                    return False
    return True


def rotate_matrix_clockwise(matrix: Matrix) -> Matrix:
    n = len(matrix)
    return tuple(tuple(matrix[n - 1 - j][i] for j in range(n)) for i in range(n))


def rotate_matrix_k(matrix: Matrix, k: int) -> Matrix:
    out = matrix
    for _ in range(k % 4):
        out = rotate_matrix_clockwise(out)
    return out


def matrix_family(base: Matrix = BASE_MDS) -> tuple[Matrix, Matrix, Matrix, Matrix]:
    return tuple(rotate_matrix_k(base, k) for k in range(4))  # type: ignore[return-value]


MDS_FAMILY = matrix_family()
MDS_INVERSES = tuple(matrix_inverse(m) for m in MDS_FAMILY)
MDS_INV_TRANSPOSES = tuple(matrix_inverse(matrix_transpose(m)) for m in MDS_FAMILY)


def state_index(row: int, col: int) -> int:
    return 4 * col + row


def bytes_to_state(block: bytes) -> list[int]:
    if len(block) != 16:
        raise ValueError("block must contain exactly 16 bytes")
    return list(block)


def shift_rows(state: Sequence[int]) -> list[int]:
    """AES ShiftRows on a column-major 4x4 byte state."""
    out = [0] * 16
    for row in range(4):
        for col in range(4):
            destination_col = (col - row) % 4
            out[state_index(row, destination_col)] = state[state_index(row, col)]
    return out


def inverse_shift_rows(state: Sequence[int]) -> list[int]:
    out = [0] * 16
    for row in range(4):
        for col in range(4):
            destination_col = (col + row) % 4
            out[state_index(row, destination_col)] = state[state_index(row, col)]
    return out


def mix_columns(state: Sequence[int], round_index: int, schedule: Schedule) -> list[int]:
    out = [0] * 16
    for col in range(4):
        vector = [state[state_index(row, col)] for row in range(4)]
        matrix = MDS_FAMILY[schedule(round_index, col) % 4]
        mixed = matrix_vector_mul(matrix, vector)
        for row, value in enumerate(mixed):
            out[state_index(row, col)] = value
    return out


def inverse_mix_columns(state: Sequence[int], round_index: int, schedule: Schedule) -> list[int]:
    out = [0] * 16
    for col in range(4):
        vector = [state[state_index(row, col)] for row in range(4)]
        matrix = MDS_INVERSES[schedule(round_index, col) % 4]
        mixed = matrix_vector_mul(matrix, vector)
        for row, value in enumerate(mixed):
            out[state_index(row, col)] = value
    return out


def propagate_difference_through_linear(state: Sequence[int], round_index: int,
                                        schedule: Schedule) -> tuple[int, ...]:
    return tuple(mix_columns(shift_rows(state), round_index, schedule))


def propagate_mask_through_linear_forward(state: Sequence[int], round_index: int,
                                           schedule: Schedule) -> tuple[int, ...]:
    """Map S-box output masks to the next round's S-box input masks.

    If y = M P z, then b_z = P^T M^T b_y.  Given b_z, the forward mask is
    b_y = M^{-T} P b_z.  P is AES ShiftRows.
    """
    shifted = shift_rows(state)
    out = [0] * 16
    for col in range(4):
        vector = [shifted[state_index(row, col)] for row in range(4)]
        matrix = MDS_INV_TRANSPOSES[schedule(round_index, col) % 4]
        mixed = matrix_vector_mul(matrix, vector)
        for row, value in enumerate(mixed):
            out[state_index(row, col)] = value
    return tuple(out)


def xor_state(a: Sequence[int], b: Sequence[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    return hashlib.sha256(
        master_key + b"MDS-ROTOR-ROUNDKEY" + round_index.to_bytes(2, "big")
    ).digest()[:16]


def derive_master_key(label: str = "MDS-ROTOR-SPN-RESEARCH-KEY") -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


@dataclass(frozen=True)
class TableSchedule:
    """Periodic orientation table indexed by round and column."""

    table: tuple[tuple[int, int, int, int], ...]
    name: str = "table"

    def __post_init__(self) -> None:
        if not self.table:
            raise ValueError("schedule table must not be empty")
        if any(len(row) != 4 for row in self.table):
            raise ValueError("each schedule row must have four column orientations")
        if any(not 0 <= value <= 3 for row in self.table for value in row):
            raise ValueError("orientations must be integers in [0,3]")

    def __call__(self, round_index: int, column_index: int) -> int:
        return self.table[round_index % len(self.table)][column_index]

    @property
    def period(self) -> int:
        return len(self.table)


def schedule_static(round_index: int, column_index: int) -> int:
    return 0


def schedule_rotor(round_index: int, column_index: int) -> int:
    return (round_index + column_index) % 4


def schedule_round_only(round_index: int, column_index: int) -> int:
    return round_index % 4


def schedule_position_only(round_index: int, column_index: int) -> int:
    return column_index % 4


DEFAULT_OPTIMIZED_TABLE = TableSchedule(
    table=(
        (0, 1, 2, 3),
        (2, 0, 3, 1),
        (1, 3, 0, 2),
        (3, 2, 1, 0),
        (1, 0, 3, 2),
        (3, 1, 2, 0),
        (0, 2, 1, 3),
        (2, 3, 0, 1),
    ),
    name="optimized_seed",
)

SCHEDULES: dict[str, Schedule] = {
    "static": schedule_static,
    "rotor": schedule_rotor,
    "round_only": schedule_round_only,
    "position_only": schedule_position_only,
    "optimized": DEFAULT_OPTIMIZED_TABLE,
}


def schedule_table(schedule: Schedule, rounds: int) -> list[list[int]]:
    return [[schedule(r, c) % 4 for c in range(4)] for r in range(rounds)]


def minimal_schedule_period(schedule: Schedule, maximum: int = 64) -> int | None:
    rows = [tuple(schedule(r, c) % 4 for c in range(4)) for r in range(maximum)]
    for period in range(1, maximum // 2 + 1):
        if all(rows[r] == rows[r % period] for r in range(maximum)):
            return period
    return None


@dataclass
class RotorSPN:
    master_key: bytes
    schedule: Schedule
    rounds: int = ROUNDS_DEFAULT

    def __post_init__(self) -> None:
        if self.rounds < 1:
            raise ValueError("round count must be positive")
        self.round_keys = [derive_round_key(self.master_key, r) for r in range(self.rounds + 1)]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        state = bytes_to_state(plaintext)
        for r in range(self.rounds):
            state = xor_state(state, self.round_keys[r])
            state = [AES_SBOX[x] for x in state]
            state = shift_rows(state)
            state = mix_columns(state, r, self.schedule)
        state = xor_state(state, self.round_keys[self.rounds])
        return bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        state = xor_state(bytes_to_state(ciphertext), self.round_keys[self.rounds])
        for r in reversed(range(self.rounds)):
            state = inverse_mix_columns(state, r, self.schedule)
            state = inverse_shift_rows(state)
            state = [INV_SBOX[x] for x in state]
            state = xor_state(state, self.round_keys[r])
        return bytes(state)


def hamming_weight_state(state: Sequence[int]) -> int:
    return sum(value.bit_count() for value in state)


def active_bytes(state: Sequence[int]) -> int:
    return sum(value != 0 for value in state)


def self_check() -> dict[str, object]:
    """Run algebraic and encryption/decryption checks."""
    family_mds = [is_mds(m) for m in MDS_FAMILY]
    if not all(family_mds):
        raise AssertionError("at least one matrix rotation is not MDS")
    if len({m for m in MDS_FAMILY}) != 4:
        raise AssertionError("matrix family does not have four distinct orientations")
    identity = identity_matrix(4)
    for matrix, inv in zip(MDS_FAMILY, MDS_INVERSES):
        if matrix_mul(matrix, inv) != identity:
            raise AssertionError("matrix inverse check failed")
    if rotate_matrix_k(BASE_MDS, 4) != BASE_MDS:
        raise AssertionError("rotation order-four check failed")
    # Known AES field arithmetic checks.
    if gf_mul(0x57, 0x13) != 0xFE:
        raise AssertionError("GF(2^8) multiplication check failed")
    key = derive_master_key("MDS-ROTOR-SPN-SELF-CHECK")
    plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    vectors: dict[str, str] = {}
    for name, schedule in SCHEDULES.items():
        cipher = RotorSPN(key, schedule, rounds=8)
        ciphertext = cipher.encrypt_block(plaintext)
        recovered = cipher.decrypt_block(ciphertext)
        if recovered != plaintext:
            raise AssertionError(f"round-trip failed for {name}")
        vectors[name] = ciphertext.hex().upper()
    return {
        "gf_multiplication_57x13": "FE",
        "all_rotations_mds": family_mds,
        "distinct_orientations": 4,
        "branch_number_each_orientation": 5,
        "eight_round_ciphertexts": vectors,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(self_check(), indent=2))
