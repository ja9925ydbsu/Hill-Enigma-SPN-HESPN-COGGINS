#!/usr/bin/env python3
"""Matched static-versus-rotor experiment for HESPN.

This script implements the 16-round HESPN test-vector specification and compares
four matrix-orientation schedules while holding every other component fixed:

    static        orientation 0 at every round and byte position
    rotor         (round + byte_position) mod 4 (manuscript schedule)
    round_only    round mod 4 at all byte positions
    position_only byte_position mod 4 at all rounds

The primary comparison is ``rotor`` versus ``static``.  The other schedules are
public, balanced controls that help distinguish temporal scheduling from mere
orientation diversity.

The script produces:
  * a normative test-vector self-check;
  * exact enumeration of the restricted one-active-bit / one-active-S-box trail
    class using the AES difference-distribution table;
  * matched plaintext-avalanche measurements with paired rotor-static deltas;
  * matched sampled-differential collision screens; and
  * matched structured-counter ciphertext-distance measurements.

The SHA-256 master-key labels used here are deterministic fixed 256-bit keys.  A
password KDF is deliberately excluded because the experiment compares fixed-key
round-function structure, not password guessing cost.

Research code only; not production cryptography.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    import numpy as np
except ImportError:  # empirical runs fall back to the slower scalar path
    np = None

NUM_BYTES = 16
BLOCK_BITS = 128
ROUNDS = 16
MIN_BRANCH_NUMBER = 4
K_VALUES = [7, 3, 1, 5, 3, 1, 5, 7, 1, 3, 5, 7, 7, 3, 1, 5]

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

Schedule = Callable[[int, int], int]


def schedule_static(round_index: int, byte_index: int) -> int:
    return 0


def schedule_rotor(round_index: int, byte_index: int) -> int:
    return (round_index + byte_index) % 4


def schedule_round_only(round_index: int, byte_index: int) -> int:
    return round_index % 4


def schedule_position_only(round_index: int, byte_index: int) -> int:
    return byte_index % 4


SCHEDULES: dict[str, Schedule] = {
    "static": schedule_static,
    "rotor": schedule_rotor,
    "round_only": schedule_round_only,
    "position_only": schedule_position_only,
}


@dataclass(frozen=True)
class Profile:
    keys: int
    avalanche_trials: int
    differential_samples: int
    counter_pairs: int
    differential_keys: int


PROFILES = {
    "smoke": Profile(keys=1, avalanche_trials=100, differential_samples=500,
                     counter_pairs=500, differential_keys=1),
    "standard": Profile(keys=4, avalanche_trials=2000, differential_samples=10000,
                        counter_pairs=10000, differential_keys=2),
    "paper": Profile(keys=8, avalanche_trials=5000, differential_samples=50000,
                     counter_pairs=20000, differential_keys=4),
}


class OnlineMoments:
    """Numerically stable online mean and sample variance."""

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    def add_many(self, values: Sequence[float]) -> None:
        if len(values) == 0:
            return
        if np is not None:
            arr = np.asarray(values, dtype=float)
            batch_n = int(arr.size)
            batch_mean = float(arr.mean())
            batch_m2 = float(((arr - batch_mean) ** 2).sum())
        else:
            vals = [float(v) for v in values]
            batch_n = len(vals)
            batch_mean = sum(vals) / batch_n
            batch_m2 = sum((v - batch_mean) ** 2 for v in vals)
        if self.n == 0:
            self.n = batch_n
            self.mean = batch_mean
            self.m2 = batch_m2
            return
        total = self.n + batch_n
        delta = batch_mean - self.mean
        self.m2 += batch_m2 + delta * delta * self.n * batch_n / total
        self.mean += delta * batch_n / total
        self.n = total

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def sd(self) -> float:
        return math.sqrt(self.variance)

    @property
    def se(self) -> float:
        return self.sd / math.sqrt(self.n) if self.n else float("nan")

    def ci95(self) -> tuple[float, float]:
        half = 1.96 * self.se if self.n > 1 else float("nan")
        return self.mean - half, self.mean + half


# ---------------------------------------------------------------------------
# HESPN primitive and matrix implementation
# ---------------------------------------------------------------------------


def rotl128(block: bytes, k: int) -> bytes:
    x = int.from_bytes(block, "big")
    k %= 128
    y = ((x << k) | (x >> (128 - k))) & ((1 << 128) - 1)
    return y.to_bytes(16, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def derive_round_key(master_key: bytes, round_index: int) -> bytes:
    return hashlib.sha256(
        master_key + b"ROUNDKEY" + round_index.to_bytes(2, "big")
    ).digest()[:16]


def apply_matrix_8(rows: Sequence[int], x: int) -> int:
    out = 0
    for row in rows:
        out = (out << 1) | ((row & x).bit_count() & 1)
    return out


def gf2_mat_rank_8(rows: Sequence[int]) -> int:
    a = list(rows)
    rank = 0
    for col in range(8):
        bit = 1 << (7 - col)
        pivot = next((r for r in range(rank, 8) if a[r] & bit), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        for r in range(8):
            if r != rank and (a[r] & bit):
                a[r] ^= a[rank]
        rank += 1
    return rank


def is_invertible_8(rows: Sequence[int]) -> bool:
    return gf2_mat_rank_8(rows) == 8


def rows_to_grid(rows: Sequence[int]) -> list[list[int]]:
    return [[(row >> (7 - j)) & 1 for j in range(8)] for row in rows]


def grid_to_rows(grid: Sequence[Sequence[int]]) -> list[int]:
    return [sum((bit & 1) << (7 - j) for j, bit in enumerate(row)) for row in grid]


def rotate_matrix_entries_clockwise_90(rows: Sequence[int]) -> list[int]:
    grid = rows_to_grid(rows)
    rotated = [[grid[7 - j][i] for j in range(8)] for i in range(8)]
    return grid_to_rows(rotated)


def rotate_matrix_entries_k(rows: Sequence[int], k: int) -> list[int]:
    out = list(rows)
    for _ in range(k % 4):
        out = rotate_matrix_entries_clockwise_90(out)
    return out


def transpose_matrix_8(rows: Sequence[int]) -> list[int]:
    grid = rows_to_grid(rows)
    return grid_to_rows([[grid[j][i] for j in range(8)] for i in range(8)])


def branch_number_at_least(rows: Sequence[int], threshold: int) -> bool:
    for x in range(1, 256):
        wx = x.bit_count()
        if wx >= threshold:
            continue
        if wx + apply_matrix_8(rows, x).bit_count() < threshold:
            return False
    return True


def branch_number(rows: Sequence[int]) -> int:
    return min(x.bit_count() + apply_matrix_8(rows, x).bit_count()
               for x in range(1, 256))


def derive_admissible_seed(master_key: bytes, byte_index: int) -> tuple[list[int], int]:
    """Return the first seed satisfying B(S)>=4 and B(S^T)>=4.

    Because R(S)=S^T J and J is weight preserving, this is exactly equivalent
    to checking all four scheduled orientations.  The reference implementation
    checks all four defensively; both procedures accept the same first seed.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(
            master_key + b"MATRIX" + byte_index.to_bytes(1, "big")
            + counter.to_bytes(4, "big")
        ).digest()
        rows = list(digest[:8])
        if (is_invertible_8(rows)
                and branch_number_at_least(rows, MIN_BRANCH_NUMBER)
                and branch_number_at_least(transpose_matrix_8(rows), MIN_BRANCH_NUMBER)):
            return rows, counter + 1
        counter += 1


def permute_index_bits(j: int, a: int, b: int) -> int:
    bits = [(j >> t) & 1 for t in range(4)]
    bits[a], bits[b] = bits[b], bits[a]
    return sum(bits[t] << t for t in range(4))


def routing_pi(round_index: int, j: int) -> int:
    mode = round_index % 4
    if mode == 0:
        return j
    return permute_index_bits(j, 0, mode)


@dataclass
class KeyContext:
    master_key: bytes
    seeds: list[list[int]]
    seed_attempts: list[int]
    round_keys: list[bytes]
    tables: list[list[bytes]]  # [byte_position][orientation][input]

    @classmethod
    def build(cls, master_key: bytes) -> "KeyContext":
        seeds: list[list[int]] = []
        attempts: list[int] = []
        tables: list[list[bytes]] = []
        for j in range(16):
            seed, count = derive_admissible_seed(master_key, j)
            seeds.append(seed)
            attempts.append(count)
            orient_tables = []
            for k in range(4):
                matrix = rotate_matrix_entries_k(seed, k)
                # Defensive equivalence checks for the manuscript guarantee.
                if not is_invertible_8(matrix):
                    raise AssertionError("rotation unexpectedly noninvertible")
                if branch_number(matrix) < MIN_BRANCH_NUMBER:
                    raise AssertionError("rotation below branch-number floor")
                orient_tables.append(bytes(apply_matrix_8(matrix, x) for x in range(256)))
            tables.append(orient_tables)
        round_keys = [derive_round_key(master_key, r) for r in range(ROUNDS)]
        return cls(master_key, seeds, attempts, round_keys, tables)

    def orbit_size(self, byte_index: int) -> int:
        family = {bytes(rotate_matrix_entries_k(self.seeds[byte_index], k)) for k in range(4)}
        return len(family)


def encrypt_block(block: bytes, ctx: KeyContext, rounds: int, schedule: Schedule) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be exactly 16 bytes")
    if not 0 <= rounds <= ROUNDS:
        raise ValueError(f"rounds must be in [0,{ROUNDS}]")
    state = block
    for r in range(rounds):
        state = rotl128(state, K_VALUES[r])
        state = xor_bytes(state, ctx.round_keys[r])
        mixed = [ctx.tables[j][schedule(r, j) % 4][state[j]] for j in range(16)]
        subbed = [AES_SBOX[x] for x in mixed]
        routed = [0] * 16
        for j, value in enumerate(subbed):
            routed[routing_pi(r, j)] = value
        state = bytes(routed)
    return state


def encrypt_blocks_numpy(blocks, ctx: KeyContext, rounds: int, schedule: Schedule):
    """Vectorized encryption of an (n,16) uint8 array."""
    if np is None:
        raise RuntimeError("NumPy is not installed")
    state = np.ascontiguousarray(blocks, dtype=np.uint8).reshape(-1, 16).copy()
    tables = getattr(ctx, "_np_tables", None)
    if tables is None:
        tables = np.empty((16, 4, 256), dtype=np.uint8)
        for j in range(16):
            for k in range(4):
                tables[j, k, :] = np.frombuffer(ctx.tables[j][k], dtype=np.uint8)
        ctx._np_tables = tables
        ctx._np_round_keys = np.frombuffer(b"".join(ctx.round_keys), dtype=np.uint8).reshape(16, 16)
        ctx._np_sbox = np.asarray(AES_SBOX, dtype=np.uint8)
    round_keys = ctx._np_round_keys
    sbox = ctx._np_sbox
    n = state.shape[0]
    for r in range(rounds):
        k = K_VALUES[r]
        words = state.view(dtype=">u8").reshape(n, 2)
        hi = words[:, 0].astype(np.uint64)
        lo = words[:, 1].astype(np.uint64)
        new_hi = (hi << np.uint64(k)) | (lo >> np.uint64(64 - k))
        new_lo = (lo << np.uint64(k)) | (hi >> np.uint64(64 - k))
        rotated_words = np.empty((n, 2), dtype=">u8")
        rotated_words[:, 0] = new_hi
        rotated_words[:, 1] = new_lo
        state = rotated_words.view(np.uint8).reshape(n, 16)
        state = np.bitwise_xor(state, round_keys[r])
        mixed = np.empty_like(state)
        for j in range(16):
            mixed[:, j] = tables[j, schedule(r, j) % 4, state[:, j]]
        subbed = sbox[mixed]
        destinations = np.asarray([routing_pi(r, j) for j in range(16)], dtype=int)
        routed = np.empty_like(subbed)
        routed[:, destinations] = subbed
        state = routed
    return state


def encrypt_blocks(blocks, ctx: KeyContext, rounds: int, schedule: Schedule):
    """Encrypt many blocks; NumPy is used when available."""
    if np is not None:
        return encrypt_blocks_numpy(blocks, ctx, rounds, schedule)
    return [encrypt_block(bytes(block), ctx, rounds, schedule) for block in blocks]


def popcount_rows(byte_array):
    if np is None:
        return [sum(int(x).bit_count() for x in row) for row in byte_array]
    lut = getattr(popcount_rows, "_lut", None)
    if lut is None:
        lut = np.asarray([i.bit_count() for i in range(256)], dtype=np.uint8)
        popcount_rows._lut = lut
    return lut[np.asarray(byte_array, dtype=np.uint8)].sum(axis=1)


def flip_bit(block: bytes, bit_index: int) -> bytes:
    if not 0 <= bit_index < 128:
        raise ValueError("bit_index must be in [0,127]")
    x = int.from_bytes(block, "big") ^ (1 << (127 - bit_index))
    return x.to_bytes(16, "big")


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def deterministic_master_key(index: int) -> bytes:
    return hashlib.sha256(b"HESPN-MATCHED-CONTROL-KEY" + index.to_bytes(4, "big")).digest()


def deterministic_rng(label: str, *parts: object) -> random.Random:
    payload = label.encode("utf-8") + b"|" + b"|".join(str(p).encode("utf-8") for p in parts)
    return random.Random(int.from_bytes(hashlib.sha256(payload).digest(), "big"))


def random_block_from_rng(rng: random.Random) -> bytes:
    return rng.getrandbits(128).to_bytes(16, "big")


# ---------------------------------------------------------------------------
# Normative self-check
# ---------------------------------------------------------------------------


def verify_test_vector() -> dict[str, str]:
    password = "HillEnigmaSPN2026!"
    salt = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    master_key = hashlib.sha256(password.encode("utf-8") + salt).digest()
    expected_master = "15C6D44AA434C83CB8C87A63969EC64513E2446B37DE5AC60B513C99FC1756E3"
    expected_rk0 = "740535C4CD34EA8908367F224C331C10"
    plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    expected_ciphertext = "3FD6391275C252DD4E3BC4CFE7F82C96"
    ctx = KeyContext.build(master_key)
    ciphertext = encrypt_block(plaintext, ctx, 16, schedule_rotor)
    checks = {
        "master_key": master_key.hex().upper(),
        "round_key_0": ctx.round_keys[0].hex().upper(),
        "ciphertext": ciphertext.hex().upper(),
    }
    if checks["master_key"] != expected_master:
        raise AssertionError(f"master-key mismatch: {checks['master_key']}")
    if checks["round_key_0"] != expected_rk0:
        raise AssertionError(f"round-key mismatch: {checks['round_key_0']}")
    if checks["ciphertext"] != expected_ciphertext:
        raise AssertionError(f"ciphertext mismatch: {checks['ciphertext']}")
    return checks


# ---------------------------------------------------------------------------
# Exact restricted weight-one trail enumeration
# ---------------------------------------------------------------------------


def aes_ddt() -> list[list[int]]:
    ddt = [[0] * 256 for _ in range(256)]
    for delta_in in range(256):
        for x in range(256):
            delta_out = AES_SBOX[x] ^ AES_SBOX[x ^ delta_in]
            ddt[delta_in][delta_out] += 1
    return ddt


def build_weight1_transitions(ctx: KeyContext, schedule: Schedule,
                              ddt: Sequence[Sequence[int]]) -> list[list[list[tuple[int, int]]]]:
    """transitions[r][input_bit] -> [(output_bit, DDT_count), ...]."""
    all_rounds: list[list[list[tuple[int, int]]]] = []
    single_bit_values = [(1 << (7 - u), u) for u in range(8)]
    for r in range(ROUNDS):
        round_transitions: list[list[tuple[int, int]]] = []
        k = K_VALUES[r]
        for bit_position in range(128):
            rotated_position = (bit_position - k) % 128
            byte_index, input_bit_in_byte = divmod(rotated_position, 8)
            input_value = 1 << (7 - input_bit_in_byte)
            table = ctx.tables[byte_index][schedule(r, byte_index) % 4]
            sbox_input_difference = table[input_value]
            edges: list[tuple[int, int]] = []
            for output_value, output_bit_in_byte in single_bit_values:
                count = ddt[sbox_input_difference][output_value]
                if count:
                    destination_byte = routing_pi(r, byte_index)
                    edges.append((8 * destination_byte + output_bit_in_byte, count))
            round_transitions.append(edges)
        all_rounds.append(round_transitions)
    return all_rounds


def exact_weight1_analysis(ctx: KeyContext, variant: str,
                           rounds_to_report: Sequence[int],
                           ddt: Sequence[Sequence[int]]) -> tuple[list[dict[str, object]], dict[str, object]]:
    schedule = SCHEDULES[variant]
    transitions = build_weight1_transitions(ctx, schedule, ddt)
    max_round = max(rounds_to_report)

    # Viterbi over all possible starting bits (initial log-probability 0).
    neg_inf = float("-inf")
    viterbi = [0.0] * 128
    backpointers: list[list[tuple[int, int] | None]] = []
    best_rows: dict[int, dict[str, object]] = {}
    for r in range(max_round):
        new = [neg_inf] * 128
        back: list[tuple[int, int] | None] = [None] * 128
        for src in range(128):
            if viterbi[src] == neg_inf:
                continue
            for dst, count in transitions[r][src]:
                candidate = viterbi[src] + math.log2(count / 256.0)
                if candidate > new[dst]:
                    new[dst] = candidate
                    back[dst] = (src, count)
        viterbi = new
        backpointers.append(back)
        rr = r + 1
        if rr in rounds_to_report:
            best_log2 = max(viterbi)
            best_rows[rr] = {
                "rounds": rr,
                "max_single_trail_log2_probability": best_log2,
                "max_single_trail_probability": 2.0 ** best_log2 if best_log2 != neg_inf else 0.0,
            }

    # Exact total probability of remaining in the weight-one class, maximized
    # over each of the 128 possible starting bits.
    max_total_by_round = {r: 0.0 for r in rounds_to_report}
    max_total_start = {r: None for r in rounds_to_report}
    for start in range(128):
        mass = [0.0] * 128
        mass[start] = 1.0
        for r in range(max_round):
            new_mass = [0.0] * 128
            for src, src_mass in enumerate(mass):
                if src_mass == 0.0:
                    continue
                for dst, count in transitions[r][src]:
                    new_mass[dst] += src_mass * (count / 256.0)
            mass = new_mass
            rr = r + 1
            if rr in rounds_to_report:
                total = sum(mass)
                if total > max_total_by_round[rr]:
                    max_total_by_round[rr] = total
                    max_total_start[rr] = start

    rows = []
    for rr in rounds_to_report:
        row = dict(best_rows[rr])
        total = max_total_by_round[rr]
        row.update({
            "variant": variant,
            "max_weight1_class_probability": total,
            "max_weight1_class_log2_probability": math.log2(total) if total > 0 else neg_inf,
            "max_weight1_class_start_bit": max_total_start[rr],
        })
        rows.append(row)

    # Reconstruct one globally best Viterbi path at max_round.
    end = max(range(128), key=lambda i: viterbi[i])
    path = [end]
    counts = []
    current = end
    for r in reversed(range(max_round)):
        bp = backpointers[r][current]
        if bp is None:
            break
        src, count = bp
        counts.append(count)
        path.append(src)
        current = src
    path.reverse()
    counts.reverse()
    detail = {
        "variant": variant,
        "rounds": max_round,
        "bit_path": path,
        "ddt_counts": counts,
        "per_round_probabilities": [c / 256.0 for c in counts],
        "log2_probability": max(viterbi),
    }
    return rows, detail


# ---------------------------------------------------------------------------
# Matched empirical measurements
# ---------------------------------------------------------------------------


def run_schedule_audit(contexts: Sequence[KeyContext], variants: Sequence[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key_index, ctx in enumerate(contexts):
        for j in range(16):
            rows.append({
                "key_index": key_index,
                "byte_index": j,
                "seed_attempts": ctx.seed_attempts[j],
                "orbit_size": ctx.orbit_size(j),
                "seed_branch_number": branch_number(ctx.seeds[j]),
                "transpose_branch_number": branch_number(transpose_matrix_8(ctx.seeds[j])),
            })
        for variant in variants:
            schedule = SCHEDULES[variant]
            labelled = {(j, schedule(r, j) % 4) for r in range(16) for j in range(16)}
            values = {
                bytes(rotate_matrix_entries_k(ctx.seeds[j], schedule(r, j)))
                for r in range(16) for j in range(16)
            }
            rows.append({
                "key_index": key_index,
                "byte_index": "ALL",
                "variant": variant,
                "labelled_seed_orientation_pairs": len(labelled),
                "distinct_matrix_values": len(values),
            })
    return rows


def run_avalanche(contexts: Sequence[KeyContext], variants: Sequence[str],
                  rounds_list: Sequence[int], trials: int) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    summary_rows: list[dict[str, object]] = []
    paired_rows: list[dict[str, object]] = []
    for key_index, ctx in enumerate(contexts):
        for rounds in rounds_list:
            rng = deterministic_rng("avalanche", key_index, rounds, trials)
            pts_bytes = b"".join(random_block_from_rng(rng) for _ in range(trials))
            bits = [rng.randrange(128) for _ in range(trials)]
            if np is not None:
                pts = np.frombuffer(pts_bytes, dtype=np.uint8).reshape(trials, 16).copy()
                pts2 = pts.copy()
                rows = np.arange(trials)
                byte_indices = np.asarray([b // 8 for b in bits], dtype=int)
                masks = np.asarray([1 << (7 - (b % 8)) for b in bits], dtype=np.uint8)
                pts2[rows, byte_indices] ^= masks
            else:
                pts = [pts_bytes[16*i:16*(i+1)] for i in range(trials)]
                pts2 = [flip_bit(pt, bit) for pt, bit in zip(pts, bits)]
            values = {}
            for variant in variants:
                schedule = SCHEDULES[variant]
                c1 = encrypt_blocks(pts, ctx, rounds, schedule)
                c2 = encrypt_blocks(pts2, ctx, rounds, schedule)
                if np is not None:
                    distances = popcount_rows(np.bitwise_xor(c1, c2)).astype(float)
                else:
                    distances = [hamming_distance(a, b) for a, b in zip(c1, c2)]
                stats = OnlineMoments(); stats.add_many(distances)
                values[variant] = distances
                low, high = stats.ci95()
                summary_rows.append({
                    "key_index": key_index, "variant": variant, "rounds": rounds,
                    "trials": stats.n, "mean_hamming_distance": stats.mean,
                    "sd": stats.sd, "ci95_low": low, "ci95_high": high,
                })
            if "rotor" in values and "static" in values:
                if np is not None:
                    diffs = np.asarray(values["rotor"], dtype=float) - np.asarray(values["static"], dtype=float)
                else:
                    diffs = [a-b for a,b in zip(values["rotor"], values["static"])]
                paired = OnlineMoments(); paired.add_many(diffs)
                low, high = paired.ci95()
                z = paired.mean / paired.se if paired.se > 0 else float("nan")
                p = math.erfc(abs(z) / math.sqrt(2.0)) if math.isfinite(z) else float("nan")
                paired_rows.append({
                    "key_index": key_index, "rounds": rounds, "trials": paired.n,
                    "mean_rotor_minus_static": paired.mean,
                    "sd_paired_difference": paired.sd, "ci95_low": low,
                    "ci95_high": high, "normal_approx_two_sided_p": p,
                    "paired_standardized_effect": paired.mean / paired.sd if paired.sd > 0 else 0.0,
                })
    return summary_rows, paired_rows


def difference_panel() -> list[tuple[str, bytes]]:
    panel: list[tuple[str, bytes]] = []
    for bit in [0, 19, 44, 68, 93, 127]:
        panel.append((f"single_bit_{bit}", (1 << (127 - bit)).to_bytes(16, "big")))
    for byte_index in [0, 5, 10, 15]:
        d = bytearray(16)
        d[byte_index] = 0xFF
        panel.append((f"full_byte_{byte_index}", bytes(d)))
    d2 = bytearray(16)
    d2[0] = 0x80
    d2[15] = 0x01
    panel.append(("two_byte_weight2", bytes(d2)))
    d4 = bytearray(16)
    for byte_index in [0, 5, 10, 15]:
        d4[byte_index] = 0x01
    panel.append(("four_byte_weight4", bytes(d4)))
    return panel


def run_differential(contexts: Sequence[KeyContext], variants: Sequence[str],
                     rounds_list: Sequence[int], samples: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key_index, ctx in enumerate(contexts):
        for rounds in rounds_list:
            for difference_name, difference in difference_panel():
                rng = deterministic_rng("differential", key_index, rounds, difference_name, samples)
                pts_bytes = b"".join(random_block_from_rng(rng) for _ in range(samples))
                if np is not None:
                    pts = np.frombuffer(pts_bytes, dtype=np.uint8).reshape(samples, 16).copy()
                    diff_arr = np.frombuffer(difference, dtype=np.uint8)
                    pts2 = np.bitwise_xor(pts, diff_arr)
                else:
                    pts = [pts_bytes[16*i:16*(i+1)] for i in range(samples)]
                    pts2 = [xor_bytes(pt, difference) for pt in pts]
                for variant in variants:
                    schedule = SCHEDULES[variant]
                    c1 = encrypt_blocks(pts, ctx, rounds, schedule)
                    c2 = encrypt_blocks(pts2, ctx, rounds, schedule)
                    if np is not None:
                        deltas = np.bitwise_xor(c1, c2)
                        packed = np.ascontiguousarray(deltas).view(np.dtype((np.void, 16))).ravel()
                        _, counts = np.unique(packed, return_counts=True)
                        max_mult = int(counts.max()) if counts.size else 0
                        distinct = int(counts.size)
                        collision_pairs = int(((counts.astype(np.int64) * (counts.astype(np.int64)-1)) // 2).sum())
                        mean_weight = float(popcount_rows(deltas).mean())
                    else:
                        counter = Counter(xor_bytes(a,b) for a,b in zip(c1,c2))
                        max_mult = max(counter.values()) if counter else 0
                        distinct = len(counter)
                        collision_pairs = sum(n*(n-1)//2 for n in counter.values())
                        mean_weight = statistics.fmean(sum(x.bit_count() for x in d) for d in counter.elements())
                    rows.append({
                        "key_index": key_index, "variant": variant, "rounds": rounds,
                        "difference": difference_name, "samples": samples,
                        "distinct_output_differences": distinct,
                        "max_multiplicity": max_mult, "collision_pairs": collision_pairs,
                        "max_observed_probability": max_mult / samples if samples else 0.0,
                        "mean_output_difference_weight": mean_weight,
                    })
    return rows


def run_counter_distance(contexts: Sequence[KeyContext], variants: Sequence[str],
                         rounds_list: Sequence[int], pairs: int,
                         strides: Sequence[int]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    modulus = 1 << 128
    for key_index, ctx in enumerate(contexts):
        for rounds in rounds_list:
            for stride in strides:
                rng = deterministic_rng("counter", key_index, rounds, stride, pairs)
                start_value = rng.getrandbits(128)
                left_bytes = b"".join(((start_value+i) % modulus).to_bytes(16,"big") for i in range(pairs))
                right_bytes = b"".join(((start_value+i+stride) % modulus).to_bytes(16,"big") for i in range(pairs))
                if np is not None:
                    left = np.frombuffer(left_bytes, dtype=np.uint8).reshape(pairs,16)
                    right = np.frombuffer(right_bytes, dtype=np.uint8).reshape(pairs,16)
                else:
                    left = [left_bytes[16*i:16*(i+1)] for i in range(pairs)]
                    right = [right_bytes[16*i:16*(i+1)] for i in range(pairs)]
                for variant in variants:
                    schedule = SCHEDULES[variant]
                    cx = encrypt_blocks(left, ctx, rounds, schedule)
                    cy = encrypt_blocks(right, ctx, rounds, schedule)
                    if np is not None:
                        distances = popcount_rows(np.bitwise_xor(cx,cy)).astype(float)
                    else:
                        distances = [hamming_distance(a,b) for a,b in zip(cx,cy)]
                    stats = OnlineMoments(); stats.add_many(distances)
                    low, high = stats.ci95()
                    rows.append({
                        "key_index": key_index, "variant": variant, "rounds": rounds,
                        "stride": stride, "pairs": stats.n,
                        "mean_hamming_distance": stats.mean, "sd": stats.sd,
                        "ci95_low": low, "ci95_high": high,
                        "z_from_ideal_64": (stats.mean-64.0)/stats.se if stats.se>0 else float("nan"),
                    })
    return rows


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def write_csv(path: Path, rows: Sequence[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def aggregate_rows(rows: Sequence[dict[str, object]], group_fields: Sequence[str],
                   value_field: str) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], list[float]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in group_fields)].append(float(row[value_field]))
    output = []
    for group, values in sorted(groups.items(), key=lambda item: tuple(str(x) for x in item[0])):
        stats = OnlineMoments()
        for value in values:
            stats.add(value)
        low, high = stats.ci95()
        record = {field: value for field, value in zip(group_fields, group)}
        record.update({
            "n_key_summaries": stats.n,
            f"mean_{value_field}": stats.mean,
            f"sd_{value_field}": stats.sd,
            "ci95_low_across_keys": low,
            "ci95_high_across_keys": high,
        })
        output.append(record)
    return output


def write_latex_summary(path: Path, avalanche_agg: Sequence[dict[str, object]],
                        counter_agg: Sequence[dict[str, object]],
                        weight1_rows: Sequence[dict[str, object]]) -> None:
    """Write a manuscript-ready compact table; values depend on the run profile."""
    av_lookup = {(r["variant"], int(r["rounds"])): r for r in avalanche_agg}
    ct_lookup = {(r["variant"], int(r["rounds"]), int(r["stride"])): r for r in counter_agg}
    w_lookup = {(r["variant"], int(r["rounds"])): r for r in weight1_rows}
    lines = [
        "% Auto-generated by matched_static_vs_rotor_experiment.py",
        "% Verify that the paper profile was used before inserting into a submission.",
        "\\begin{table*}[t]",
        "\\caption{Matched static-versus-rotor comparison. All variants use identical master keys, round keys, seed matrices, plaintexts, and input differences; only the public matrix-orientation schedule changes. Values are means across the key panel.}",
        "\\label{tab:matched-schedule}",
        "\\centering\\small",
        "\\begin{tabular}{llrrr}",
        "\\toprule",
        r"Variant & Rounds & Avalanche mean & Counter HD (stride 1) & $\log_2$ max weight-1 class probability \\",
        "\\midrule",
    ]
    for variant in ["static", "rotor", "round_only", "position_only"]:
        for rounds in [8, 12, 16]:
            av = av_lookup.get((variant, rounds), {})
            ct = ct_lookup.get((variant, rounds, 1), {})
            w = w_lookup.get((variant, rounds), {})
            avv = av.get("mean_mean_hamming_distance", float("nan"))
            ctv = ct.get("mean_mean_hamming_distance", float("nan"))
            wv = w.get("mean_max_weight1_class_log2_probability", w.get("max_weight1_class_log2_probability", float("nan")))
            safe_variant = variant.replace("_", "\\_")
            lines.append(f"{safe_variant} & {rounds} & {avv:.3f} & {ctv:.3f} & {float(wv):.2f}" + r" \\")
        lines.append("\\addlinespace")
    lines.extend(["\\bottomrule", "\\end{tabular}", "\\end{table*}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def make_plots(out_dir: Path, avalanche_agg: Sequence[dict[str, object]],
               counter_agg: Sequence[dict[str, object]]) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover - optional dependency
        print(f"Plotting skipped: {exc}", file=sys.stderr)
        return

    variants = sorted({str(r["variant"]) for r in avalanche_agg})
    fig, ax = plt.subplots(figsize=(8, 5))
    for variant in variants:
        subset = sorted((r for r in avalanche_agg if r["variant"] == variant),
                        key=lambda r: int(r["rounds"]))
        ax.plot([int(r["rounds"]) for r in subset],
                [float(r["mean_mean_hamming_distance"]) for r in subset],
                marker="o", label=variant)
    ax.axhline(64.0, linestyle="--", linewidth=1)
    ax.set_xlabel("Rounds")
    ax.set_ylabel("Mean plaintext-avalanche distance (bits)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "matched_avalanche.pdf")
    fig.savefig(out_dir / "matched_avalanche.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 5))
    subset_all = [r for r in counter_agg if int(r["stride"]) == 1]
    variants = sorted({str(r["variant"]) for r in subset_all})
    for variant in variants:
        subset = sorted((r for r in subset_all if r["variant"] == variant),
                        key=lambda r: int(r["rounds"]))
        ax.plot([int(r["rounds"]) for r in subset],
                [float(r["mean_mean_hamming_distance"]) for r in subset],
                marker="o", label=variant)
    ax.axhline(64.0, linestyle="--", linewidth=1)
    ax.set_xlabel("Rounds")
    ax.set_ylabel("Mean HD of ciphertexts for counter stride 1")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "matched_counter_distance.pdf")
    fig.savefig(out_dir / "matched_counter_distance.png", dpi=200)
    plt.close(fig)


def parse_int_list(text: str) -> list[int]:
    return [int(part.strip()) for part in text.split(",") if part.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="standard")
    parser.add_argument("--out", type=Path, default=Path("matched_experiment_results"))
    parser.add_argument("--variants", default="static,rotor,round_only,position_only")
    parser.add_argument("--avalanche-rounds", default="1,2,4,5,8,12,16")
    parser.add_argument("--differential-rounds", default="4,8,12,16")
    parser.add_argument("--counter-rounds", default="8,12,14,16")
    parser.add_argument("--counter-strides", default="1,2,4,8,16,256")
    parser.add_argument("--weight1-rounds", default="4,8,12,16")
    parser.add_argument("--skip-avalanche", action="store_true")
    parser.add_argument("--skip-differential", action="store_true")
    parser.add_argument("--skip-counter", action="store_true")
    args = parser.parse_args(argv)

    variants = [part.strip() for part in args.variants.split(",") if part.strip()]
    unknown = [name for name in variants if name not in SCHEDULES]
    if unknown:
        parser.error(f"unknown variants: {', '.join(unknown)}")
    if "static" not in variants or "rotor" not in variants:
        parser.error("the matched design requires both static and rotor variants")

    profile = PROFILES[args.profile]
    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()

    print("Verifying normative test vector...")
    test_vector = verify_test_vector()
    print("  PASS", test_vector)

    print(f"Building {profile.keys} deterministic matched key contexts...")
    contexts = [KeyContext.build(deterministic_master_key(i)) for i in range(profile.keys)]

    metadata = {
        "script": Path(__file__).name,
        "profile": args.profile,
        "profile_parameters": profile.__dict__,
        "variants": variants,
        "schedule_definitions": {
            "static": "0",
            "rotor": "(r+j) mod 4",
            "round_only": "r mod 4",
            "position_only": "j mod 4",
        },
        "avalanche_rounds": parse_int_list(args.avalanche_rounds),
        "differential_rounds": parse_int_list(args.differential_rounds),
        "counter_rounds": parse_int_list(args.counter_rounds),
        "counter_strides": parse_int_list(args.counter_strides),
        "weight1_rounds": parse_int_list(args.weight1_rounds),
        "key_derivation": "SHA-256 of fixed public labels; fixed-key comparison only",
        "test_vector": test_vector,
        "python": sys.version,
    }
    (out_dir / "experiment_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8")

    audit_rows = run_schedule_audit(contexts, variants)
    write_csv(out_dir / "schedule_and_seed_audit.csv", audit_rows)

    print("Running exact restricted weight-one trail enumeration...")
    ddt = aes_ddt()
    weight1_rows: list[dict[str, object]] = []
    weight1_paths: list[dict[str, object]] = []
    weight_rounds = parse_int_list(args.weight1_rounds)
    for key_index, ctx in enumerate(contexts):
        for variant in variants:
            rows, detail = exact_weight1_analysis(ctx, variant, weight_rounds, ddt)
            for row in rows:
                row["key_index"] = key_index
            detail["key_index"] = key_index
            weight1_rows.extend(rows)
            weight1_paths.append(detail)
    write_csv(out_dir / "exact_weight1_trail_summary.csv", weight1_rows)
    (out_dir / "exact_weight1_best_paths.json").write_text(
        json.dumps(weight1_paths, indent=2), encoding="utf-8")
    weight1_agg = aggregate_rows(
        weight1_rows, ["variant", "rounds"], "max_weight1_class_log2_probability")
    write_csv(out_dir / "exact_weight1_trail_across_keys.csv", weight1_agg)

    avalanche_rows: list[dict[str, object]] = []
    paired_rows: list[dict[str, object]] = []
    avalanche_agg: list[dict[str, object]] = []
    if not args.skip_avalanche:
        print("Running matched plaintext-avalanche experiment...")
        avalanche_rows, paired_rows = run_avalanche(
            contexts, variants, parse_int_list(args.avalanche_rounds),
            profile.avalanche_trials)
        write_csv(out_dir / "avalanche_by_key.csv", avalanche_rows)
        write_csv(out_dir / "avalanche_rotor_minus_static_paired.csv", paired_rows)
        avalanche_agg = aggregate_rows(
            avalanche_rows, ["variant", "rounds"], "mean_hamming_distance")
        write_csv(out_dir / "avalanche_across_keys.csv", avalanche_agg)

    differential_rows: list[dict[str, object]] = []
    if not args.skip_differential:
        print("Running matched sampled-differential experiment...")
        differential_rows = run_differential(
            contexts[:profile.differential_keys], variants,
            parse_int_list(args.differential_rounds), profile.differential_samples)
        write_csv(out_dir / "differential_collision_screen.csv", differential_rows)

    counter_rows: list[dict[str, object]] = []
    counter_agg: list[dict[str, object]] = []
    if not args.skip_counter:
        print("Running matched structured-counter distance experiment...")
        counter_rows = run_counter_distance(
            contexts, variants, parse_int_list(args.counter_rounds),
            profile.counter_pairs, parse_int_list(args.counter_strides))
        write_csv(out_dir / "counter_distance_by_key.csv", counter_rows)
        counter_agg = aggregate_rows(
            counter_rows, ["variant", "rounds", "stride"], "mean_hamming_distance")
        write_csv(out_dir / "counter_distance_across_keys.csv", counter_agg)

    if avalanche_agg and counter_agg:
        make_plots(out_dir, avalanche_agg, counter_agg)
        # Normalize weight1 aggregate field for the LaTeX helper.
        weight_for_tex = []
        for row in weight1_agg:
            rr = dict(row)
            rr["mean_max_weight1_class_log2_probability"] = rr.get(
                "mean_max_weight1_class_log2_probability",
                rr.get("mean_max_weight1_class_log2_probability", float("nan")))
            weight_for_tex.append(rr)
        write_latex_summary(out_dir / "matched_experiment_table.tex",
                            avalanche_agg, counter_agg, weight_for_tex)

    elapsed = time.time() - started
    metadata["elapsed_seconds"] = elapsed
    (out_dir / "experiment_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Complete in {elapsed:.1f} seconds. Results: {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
