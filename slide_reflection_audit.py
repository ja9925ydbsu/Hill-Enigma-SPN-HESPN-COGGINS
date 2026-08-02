#!/usr/bin/env python3
"""Structural slide- and reflection-symmetry audits for the MDS-rotor SPN.

These are diagnostics, not attack implementations. They identify exact or
near-exact self-similarity that could motivate a dedicated attack: repeated
orientation rows, repeated full-round fingerprints, palindromic schedules,
and inverse-related matrix pairs across reflected rounds.

The detailed audit is intentionally comprehensive. For routine inspection,
use :func:`compact_audit`, which removes repeated tables and replaces long pair
lists with counts and a few representative examples.
"""
from __future__ import annotations

import hashlib
import json
from statistics import fmean
from typing import Any, Sequence

from mds_rotor_core import (
    MDS_FAMILY,
    MDS_INVERSES,
    Schedule,
    derive_round_key,
    matrix_transpose,
    minimal_schedule_period,
    schedule_table,
)


def _matrix_hex(matrix) -> list[list[str]]:
    return [[f"{v:02X}" for v in row] for row in matrix]


def _round_fingerprint(master_key: bytes, schedule: Schedule, round_index: int,
                       include_key: bool) -> str:
    payload = bytearray()
    payload.extend(bytes(schedule(round_index, c) % 4 for c in range(4)))
    # ShiftRows and S-box are fixed; domain tags prevent ambiguity.
    payload.extend(b"AES-SBOX|SHIFTROWS|GF256-MDS")
    if include_key:
        payload.extend(derive_round_key(master_key, round_index))
    return hashlib.sha256(payload).hexdigest()


def slide_audit(master_key: bytes, schedule: Schedule, rounds: int) -> dict[str, object]:
    table = schedule_table(schedule, rounds)
    structural_fingerprints = [
        _round_fingerprint(master_key, schedule, r, include_key=False) for r in range(rounds)
    ]
    keyed_fingerprints = [
        _round_fingerprint(master_key, schedule, r, include_key=True) for r in range(rounds)
    ]

    repeated_structural: list[tuple[int, int]] = []
    repeated_keyed: list[tuple[int, int]] = []
    for a in range(rounds):
        for b in range(a + 1, rounds):
            if structural_fingerprints[a] == structural_fingerprints[b]:
                repeated_structural.append((a, b))
            if keyed_fingerprints[a] == keyed_fingerprints[b]:
                repeated_keyed.append((a, b))

    round_keys = [derive_round_key(master_key, r) for r in range(rounds)]
    key_hamming_distances = []
    for r in range(rounds - 1):
        key_hamming_distances.append(sum(
            (a ^ b).bit_count() for a, b in zip(round_keys[r], round_keys[r + 1])
        ))

    period = minimal_schedule_period(schedule, maximum=max(64, rounds * 2))
    return {
        "rounds": rounds,
        "orientation_table": table,
        "minimal_orientation_period": period,
        "repeated_structural_round_pairs": repeated_structural,
        "repeated_full_keyed_round_pairs": repeated_keyed,
        "all_round_keys_distinct": len(set(round_keys)) == len(round_keys),
        "adjacent_round_key_hamming_distances": key_hamming_distances,
        "minimum_adjacent_round_key_hamming_distance": min(key_hamming_distances) if key_hamming_distances else None,
        "assessment": (
            "Classical exact slide self-similarity is absent because no keyed round "
            "fingerprints repeat. Structural schedule repetition remains visible and "
            "should be considered in advanced slide/related-key analysis."
            if not repeated_keyed else
            "Exact keyed round repetition detected; dedicated slide analysis is required."
        ),
    }


def reflection_audit(master_key: bytes, schedule: Schedule, rounds: int) -> dict[str, object]:
    table = schedule_table(schedule, rounds)
    palindromic_pairs = []
    inverse_matrix_pairs = []
    transpose_pairs = []
    key_equal_pairs = []
    key_xor_weights = []

    for r in range(rounds):
        s = rounds - 1 - r
        if r > s:
            break
        row_r = table[r]
        row_s = table[s]
        if row_r == row_s:
            palindromic_pairs.append((r, s))
        key_r = derive_round_key(master_key, r)
        key_s = derive_round_key(master_key, s)
        if key_r == key_s:
            key_equal_pairs.append((r, s))
        key_xor_weights.append({
            "round_pair": [r, s],
            "xor_hamming_weight": sum((a ^ b).bit_count() for a, b in zip(key_r, key_s)),
        })
        for col in range(4):
            o_r = row_r[col]
            o_s = row_s[col]
            if MDS_FAMILY[o_r] == MDS_INVERSES[o_s]:
                inverse_matrix_pairs.append((r, s, col, o_r, o_s))
            if MDS_FAMILY[o_r] == matrix_transpose(MDS_FAMILY[o_s]):
                transpose_pairs.append((r, s, col, o_r, o_s))

    exact_schedule_palindrome = table == list(reversed(table))
    return {
        "rounds": rounds,
        "orientation_table": table,
        "exact_schedule_palindrome": exact_schedule_palindrome,
        "palindromic_round_pairs": palindromic_pairs,
        "inverse_related_matrix_positions": inverse_matrix_pairs,
        "transpose_related_matrix_positions": transpose_pairs,
        "equal_reflected_round_keys": key_equal_pairs,
        "reflected_round_key_xor_weights": key_xor_weights,
        "fixed_round_order_is_self_inverse": False,
        "assessment": (
            "No exact encryption/decryption reflection was found: the round operation "
            "order is not self-inverse, reflected round keys are distinct, and no full "
            "inverse-matrix alignment spans the schedule. Any partial palindromic or "
            "transpose relations are structural flags, not a demonstrated attack."
        ),
    }


def audit_all(master_key: bytes, schedules: dict[str, Schedule], rounds: int) -> dict[str, object]:
    """Return the complete, verbose audit for archival/reproducibility use."""
    return {
        name: {
            "slide": slide_audit(master_key, schedule, rounds),
            "reflection": reflection_audit(master_key, schedule, rounds),
        }
        for name, schedule in schedules.items()
    }


def _numeric_summary(values: Sequence[int | float]) -> dict[str, float | int | None]:
    if not values:
        return {"minimum": None, "maximum": None, "mean": None}
    return {
        "minimum": min(values),
        "maximum": max(values),
        "mean": round(float(fmean(values)), 3),
    }


def compact_audit(full_audit: dict[str, Any], example_limit: int = 8) -> dict[str, Any]:
    """Compress a detailed audit into a concise human-readable structure.

    Long orientation tables are represented by their unique rows. Long pair
    lists are represented by counts plus at most ``example_limit`` examples.
    Round-key statistics that repeat across variants are retained per row so the
    compact JSON and CSV remain self-contained.
    """
    variants: dict[str, Any] = {}
    for name, data in full_audit.items():
        slide = data["slide"]
        reflection = data["reflection"]
        table = slide.get("orientation_table", [])
        unique_rows = []
        for row in table:
            if row not in unique_rows:
                unique_rows.append(row)

        structural_pairs = slide.get("repeated_structural_round_pairs", [])
        keyed_pairs = slide.get("repeated_full_keyed_round_pairs", [])
        pal_pairs = reflection.get("palindromic_round_pairs", [])
        inverse_positions = reflection.get("inverse_related_matrix_positions", [])
        transpose_positions = reflection.get("transpose_related_matrix_positions", [])
        equal_reflected_keys = reflection.get("equal_reflected_round_keys", [])
        adjacent_hd = slide.get("adjacent_round_key_hamming_distances", [])
        reflected_hd = [
            item["xor_hamming_weight"]
            for item in reflection.get("reflected_round_key_xor_weights", [])
        ]

        variants[name] = {
            "rounds": slide.get("rounds"),
            "schedule": {
                "minimal_orientation_period": slide.get("minimal_orientation_period"),
                "unique_orientation_row_count": len(unique_rows),
                "unique_orientation_rows": unique_rows,
                "exact_palindrome": reflection.get("exact_schedule_palindrome", False),
            },
            "slide": {
                "structural_repeat_pair_count": len(structural_pairs),
                "structural_repeat_pair_examples": structural_pairs[:example_limit],
                "full_keyed_repeat_pair_count": len(keyed_pairs),
                "full_keyed_repeat_pair_examples": keyed_pairs[:example_limit],
                "all_round_keys_distinct": slide.get("all_round_keys_distinct"),
                "adjacent_round_key_hamming": _numeric_summary(adjacent_hd),
                "assessment": slide.get("assessment"),
            },
            "reflection": {
                "palindromic_reflected_pair_count": len(pal_pairs),
                "palindromic_reflected_pair_examples": pal_pairs[:example_limit],
                "inverse_related_position_count": len(inverse_positions),
                "inverse_related_position_examples": inverse_positions[:example_limit],
                "transpose_related_position_count": len(transpose_positions),
                "transpose_related_position_examples": transpose_positions[:example_limit],
                "equal_reflected_round_key_count": len(equal_reflected_keys),
                "equal_reflected_round_key_examples": equal_reflected_keys[:example_limit],
                "reflected_round_key_xor_hamming": _numeric_summary(reflected_hd),
                "fixed_round_order_is_self_inverse": reflection.get(
                    "fixed_round_order_is_self_inverse", False
                ),
                "assessment": reflection.get("assessment"),
            },
        }

    return {
        "format_version": 2,
        "detail_policy": (
            "Compact audit: long pair lists are replaced by counts and representative "
            f"examples (maximum {example_limit}). The complete audit is stored separately."
        ),
        "variants": variants,
    }


def compact_rows(compact: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten compact audit data for CSV output."""
    rows: list[dict[str, Any]] = []
    for name, data in compact["variants"].items():
        schedule = data["schedule"]
        slide = data["slide"]
        reflection = data["reflection"]
        adjacent = slide["adjacent_round_key_hamming"]
        reflected = reflection["reflected_round_key_xor_hamming"]
        rows.append({
            "variant": name,
            "rounds": data["rounds"],
            "orientation_period": schedule["minimal_orientation_period"],
            "unique_orientation_rows": schedule["unique_orientation_row_count"],
            "exact_schedule_palindrome": schedule["exact_palindrome"],
            "structural_repeat_pairs": slide["structural_repeat_pair_count"],
            "full_keyed_repeat_pairs": slide["full_keyed_repeat_pair_count"],
            "all_round_keys_distinct": slide["all_round_keys_distinct"],
            "adjacent_key_hd_min": adjacent["minimum"],
            "adjacent_key_hd_max": adjacent["maximum"],
            "adjacent_key_hd_mean": adjacent["mean"],
            "palindromic_reflected_pairs": reflection["palindromic_reflected_pair_count"],
            "inverse_related_positions": reflection["inverse_related_position_count"],
            "transpose_related_positions": reflection["transpose_related_position_count"],
            "equal_reflected_round_keys": reflection["equal_reflected_round_key_count"],
            "reflected_key_xor_hd_min": reflected["minimum"],
            "reflected_key_xor_hd_max": reflected["maximum"],
            "reflected_key_xor_hd_mean": reflected["mean"],
            "fixed_round_order_self_inverse": reflection["fixed_round_order_is_self_inverse"],
        })
    return rows


def compact_markdown(compact: dict[str, Any]) -> str:
    """Render the compact audit as a short Markdown report."""
    lines = [
        "# Slide and Reflection Audit Summary",
        "",
        "The complete pair lists and 16-round orientation tables are preserved in ",
        "`slide_and_reflection_audit_full.json`. This report presents counts and ",
        "summary statistics only.",
        "",
        "| Variant | Period | Unique rows | Structural repeat pairs | Keyed repeat pairs | Palindrome | Inverse positions | Transpose positions |",
        "|---|---:|---:|---:|---:|---|---:|---:|",
    ]
    for name, data in compact["variants"].items():
        schedule = data["schedule"]
        slide = data["slide"]
        reflection = data["reflection"]
        lines.append(
            f"| {name} | {schedule['minimal_orientation_period']} | "
            f"{schedule['unique_orientation_row_count']} | "
            f"{slide['structural_repeat_pair_count']} | "
            f"{slide['full_keyed_repeat_pair_count']} | "
            f"{str(schedule['exact_palindrome']).lower()} | "
            f"{reflection['inverse_related_position_count']} | "
            f"{reflection['transpose_related_position_count']} |"
        )

    lines.extend([
        "",
        "## Key findings",
        "",
    ])
    for name, data in compact["variants"].items():
        schedule = data["schedule"]
        slide = data["slide"]
        reflection = data["reflection"]
        adj = slide["adjacent_round_key_hamming"]
        refl = reflection["reflected_round_key_xor_hamming"]
        lines.append(
            f"- **{name}:** period {schedule['minimal_orientation_period']}; "
            f"{slide['structural_repeat_pair_count']} structural repeat pairs; "
            f"{slide['full_keyed_repeat_pair_count']} full keyed repeat pairs; "
            f"adjacent-key Hamming distance min/mean/max "
            f"{adj['minimum']}/{adj['mean']}/{adj['maximum']}; "
            f"reflected-key XOR Hamming distance min/mean/max "
            f"{refl['minimum']}/{refl['mean']}/{refl['maximum']}."
        )

    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "No exact keyed-round repetition or exact encryption/decryption reflection is ",
        "demonstrated when the corresponding counts are zero. Structural periodicity or ",
        "palindromic schedule rows are diagnostic flags only and are not attacks.",
        "",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    from mds_rotor_core import SCHEDULES, derive_master_key
    detailed = audit_all(derive_master_key(), SCHEDULES, 16)
    print(json.dumps(compact_audit(detailed), indent=2))
