#!/usr/bin/env python3
"""Run the matched GF(2^8) MDS-rotor SPN study.

Default execution is a short smoke profile suitable for IDLE.  The standard and
paper profiles are intentionally heavier.  All variants use the same S-box,
ShiftRows permutation, round keys, base MDS matrix, plaintext/input panels, and
solver settings; only the public matrix-orientation schedule changes.

Research code only; not production cryptography.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from mds_rotor_core import (
    BASE_MDS,
    MDS_FAMILY,
    SCHEDULES as CORE_SCHEDULES,
    TableSchedule,
    derive_master_key,
    is_mds,
    minimal_schedule_period,
    schedule_table,
    self_check,
)
from mds_rotor_milp import enumerate_minimum_patterns, export_lp, solve_active_bound
from mds_rotor_schedule_optimizer import PROFILES as OPT_PROFILES, optimize_schedule
from mds_rotor_trails import (
    beam_search_best,
    beam_search_low_weight_mass,
    build_ddt,
    build_lat,
    sbox_statistics,
)
from slide_reflection_audit import audit_all, compact_audit, compact_markdown, compact_rows


@dataclass(frozen=True)
class StudyProfile:
    heuristic_rounds: tuple[int, ...]
    beam_width: int
    top_per_active: int
    joint_expansions: int
    enumeration_cap: int
    mass_rounds: int
    mass_active_budget: int
    mass_beam_width: int
    mass_joint_expansions: int
    optimizer_profile: str


PROFILES = {
    "smoke": StudyProfile(
        heuristic_rounds=(2, 3), beam_width=250, top_per_active=2,
        joint_expansions=4, enumeration_cap=10,
        mass_rounds=3, mass_active_budget=24, mass_beam_width=500,
        mass_joint_expansions=4, optimizer_profile="smoke",
    ),
    "standard": StudyProfile(
        heuristic_rounds=(2, 3, 4), beam_width=1500, top_per_active=4,
        joint_expansions=16, enumeration_cap=100,
        mass_rounds=4, mass_active_budget=40, mass_beam_width=5000,
        mass_joint_expansions=24, optimizer_profile="standard",
    ),
    "paper": StudyProfile(
        heuristic_rounds=(2, 3, 4, 5), beam_width=8000, top_per_active=6,
        joint_expansions=64, enumeration_cap=1000,
        mass_rounds=5, mass_active_budget=58, mass_beam_width=30000,
        mass_joint_expansions=96, optimizer_profile="paper",
    ),
}


def json_safe(value: Any) -> Any:
    if isinstance(value, float):
        if value == float("inf"):
            return "Infinity"
        if value == float("-inf"):
            return "-Infinity"
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(json_safe(data), indent=2), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (list, dict, tuple)) else v
                             for k, v in row.items()})


def matrix_hex(matrix) -> list[list[str]]:
    return [[f"{value:02X}" for value in row] for row in matrix]


def build_summary(out: Path, metadata: dict[str, Any], active_rows: list[dict[str, Any]],
                  differential_rows: list[dict[str, Any]], linear_rows: list[dict[str, Any]],
                  mass_rows: list[dict[str, Any]], schedules: dict[str, Any]) -> None:
    lines = [
        "# GF(2^8) MDS-Rotor SPN Study Summary",
        "",
        "This experiment tests whether 90-degree element rotations of an asymmetric ",
        "4x4 Cauchy MDS matrix can serve as a scheduled cross-byte SPN mix layer. ",
        "It does not claim a replacement for AES or a deployment-ready cipher.",
        "",
        "## Certified wide-trail activity bounds",
        "",
        "| Rounds | Minimum active S-boxes | Differential trail upper bound | Linear-correlation upper bound |",
        "|---:|---:|---:|---:|",
    ]
    for row in active_rows:
        lines.append(
            f"| {row['rounds']} | {row['minimum_active_sboxes']} | "
            f"2^({row['differential_trail_log2_upper_bound']:.0f}) | "
            f"2^({row['linear_correlation_log2_upper_bound']:.0f}) |"
        )
    lines.extend([
        "",
        "Because every orientation is MDS with branch number 5, these certified ",
        "activity bounds are schedule-independent. Schedule effects, if any, must ",
        "appear in coefficient-sensitive trail multiplicities, aggregate classes, ",
        "or structural self-similarity—not in the one-layer branch number.",
        "",
        "## Heuristic coefficient-sensitive searches",
        "",
        "Candidate trail searches are beam searches and are not proofs of global optima.",
        "",
        "| Kind | Variant | Rounds | Candidate log2 magnitude | Active S-boxes |",
        "|---|---|---:|---:|---:|",
    ])
    for row in differential_rows + linear_rows:
        lines.append(
            f"| {row['kind']} | {row['variant']} | {row['rounds']} | "
            f"{row['candidate_log2_magnitude']:.3f} | {row['cumulative_active_sboxes']} |"
        )
    lines.extend([
        "",
        "## Captured low-active differential mass",
        "",
        "These are lower bounds on captured class probability because local transitions ",
        "and global states are pruned.",
        "",
        "| Variant | Rounds | Active budget | Captured log2 mass |",
        "|---|---:|---:|---:|",
    ])
    for row in mass_rows:
        lines.append(
            f"| {row['variant']} | {row['rounds']} | {row['active_budget']} | "
            f"{row['maximum_captured_log2_mass']} |"
        )
    lines.extend([
        "",
        "## Schedule periods",
        "",
        "| Variant | Detected period |",
        "|---|---:|",
    ])
    for name, schedule in schedules.items():
        lines.append(f"| {name} | {minimal_schedule_period(schedule, 64)} |")
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "A favorable rotor result on one trail metric is evidence about that metric only. ",
        "A tie or unfavorable result is also informative. The central research question is ",
        "whether rotated Hill-derived MDS layers alter multi-round trail structure while ",
        "retaining a certified branch-number floor.",
        "",
        f"Profile: `{metadata['profile']}`. Runtime: {metadata['elapsed_seconds']:.2f} s.",
    ])
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="smoke")
    parser.add_argument("--out", default="mds_rotor_study_results")
    parser.add_argument("--variants", default="static,rotor,round_only,position_only,optimized")
    parser.add_argument("--skip-optimizer", action="store_true",
                        help="Use the bundled optimized seed table without a new search")
    parser.add_argument("--skip-heuristic-trails", action="store_true")
    parser.add_argument("--skip-mass", action="store_true")
    parser.add_argument("--skip-enumeration", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = PROFILES[args.profile]
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()

    print("GF(2^8) MDS-rotor SPN study")
    print("Research purpose: evaluate a rotated Hill-derived MDS mix layer; not an AES replacement.")
    print("Running algebraic and cipher self-check...")
    checks = self_check()
    print("  PASS: all four matrix orientations are distinct, invertible, and MDS (B=5).")

    schedules = dict(CORE_SCHEDULES)
    optimizer_result: dict[str, Any] | None = None
    if not args.skip_optimizer:
        print(f"Searching for an optimized schedule ({profile.optimizer_profile} optimizer profile)...")
        optimizer_result = optimize_schedule(OPT_PROFILES[profile.optimizer_profile])
        optimized_table = tuple(tuple(int(v) for v in row)
                                for row in optimizer_result["optimized_table"])
        schedules["optimized"] = TableSchedule(optimized_table, name="optimized")
        write_json(out / "schedule_optimizer.json", optimizer_result)
    else:
        print("Skipping new schedule search; using bundled optimized seed table.")

    requested = [v.strip() for v in args.variants.split(",") if v.strip()]
    unknown = [v for v in requested if v not in schedules]
    if unknown:
        raise SystemExit(f"Unknown variants: {', '.join(unknown)}")
    schedules = {name: schedules[name] for name in requested}

    mds_audit = {
        "base_matrix_hex": matrix_hex(BASE_MDS),
        "orientations": [
            {"orientation": k, "matrix_hex": matrix_hex(matrix), "is_mds": is_mds(matrix),
             "symbol_branch_number": 5}
            for k, matrix in enumerate(MDS_FAMILY)
        ],
        "self_check": checks,
        "schedule_tables_first_16_rounds": {
            name: schedule_table(schedule, 16) for name, schedule in schedules.items()
        },
    }
    write_json(out / "mds_and_schedule_audit.json", mds_audit)

    print("Solving certified active-S-box MILP bounds for 2, 4, 6, and 8 rounds...")
    active_rows: list[dict[str, Any]] = []
    enumeration_rows: list[dict[str, Any]] = []
    for rounds in (2, 4, 6, 8):
        bound = solve_active_bound(rounds)
        active_rows.append(bound.__dict__)
        export_lp(rounds, str(out / f"active_sbox_{rounds:02d}r.lp"))
        print(f"  {rounds} rounds: minimum {bound.minimum_active_sboxes} active S-boxes")
        if not args.skip_enumeration:
            enum = enumerate_minimum_patterns(rounds, profile.enumeration_cap)
            enumeration_rows.append({k: v for k, v in enum.items() if k != "patterns"})
            write_json(out / f"minimum_activity_patterns_{rounds:02d}r.json", enum)
    write_csv(out / "active_sbox_bounds.csv", active_rows)
    write_csv(out / "minimum_pattern_counts.csv", enumeration_rows)

    print("Building exact AES S-box DDT and LAT...")
    ddt = build_ddt()
    lat = build_lat()
    write_json(out / "aes_sbox_statistics.json", sbox_statistics(ddt, lat))

    differential_rows: list[dict[str, Any]] = []
    linear_rows: list[dict[str, Any]] = []
    if not args.skip_heuristic_trails:
        print("Running coefficient-sensitive differential and linear beam searches...")
        for name, schedule in schedules.items():
            for rounds in profile.heuristic_rounds:
                for kind, table, destination in (
                    ("differential", ddt, differential_rows),
                    ("linear", lat, linear_rows),
                ):
                    result = beam_search_best(
                        schedule, rounds, kind, table,
                        beam_width=profile.beam_width,
                        top_per_active=profile.top_per_active,
                        joint_expansions=profile.joint_expansions,
                        initial_mode="single_bit" if args.profile == "smoke" else "single_byte_all",
                    )
                    detail_path = out / f"{kind}_{name}_{rounds:02d}r_best_candidate.json"
                    write_json(detail_path, result)
                    destination.append({
                        "variant": name,
                        "kind": kind,
                        "rounds": rounds,
                        "candidate_log2_magnitude": result["candidate_log2_magnitude"],
                        "candidate_magnitude": result["candidate_magnitude"],
                        "start_position": result["start_position"],
                        "start_value": result["start_value"],
                        "cumulative_active_sboxes": result["cumulative_active_sboxes"],
                        "retained_best_weight_path_count": result["retained_best_weight_path_count"],
                        "status": result["status"],
                    })
                    print(f"  {kind:12s} {name:13s} r={rounds}: log2={result['candidate_log2_magnitude']}")
    write_csv(out / "differential_trail_candidates.csv", differential_rows)
    write_csv(out / "linear_trail_candidates.csv", linear_rows)

    mass_rows: list[dict[str, Any]] = []
    if not args.skip_mass:
        print("Estimating captured aggregate low-active differential mass...")
        for name, schedule in schedules.items():
            result = beam_search_low_weight_mass(
                schedule, profile.mass_rounds, ddt,
                active_budget=profile.mass_active_budget,
                beam_width=profile.mass_beam_width,
                top_per_active=profile.top_per_active,
                joint_expansions=profile.mass_joint_expansions,
            )
            write_json(out / f"low_weight_mass_{name}.json", result)
            mass_rows.append({
                "variant": name,
                "rounds": result["rounds"],
                "active_budget": result["active_budget"],
                "maximum_captured_mass": result["maximum_captured_mass"],
                "maximum_captured_log2_mass": result["maximum_captured_log2_mass"],
                "worst_start_position": result["worst_start_position"],
                "worst_start_value": result["worst_start_value"],
                "status": result["status"],
            })
            print(f"  {name:13s}: captured log2 mass={result['maximum_captured_log2_mass']}")
    write_csv(out / "low_weight_trail_mass.csv", mass_rows)

    print("Auditing slide self-similarity and reflection symmetry...")
    master_key = derive_master_key()
    audits_full = audit_all(master_key, schedules, 16)
    audits_compact = compact_audit(audits_full)
    # Preserve complete reproducibility details separately while making the
    # default audit concise enough for terminal inspection and manuscript use.
    write_json(out / "slide_and_reflection_audit_full.json", audits_full)
    write_json(out / "slide_and_reflection_audit.json", audits_compact)
    write_json(out / "slide_and_reflection_summary.json", audits_compact)
    write_csv(out / "slide_and_reflection_summary.csv", compact_rows(audits_compact))
    (out / "SLIDE_REFLECTION_SUMMARY.md").write_text(
        compact_markdown(audits_compact), encoding="utf-8"
    )

    elapsed = time.time() - started
    metadata = {
        "profile": args.profile,
        "python": sys.version,
        "platform": platform.platform(),
        "elapsed_seconds": elapsed,
        "variants": requested,
        "optimizer_run": not args.skip_optimizer,
        "interpretation_boundary": (
            "The study evaluates a rotated Hill-derived MDS mix layer. It does not "
            "establish a secure cipher, an AES replacement, or schedule optimality."
        ),
    }
    write_json(out / "experiment_metadata.json", metadata)
    build_summary(out, metadata, active_rows, differential_rows, linear_rows, mass_rows, schedules)

    print(f"Complete in {elapsed:.2f} seconds.")
    print(f"Results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
