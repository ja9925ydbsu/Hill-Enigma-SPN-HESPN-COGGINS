#!/usr/bin/env python3
"""Deterministic search for a nontrivial MDS-rotor orientation schedule.

The optimizer does not assume that more orientation changes are automatically
better.  It scores candidate period-8 schedules using common-random-number
Monte Carlo sampling of exact AES DDT transitions, then uses structural
slide/reflection penalties only as tie breakers.  Because this is a heuristic
search, the result is a candidate schedule, not a proof of optimality.
"""
from __future__ import annotations

import json
import math
import random
import statistics
from dataclasses import dataclass
from typing import Sequence

from mds_rotor_core import Schedule, TableSchedule, active_bytes, propagate_difference_through_linear
from mds_rotor_trails import build_ddt


@dataclass(frozen=True)
class OptimizerProfile:
    iterations: int
    trials: int
    rounds: int
    period: int = 8


PROFILES = {
    "smoke": OptimizerProfile(iterations=20, trials=300, rounds=4),
    "standard": OptimizerProfile(iterations=150, trials=1500, rounds=4),
    "paper": OptimizerProfile(iterations=1000, trials=8000, rounds=4),
}


def ddt_cdfs(ddt: Sequence[Sequence[int]]) -> list[list[tuple[int, int]]]:
    cdfs: list[list[tuple[int, int]]] = [[] for _ in range(256)]
    cdfs[0] = [(256, 0)]
    for a in range(1, 256):
        cumulative = 0
        row: list[tuple[int, int]] = []
        for b, count in enumerate(ddt[a]):
            if count:
                cumulative += count
                row.append((cumulative, b))
        if cumulative != 256:
            raise AssertionError("DDT row does not sum to 256")
        cdfs[a] = row
    return cdfs


def _sample_from_cdf(cdf: Sequence[tuple[int, int]], draw: int) -> int:
    for cumulative, value in cdf:
        if draw < cumulative:
            return value
    raise AssertionError("CDF sampling fell through")


def schedule_structure_metrics(schedule: Schedule, period: int) -> dict[str, float]:
    rows = [tuple(schedule(r, c) % 4 for c in range(4)) for r in range(period)]
    distinct_rows = len(set(rows))
    orientation_changes = sum(
        rows[r][c] != rows[(r + 1) % period][c]
        for r in range(period) for c in range(4)
    )
    column_coverage = sum(len({rows[r][c] for r in range(period)}) for c in range(4))
    palindrome_matches = sum(rows[r] == rows[period - 1 - r] for r in range(period))
    repeated_adjacent = sum(rows[r] == rows[(r + 1) % period] for r in range(period))
    return {
        "distinct_rows": float(distinct_rows),
        "orientation_changes": float(orientation_changes),
        "column_coverage": float(column_coverage),
        "palindrome_matches": float(palindrome_matches),
        "repeated_adjacent_rows": float(repeated_adjacent),
    }


def monte_carlo_trail_score(schedule: Schedule, cdfs: Sequence[Sequence[tuple[int, int]]],
                            *, trials: int, rounds: int, seed: int = 0xC0991A5) -> dict[str, float]:
    """Sample exact differential transitions using common random draws.

    Every candidate receives the same initial positions/differences and the same
    sequence of uniform DDT draws.  This reduces comparison noise, although the
    state-dependent mapping of draws means the estimator remains stochastic.
    """
    rng = random.Random(seed)
    # Pre-generate common random data so every schedule consumes the same draws.
    initial_positions = [rng.randrange(16) for _ in range(trials)]
    initial_values = [rng.randrange(1, 256) for _ in range(trials)]
    draws = [[[rng.randrange(256) for _ in range(16)] for _ in range(rounds)]
             for _ in range(trials)]

    cumulative_counts: list[int] = []
    final_counts: list[int] = []
    low_tail_35 = 0
    low_tail_36 = 0
    for t in range(trials):
        state = [0] * 16
        state[initial_positions[t]] = initial_values[t]
        cumulative = 0
        for r in range(rounds):
            cumulative += active_bytes(state)
            sbox_out = [
                0 if value == 0 else _sample_from_cdf(cdfs[value], draws[t][r][i])
                for i, value in enumerate(state)
            ]
            state = list(propagate_difference_through_linear(sbox_out, r, schedule))
        final_active = active_bytes(state)
        cumulative_counts.append(cumulative)
        final_counts.append(final_active)
        low_tail_35 += cumulative <= 35
        low_tail_36 += cumulative <= 36

    return {
        "mean_cumulative_active_sboxes": statistics.fmean(cumulative_counts),
        "sd_cumulative_active_sboxes": statistics.pstdev(cumulative_counts),
        "minimum_sampled_cumulative_active_sboxes": float(min(cumulative_counts)),
        "mean_final_active_bytes": statistics.fmean(final_counts),
        "probability_cumulative_at_most_35": low_tail_35 / trials,
        "probability_cumulative_at_most_36": low_tail_36 / trials,
    }


def scalar_objective(trail: dict[str, float], structure: dict[str, float]) -> float:
    """Higher is better; structural terms only break near-ties."""
    return (
        1000.0 * trail["mean_cumulative_active_sboxes"]
        + 20.0 * trail["mean_final_active_bytes"]
        - 100.0 * trail["probability_cumulative_at_most_35"]
        - 20.0 * trail["probability_cumulative_at_most_36"]
        + 0.05 * structure["orientation_changes"]
        + 0.02 * structure["column_coverage"]
        + 0.01 * structure["distinct_rows"]
        - 0.05 * structure["palindrome_matches"]
        - 0.05 * structure["repeated_adjacent_rows"]
    )


def random_latin_row(rng: random.Random) -> tuple[int, int, int, int]:
    row = [0, 1, 2, 3]
    rng.shuffle(row)
    return tuple(row)  # type: ignore[return-value]


def mutate_table(table: tuple[tuple[int, int, int, int], ...], rng: random.Random
                 ) -> tuple[tuple[int, int, int, int], ...]:
    rows = [list(row) for row in table]
    mode = rng.randrange(3)
    if mode == 0:
        r = rng.randrange(len(rows)); a, b = rng.sample(range(4), 2)
        rows[r][a], rows[r][b] = rows[r][b], rows[r][a]
    elif mode == 1:
        a, b = rng.sample(range(len(rows)), 2)
        rows[a], rows[b] = rows[b], rows[a]
    else:
        r = rng.randrange(len(rows))
        rows[r] = list(random_latin_row(rng))
    return tuple(tuple(row) for row in rows)  # type: ignore[return-value]


def optimize_schedule(profile: OptimizerProfile, *, seed: int = 20260731,
                      initial_table: tuple[tuple[int, int, int, int], ...] | None = None
                      ) -> dict[str, object]:
    ddt = build_ddt()
    cdfs = ddt_cdfs(ddt)
    rng = random.Random(seed)
    if initial_table is None:
        current_table = tuple(random_latin_row(rng) for _ in range(profile.period))
    else:
        current_table = initial_table
    current_schedule = TableSchedule(current_table, name="optimizer_current")
    current_trail = monte_carlo_trail_score(
        current_schedule, cdfs, trials=profile.trials, rounds=profile.rounds, seed=seed ^ 0x5A5A
    )
    current_structure = schedule_structure_metrics(current_schedule, profile.period)
    current_score = scalar_objective(current_trail, current_structure)

    best = (current_score, current_table, current_trail, current_structure)
    history: list[dict[str, object]] = []
    for iteration in range(profile.iterations):
        candidate_table = mutate_table(current_table, rng)
        candidate_schedule = TableSchedule(candidate_table, name="optimizer_candidate")
        trail = monte_carlo_trail_score(
            candidate_schedule, cdfs, trials=profile.trials,
            rounds=profile.rounds, seed=seed ^ 0x5A5A,
        )
        structure = schedule_structure_metrics(candidate_schedule, profile.period)
        score = scalar_objective(trail, structure)
        temperature = max(0.01, 1.0 - iteration / max(1, profile.iterations))
        accept = score >= current_score or rng.random() < math.exp(
            min(0.0, (score - current_score) / temperature)
        )
        if accept:
            current_score, current_table = score, candidate_table
        if score > best[0]:
            best = (score, candidate_table, trail, structure)
        if iteration % max(1, profile.iterations // 20) == 0 or iteration + 1 == profile.iterations:
            history.append({
                "iteration": iteration + 1,
                "best_score": best[0],
                "current_score": current_score,
            })

    best_score, best_table, best_trail, best_structure = best
    return {
        "profile": profile.__dict__,
        "seed": seed,
        "optimized_table": [list(row) for row in best_table],
        "objective": best_score,
        "trail_metrics": best_trail,
        "structural_metrics": best_structure,
        "history": history,
        "status": (
            "heuristic candidate selected by sampled DDT-trail activity; not a proof "
            "of optimality or security improvement"
        ),
    }


if __name__ == "__main__":
    result = optimize_schedule(PROFILES["smoke"])
    print(json.dumps(result, indent=2))
