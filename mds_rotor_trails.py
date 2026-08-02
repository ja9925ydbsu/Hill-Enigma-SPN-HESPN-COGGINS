#!/usr/bin/env python3
"""Coefficient-sensitive differential and linear trail searches.

The searches are beam searches, not proofs.  They complement the certified MILP
active-S-box bounds by retaining actual byte differences/masks and the exact AES
S-box DDT/LAT weights.  Reported candidate best trails are lower bounds on the
best achievable trail probability/correlation (an unseen trail may be better).
The MILP-derived values remain the rigorous upper bounds.
"""
from __future__ import annotations

import heapq
import math
from dataclasses import dataclass
from typing import Callable, Iterable, Literal, Sequence

from mds_rotor_core import (
    AES_SBOX,
    Schedule,
    active_bytes,
    propagate_difference_through_linear,
    propagate_mask_through_linear_forward,
)

SearchKind = Literal["differential", "linear"]


@dataclass(frozen=True)
class LocalChoice:
    output: int
    weight: float
    magnitude: float
    signed_value: int


@dataclass
class TrailNode:
    state: tuple[int, ...]
    weight: float
    start: tuple[int, int]
    cumulative_active: int
    path: tuple[tuple[int, ...], ...]
    best_path_count: int = 1


@dataclass
class MassNode:
    state: tuple[int, ...]
    start: tuple[int, int]
    cumulative_active: int
    mass: float
    best_weight: float


def build_ddt() -> list[list[int]]:
    table = [[0] * 256 for _ in range(256)]
    for a in range(256):
        for x in range(256):
            b = AES_SBOX[x] ^ AES_SBOX[x ^ a]
            table[a][b] += 1
    return table


def parity(x: int) -> int:
    return x.bit_count() & 1


def build_lat() -> list[list[int]]:
    table = [[0] * 256 for _ in range(256)]
    for a in range(256):
        for b in range(256):
            total = 0
            for x in range(256):
                total += 1 if parity(a & x) == parity(b & AES_SBOX[x]) else -1
            table[a][b] = total
    return table


def transition_choices(kind: SearchKind, table: Sequence[Sequence[int]],
                       top_per_active: int) -> list[list[LocalChoice]]:
    all_choices: list[list[LocalChoice]] = []
    for input_value in range(256):
        if input_value == 0:
            all_choices.append([LocalChoice(0, 0.0, 1.0, 256)])
            continue
        choices: list[LocalChoice] = []
        if kind == "differential":
            for output_value, count in enumerate(table[input_value]):
                if count:
                    magnitude = count / 256.0
                    choices.append(LocalChoice(
                        output_value, -math.log2(magnitude), magnitude, count
                    ))
        else:
            for output_value, walsh in enumerate(table[input_value]):
                if walsh:
                    magnitude = abs(walsh) / 256.0
                    choices.append(LocalChoice(
                        output_value, -math.log2(magnitude), magnitude, walsh
                    ))
        choices.sort(key=lambda item: (item.weight, item.output))
        all_choices.append(choices[:top_per_active])
    return all_choices


def k_best_joint_choices(choice_lists: Sequence[Sequence[LocalChoice]],
                         maximum: int) -> Iterable[tuple[tuple[int, ...], float, float]]:
    """Yield up to ``maximum`` best products without materializing a Cartesian product."""
    if maximum < 1:
        return
    if not choice_lists:
        yield tuple(), 0.0, 1.0
        return
    start = tuple(0 for _ in choice_lists)

    def score(indices: tuple[int, ...]) -> float:
        return sum(choice_lists[i][j].weight for i, j in enumerate(indices))

    heap: list[tuple[float, tuple[int, ...]]] = [(score(start), start)]
    seen = {start}
    emitted = 0
    while heap and emitted < maximum:
        joint_weight, indices = heapq.heappop(heap)
        outputs = tuple(choice_lists[i][j].output for i, j in enumerate(indices))
        magnitude = math.prod(choice_lists[i][j].magnitude for i, j in enumerate(indices))
        yield outputs, joint_weight, magnitude
        emitted += 1
        for dimension in range(len(indices)):
            next_index = indices[dimension] + 1
            if next_index >= len(choice_lists[dimension]):
                continue
            neighbor = list(indices)
            neighbor[dimension] = next_index
            neighbor_t = tuple(neighbor)
            if neighbor_t not in seen:
                seen.add(neighbor_t)
                heapq.heappush(heap, (score(neighbor_t), neighbor_t))


def initial_states(mode: str = "single_byte_all") -> list[tuple[tuple[int, ...], tuple[int, int]]]:
    states: list[tuple[tuple[int, ...], tuple[int, int]]] = []
    if mode == "single_byte_all":
        values = range(1, 256)
    elif mode == "single_bit":
        values = [1 << bit for bit in range(8)]
    else:
        raise ValueError("initial mode must be 'single_byte_all' or 'single_bit'")
    for position in range(16):
        for value in values:
            state = [0] * 16
            state[position] = value
            states.append((tuple(state), (position, value)))
    return states


def _linear_propagator(kind: SearchKind):
    return (propagate_difference_through_linear if kind == "differential"
            else propagate_mask_through_linear_forward)


def beam_search_best(schedule: Schedule, rounds: int, kind: SearchKind,
                     table: Sequence[Sequence[int]], *, beam_width: int = 2000,
                     top_per_active: int = 4, joint_expansions: int = 16,
                     initial_mode: str = "single_byte_all") -> dict[str, object]:
    """Find a high-probability candidate trail from a one-byte input.

    The returned candidate probability/correlation is achieved by a concrete
    retained trail.  It is not a global optimum certificate.
    """
    choices = transition_choices(kind, table, top_per_active)
    propagate = _linear_propagator(kind)
    nodes = [TrailNode(state, 0.0, start, 0, (state,), 1)
             for state, start in initial_states(initial_mode)]
    per_round: list[dict[str, object]] = []

    for r in range(rounds):
        merged: dict[tuple[int, ...], TrailNode] = {}
        for node in nodes:
            round_active = active_bytes(node.state)
            local_lists = [choices[value] for value in node.state]
            for sbox_outputs, local_weight, _ in k_best_joint_choices(
                    local_lists, joint_expansions):
                next_state = propagate(sbox_outputs, r, schedule)
                candidate = TrailNode(
                    state=next_state,
                    weight=node.weight + local_weight,
                    start=node.start,
                    cumulative_active=node.cumulative_active + round_active,
                    path=node.path + (next_state,),
                    best_path_count=node.best_path_count,
                )
                previous = merged.get(next_state)
                if previous is None or candidate.weight < previous.weight - 1e-12:
                    merged[next_state] = candidate
                elif abs(candidate.weight - previous.weight) <= 1e-12:
                    previous.best_path_count += candidate.best_path_count
        nodes = heapq.nsmallest(beam_width, merged.values(), key=lambda n: n.weight)
        if not nodes:
            raise RuntimeError("beam search exhausted all nodes")
        best = nodes[0]
        per_round.append({
            "round": r + 1,
            "candidate_log2_magnitude": -best.weight,
            "candidate_magnitude": 2.0 ** (-best.weight),
            "cumulative_active_sboxes": best.cumulative_active,
            "current_active_bytes": active_bytes(best.state),
            "retained_states": len(nodes),
            "retained_best_weight_path_count": sum(
                n.best_path_count for n in nodes if abs(n.weight - best.weight) <= 1e-12
            ),
        })

    best = min(nodes, key=lambda n: n.weight)
    return {
        "kind": kind,
        "rounds": rounds,
        "initial_mode": initial_mode,
        "beam_width": beam_width,
        "top_per_active": top_per_active,
        "joint_expansions": joint_expansions,
        "candidate_log2_magnitude": -best.weight,
        "candidate_magnitude": 2.0 ** (-best.weight),
        "start_position": best.start[0],
        "start_value": best.start[1],
        "cumulative_active_sboxes": best.cumulative_active,
        "retained_best_weight_path_count": sum(
            n.best_path_count for n in nodes if abs(n.weight - best.weight) <= 1e-12
        ),
        "state_path_hex": [bytes(state).hex().upper() for state in best.path],
        "per_round": per_round,
        "status": "heuristic candidate; not a global optimum proof",
    }


def beam_search_low_weight_mass(schedule: Schedule, rounds: int,
                                ddt: Sequence[Sequence[int]], *,
                                active_budget: int,
                                beam_width: int = 5000,
                                top_per_active: int = 4,
                                joint_expansions: int = 32) -> dict[str, object]:
    """Estimate captured aggregate probability of low-active differential trails.

    The search starts from all 128 one-bit input differences.  It sums retained
    path probabilities separately for each input.  Truncating local transitions
    and the global beam means the reported mass is a lower bound on the complete
    low-active class probability.
    """
    choices = transition_choices("differential", ddt, top_per_active)
    initial = initial_states("single_bit")
    nodes = [MassNode(state, start, 0, 1.0, 0.0) for state, start in initial]
    per_round: list[dict[str, object]] = []

    for r in range(rounds):
        merged: dict[tuple[tuple[int, int], tuple[int, ...], int], MassNode] = {}
        for node in nodes:
            cumulative = node.cumulative_active + active_bytes(node.state)
            if cumulative > active_budget:
                continue
            local_lists = [choices[value] for value in node.state]
            for sbox_outputs, local_weight, magnitude in k_best_joint_choices(
                    local_lists, joint_expansions):
                next_state = propagate_difference_through_linear(sbox_outputs, r, schedule)
                key = (node.start, next_state, cumulative)
                contribution = node.mass * magnitude
                previous = merged.get(key)
                if previous is None:
                    merged[key] = MassNode(
                        next_state, node.start, cumulative, contribution,
                        node.best_weight + local_weight,
                    )
                else:
                    previous.mass += contribution
                    previous.best_weight = min(previous.best_weight,
                                               node.best_weight + local_weight)

        # Retain nodes by probability mass, with best-weight tie breaking.
        nodes = heapq.nlargest(
            beam_width, merged.values(), key=lambda n: (n.mass, -n.best_weight)
        )
        mass_by_start: dict[tuple[int, int], float] = {}
        for node in nodes:
            mass_by_start[node.start] = mass_by_start.get(node.start, 0.0) + node.mass
        if mass_by_start:
            best_start, best_mass = max(mass_by_start.items(), key=lambda item: item[1])
        else:
            best_start, best_mass = (-1, -1), 0.0
        per_round.append({
            "round": r + 1,
            "retained_nodes": len(nodes),
            "maximum_captured_mass": best_mass,
            "maximum_captured_log2_mass": math.log2(best_mass) if best_mass > 0 else float("-inf"),
            "worst_start_position": best_start[0],
            "worst_start_value": best_start[1],
        })
        if not nodes:
            break

    mass_by_start: dict[tuple[int, int], float] = {}
    for node in nodes:
        mass_by_start[node.start] = mass_by_start.get(node.start, 0.0) + node.mass
    if mass_by_start:
        best_start, best_mass = max(mass_by_start.items(), key=lambda item: item[1])
    else:
        best_start, best_mass = (-1, -1), 0.0
    return {
        "rounds": rounds,
        "active_budget": active_budget,
        "beam_width": beam_width,
        "top_per_active": top_per_active,
        "joint_expansions": joint_expansions,
        "maximum_captured_mass": best_mass,
        "maximum_captured_log2_mass": math.log2(best_mass) if best_mass > 0 else float("-inf"),
        "worst_start_position": best_start[0],
        "worst_start_value": best_start[1],
        "per_round": per_round,
        "status": "captured-mass lower bound; omitted transitions/trails can add probability",
    }


def sbox_statistics(ddt: Sequence[Sequence[int]], lat: Sequence[Sequence[int]]) -> dict[str, object]:
    max_ddt = max(ddt[a][b] for a in range(1, 256) for b in range(256))
    max_lat = max(abs(lat[a][b]) for a in range(1, 256) for b in range(1, 256))
    return {
        "aes_sbox_max_ddt_count": max_ddt,
        "aes_sbox_max_differential_probability": max_ddt / 256.0,
        "aes_sbox_max_differential_log2_probability": math.log2(max_ddt / 256.0),
        "aes_sbox_max_abs_walsh": max_lat,
        "aes_sbox_max_abs_correlation": max_lat / 256.0,
        "aes_sbox_max_abs_correlation_log2": math.log2(max_lat / 256.0),
    }


if __name__ == "__main__":
    import json
    from mds_rotor_core import SCHEDULES
    ddt = build_ddt()
    lat = build_lat()
    print(json.dumps(sbox_statistics(ddt, lat), indent=2))
    print(json.dumps(beam_search_best(
        SCHEDULES["rotor"], 2, "differential", ddt,
        beam_width=200, top_per_active=2, joint_expansions=4,
        initial_mode="single_bit",
    ), indent=2))
