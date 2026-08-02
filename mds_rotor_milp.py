#!/usr/bin/env python3
"""MILP wide-trail analysis for the 4x4 GF(2^8) MDS-rotor SPN.

The activity model uses only the MDS branch-number property B=5.  Therefore all
four rotated orientations, and all public schedules composed from them, have the
same certified active-S-box lower bound.  Schedule-specific differences must be
sought in coefficient-sensitive differential/linear trail searches, not in this
truncated branch-number model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

try:
    from scipy.optimize import Bounds, LinearConstraint, milp
    from scipy.sparse import lil_matrix, vstack
except Exception as exc:  # pragma: no cover - friendly runtime message
    Bounds = LinearConstraint = milp = None
    lil_matrix = vstack = None
    SCIPY_IMPORT_ERROR = exc
else:
    SCIPY_IMPORT_ERROR = None

from mds_rotor_core import state_index


@dataclass
class MilpLayout:
    rounds: int

    @property
    def x_count(self) -> int:
        return self.rounds * 16

    @property
    def y_count(self) -> int:
        return self.rounds * 16

    @property
    def z_count(self) -> int:
        return self.rounds * 4

    @property
    def nvars(self) -> int:
        return self.x_count + self.y_count + self.z_count

    def x(self, r: int, i: int) -> int:
        return r * 16 + i

    def y(self, r: int, i: int) -> int:
        return self.x_count + r * 16 + i

    def z(self, r: int, c: int) -> int:
        return self.x_count + self.y_count + r * 4 + c


@dataclass
class ActiveBoundResult:
    rounds: int
    minimum_active_sboxes: int
    differential_trail_log2_upper_bound: float
    linear_correlation_log2_upper_bound: float
    activity_masks: list[int]
    solver_message: str


def _require_scipy() -> None:
    if milp is None:
        raise RuntimeError(
            "SciPy is required for the MILP analysis. Install it with: "
            "py -m pip install numpy scipy"
        ) from SCIPY_IMPORT_ERROR


def _mix_input_indices(column: int) -> list[int]:
    # ShiftRows moves source (row,col_source) to (row,col_source-row).
    # Therefore sources entering destination column c are at col_source=c+row.
    return [state_index(row, (column + row) % 4) for row in range(4)]


def build_activity_model(rounds: int):
    """Return objective, integrality, bounds, and base linear constraints."""
    _require_scipy()
    if rounds < 1:
        raise ValueError("round count must be positive")
    layout = MilpLayout(rounds)
    c = np.zeros(layout.nvars)
    for r in range(rounds):
        for i in range(16):
            c[layout.x(r, i)] = 1.0

    rows: list[dict[int, float]] = []
    lower: list[float] = []
    upper: list[float] = []

    def add(coeffs: dict[int, float], lb: float = -np.inf, ub: float = np.inf) -> None:
        rows.append(coeffs)
        lower.append(lb)
        upper.append(ub)

    # Nonzero input difference/mask.
    add({layout.x(0, i): 1.0 for i in range(16)}, lb=1.0)

    for r in range(rounds):
        for col in range(4):
            z = layout.z(r, col)
            in_vars = [layout.x(r, i) for i in _mix_input_indices(col)]
            out_vars = [layout.y(r, state_index(row, col)) for row in range(4)]

            # z is the OR of input activities.
            coeff = {idx: 1.0 for idx in in_vars}
            coeff[z] = -1.0
            add(coeff, lb=0.0)  # sum(in) >= z

            coeff = {idx: 1.0 for idx in in_vars}
            coeff[z] = -4.0
            add(coeff, ub=0.0)  # sum(in) <= 4z

            coeff = {idx: 1.0 for idx in out_vars}
            coeff[z] = -4.0
            add(coeff, ub=0.0)  # no output if input column is zero

            # MDS branch-number condition: wt(in)+wt(out) >= 5 when active.
            coeff = {idx: 1.0 for idx in in_vars + out_vars}
            coeff[z] = -5.0
            add(coeff, lb=0.0)

        # Output activity becomes next round's S-box input activity.
        if r < rounds - 1:
            for i in range(16):
                add({layout.y(r, i): 1.0, layout.x(r + 1, i): -1.0}, lb=0.0, ub=0.0)

    matrix = lil_matrix((len(rows), layout.nvars), dtype=float)
    for rr, coeffs in enumerate(rows):
        for cc, value in coeffs.items():
            matrix[rr, cc] = value
    constraint = LinearConstraint(matrix.tocsr(), np.asarray(lower), np.asarray(upper))
    integrality = np.ones(layout.nvars, dtype=int)
    bounds = Bounds(np.zeros(layout.nvars), np.ones(layout.nvars))
    return layout, c, integrality, bounds, constraint


def solve_active_bound(rounds: int) -> ActiveBoundResult:
    layout, c, integrality, bounds, constraint = build_activity_model(rounds)
    result = milp(c=c, integrality=integrality, bounds=bounds,
                  constraints=constraint, options={"presolve": True})
    if not result.success or result.x is None:
        raise RuntimeError(f"MILP failed for {rounds} rounds: {result.message}")
    minimum = int(round(float(result.fun)))
    masks: list[int] = []
    for r in range(rounds):
        mask = 0
        for i in range(16):
            if result.x[layout.x(r, i)] > 0.5:
                mask |= 1 << i
        masks.append(mask)
    return ActiveBoundResult(
        rounds=rounds,
        minimum_active_sboxes=minimum,
        differential_trail_log2_upper_bound=-6.0 * minimum,
        linear_correlation_log2_upper_bound=-3.0 * minimum,
        activity_masks=masks,
        solver_message=str(result.message),
    )


def enumerate_minimum_patterns(rounds: int, maximum: int = 100,
                               distinct_on: str = "x") -> dict[str, object]:
    """Enumerate minimum-activity support patterns with MILP no-good cuts.

    The enumeration is capped because the number of optimal support patterns can
    be very large.  The returned count is exact only when ``cap_reached`` is false.
    Patterns are considered distinct by S-box activity variables (``x``) by
    default; choosing ``all`` also distinguishes linear-layer output and column
    activation variables.
    """
    _require_scipy()
    if maximum < 1:
        raise ValueError("maximum must be positive")
    optimum = solve_active_bound(rounds).minimum_active_sboxes
    layout, _, integrality, bounds, base_constraint = build_activity_model(rounds)

    # Fix objective value to the known optimum and use a zero objective.
    opt_row = lil_matrix((1, layout.nvars), dtype=float)
    for r in range(rounds):
        for i in range(16):
            opt_row[0, layout.x(r, i)] = 1.0

    base_A = base_constraint.A
    base_lb = np.asarray(base_constraint.lb)
    base_ub = np.asarray(base_constraint.ub)
    A = vstack([base_A, opt_row.tocsr()], format="csr")
    lb = np.concatenate([base_lb, [float(optimum)]])
    ub = np.concatenate([base_ub, [float(optimum)]])

    if distinct_on == "x":
        selected = [layout.x(r, i) for r in range(rounds) for i in range(16)]
    elif distinct_on == "all":
        selected = list(range(layout.nvars))
    else:
        raise ValueError("distinct_on must be 'x' or 'all'")

    zero_obj = np.zeros(layout.nvars)
    patterns: list[list[int]] = []
    cut_rows: list = []
    cut_ubs: list[float] = []
    for _ in range(maximum):
        if cut_rows:
            cut_matrix = vstack(cut_rows, format="csr")
            full_A = vstack([A, cut_matrix], format="csr")
            full_lb = np.concatenate([lb, np.full(len(cut_rows), -np.inf)])
            full_ub = np.concatenate([ub, np.asarray(cut_ubs)])
        else:
            full_A, full_lb, full_ub = A, lb, ub
        constraint = LinearConstraint(full_A, full_lb, full_ub)
        result = milp(c=zero_obj, integrality=integrality, bounds=bounds,
                      constraints=constraint, options={"presolve": True})
        if not result.success or result.x is None:
            return {
                "rounds": rounds,
                "minimum_active_sboxes": optimum,
                "enumerated_patterns": len(patterns),
                "cap": maximum,
                "cap_reached": False,
                "exact_count": len(patterns),
                "distinct_on": distinct_on,
                "patterns": patterns,
            }
        bits = [1 if result.x[idx] > 0.5 else 0 for idx in selected]
        patterns.append(bits)
        # No-good cut: sum_{ones} x - sum_{zeros} x <= (#ones)-1.
        cut = lil_matrix((1, layout.nvars), dtype=float)
        ones = 0
        for idx, bit in zip(selected, bits):
            if bit:
                cut[0, idx] = 1.0
                ones += 1
            else:
                cut[0, idx] = -1.0
        cut_rows.append(cut.tocsr())
        cut_ubs.append(float(ones - 1))

    return {
        "rounds": rounds,
        "minimum_active_sboxes": optimum,
        "enumerated_patterns": len(patterns),
        "cap": maximum,
        "cap_reached": True,
        "exact_count": None,
        "distinct_on": distinct_on,
        "patterns": patterns,
    }


def export_lp(rounds: int, path: str) -> None:
    """Write a solver-neutral LP model for external CBC/Gurobi/CPLEX use."""
    layout = MilpLayout(rounds)
    lines: list[str] = ["Minimize", " obj: " + " + ".join(
        f"x_{r}_{i}" for r in range(rounds) for i in range(16)
    ), "Subject To"]
    lines.append(" nonzero_input: " + " + ".join(f"x_0_{i}" for i in range(16)) + " >= 1")
    cid = 0
    for r in range(rounds):
        for col in range(4):
            ins = [f"x_{r}_{i}" for i in _mix_input_indices(col)]
            outs = [f"y_{r}_{state_index(row, col)}" for row in range(4)]
            z = f"z_{r}_{col}"
            lines.append(f" c{cid}: " + " + ".join(ins) + f" - {z} >= 0"); cid += 1
            lines.append(f" c{cid}: " + " + ".join(ins) + f" - 4 {z} <= 0"); cid += 1
            lines.append(f" c{cid}: " + " + ".join(outs) + f" - 4 {z} <= 0"); cid += 1
            lines.append(f" c{cid}: " + " + ".join(ins + outs) + f" - 5 {z} >= 0"); cid += 1
        if r < rounds - 1:
            for i in range(16):
                lines.append(f" c{cid}: y_{r}_{i} - x_{r+1}_{i} = 0"); cid += 1
    lines.append("Binary")
    for r in range(rounds):
        for i in range(16):
            lines.append(f" x_{r}_{i}")
            lines.append(f" y_{r}_{i}")
        for col in range(4):
            lines.append(f" z_{r}_{col}")
    lines.append("End")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    import json
    results = [solve_active_bound(r).__dict__ for r in (2, 4, 6, 8)]
    print(json.dumps(results, indent=2))
