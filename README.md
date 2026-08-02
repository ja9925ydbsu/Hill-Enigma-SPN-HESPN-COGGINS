# GF(2^8) MDS-Rotor SPN Study

This package is a separate research branch for testing whether previously reported
Hill-matrix element rotations can serve as a **cross-byte modified mix layer** in a
substitution-permutation network (SPN).

It is **not** a proposal to replace AES, and it does not claim that the experimental
SPN is deployment-ready or completely secure. The purpose is to test the mix-layer
hypothesis under stronger conditions than the byte-local 8x8 GF(2) HESPN layer.

## What changed from HESPN v4

The published HESPN v4 experiment applies an 8x8 binary matrix independently to
each byte. This study instead uses an asymmetric 4x4 Cauchy maximum-distance-
separable (MDS) matrix over GF(2^8), so each matrix application spans four AES-sized
S-box inputs. Every 90-degree matrix-element orientation is verified to remain MDS
with symbol branch number 5.

The asymmetric Cauchy matrix is the default rather than the circulant AES
MixColumns matrix. This avoids making the rotor comparison depend on an unusually
symmetric base matrix. The AES matrix remains documented in `mds_rotor_core.py` as
a future control.

## Five matched schedules

Only the public orientation schedule changes:

1. `static`: orientation 0 in every round and column.
2. `rotor`: `(round + column) mod 4`.
3. `round_only`: `round mod 4` in every column.
4. `position_only`: `column mod 4` in every round.
5. `optimized`: a period-8 schedule selected by a deterministic heuristic search.

The S-box, ShiftRows, MDS seed matrix, round-key derivation, input panels, and
analysis settings are held fixed.

## Analyses included

1. **Minimum active S-box count** over 2, 4, 6, and 8 rounds.
2. **Count of minimum-activity support patterns**, using capped MILP enumeration.
3. **Differential trail bound and candidate search**:
   - certified bound from the active-S-box minimum and AES maximum differential
     probability;
   - coefficient-sensitive beam-search candidates using the exact AES DDT.
4. **Linear-correlation bound and candidate search**:
   - certified bound from the active-S-box minimum and AES maximum correlation;
   - coefficient-sensitive beam-search candidates using the exact AES LAT.
5. **Aggregate low-weight differential class estimate**, reported as captured mass
   under explicit beam and transition pruning.
6. **MILP trail search**, solved with SciPy/HiGHS and exported as solver-neutral LP
   files for CBC, Gurobi, CPLEX, or similar solvers.

The package also includes:

- a **slide self-similarity audit**;
- a **reflection/inverse-symmetry audit**;
- a deterministic schedule optimizer;
- algebraic and encryption/decryption self-tests;
- CSV, JSON, LP, and Markdown result output.

## Important interpretation point

Since every orientation is MDS with branch number 5, the certified wide-trail
active-S-box bounds are necessarily the same for all schedules. A rotor benefit, if
one exists, must appear in coefficient-sensitive trail multiplicities, aggregate
trail classes, related-key/slide structure, or other multi-round properties—not in
the one-round branch number itself.

The beam searches are heuristic. Their candidate trail values are achieved by
retained trails but are not global optimum proofs. The MILP active-S-box bounds are
the certified results.

## Files

- `mds_rotor_core.py` — GF(2^8), Cauchy MDS matrix, rotations, schedules, SPN,
  encryption/decryption, and self-checks.
- `mds_rotor_milp.py` — certified activity MILP, capped optimum-pattern
  enumeration, and LP export.
- `mds_rotor_trails.py` — AES DDT/LAT generation, differential/linear beam search,
  and aggregate low-active mass search.
- `mds_rotor_schedule_optimizer.py` — deterministic period-8 schedule search.
- `slide_reflection_audit.py` — detailed and compact slide/reflection diagnostics.
- `compact_existing_audit.py` — converts an already-completed verbose audit into compact JSON, CSV, and Markdown without rerunning the experiment.
- `run_mds_rotor_study.py` — main command-line runner.
- `test_mds_rotor_study.py` — unit tests.
- `run_smoke_test.bat`, `run_standard_study.bat`, `run_paper_study.bat` — Windows
  launchers.
- `run_study.ps1` — PowerShell launcher with a selectable profile.

## Installation on Windows

Open PowerShell in this folder and run:

```powershell
py -m pip install -r requirements.txt
```

Python 3.10 or newer is required. The code is compatible with the user's Python
3.14 environment provided NumPy and SciPy wheels are available for that Python
version.

## Run order

### 1. Unit tests

```powershell
py -m unittest -v test_mds_rotor_study.py
```

### 2. Smoke study

```powershell
py run_mds_rotor_study.py --profile smoke --out smoke_results
```

The no-argument IDLE run also uses the smoke profile:

```powershell
py run_mds_rotor_study.py
```

### 3. Standard study

```powershell
py run_mds_rotor_study.py --profile standard --out standard_results
```

### 4. Paper study

```powershell
py run_mds_rotor_study.py --profile paper --out paper_results
```

The paper profile can be computationally expensive. Run the smoke and standard
profiles first. Do not treat a silent interval during a beam search or MILP
enumeration as a crash unless Python has stopped using CPU and no files are being
updated for an extended period.

## Useful partial runs

Skip the optimizer and use the bundled period-8 seed schedule:

```powershell
py run_mds_rotor_study.py --profile standard --skip-optimizer --out standard_no_optimizer
```

Run only certified MILP results and audits:

```powershell
py run_mds_rotor_study.py --profile smoke --skip-optimizer --skip-heuristic-trails --skip-mass --out milp_audit_only
```

Compare only static and rotor schedules:

```powershell
py run_mds_rotor_study.py --profile standard --variants static,rotor --out static_vs_rotor
```

## Slide and reflection attacks

The runner now writes a concise default report and preserves the complete detail separately:

- `SLIDE_REFLECTION_SUMMARY.md` — shortest human-readable report;
- `slide_and_reflection_summary.csv` — one comparison row per variant;
- `slide_and_reflection_audit.json` — compact JSON with counts and representative examples;
- `slide_and_reflection_audit_full.json` — complete orientation tables and pair lists for archival reproducibility.

For an older results directory that contains only the long JSON, run:

```powershell
py .\compact_existing_audit.py .\standard_results_local
Get-Content .\standard_results_local\SLIDE_REFLECTION_SUMMARY.md -Encoding utf8
```

This conversion takes only a moment and does not rerun the optimizer, MILP, or trail searches.

The audits are intentionally conservative:

- **Slide audit:** finds the orientation schedule period, repeated structural round
  descriptions, repeated full keyed rounds, and adjacent round-key distances. A
  repeated public matrix schedule is not itself a slid pair; an exact classical
  slide requires sufficient full-round self-similarity.
- **Reflection audit:** checks schedule palindromes, reflected key equality,
  transpose relations, and whether a forward orientation equals the inverse of a
  reflected orientation. Flags indicate structures needing analysis, not a proven
  attack.

## Starting-point relationship to the existing GitHub repository

The package follows the existing HESPN repository's research conventions:

- AES S-box and deterministic reference behavior from the HESPN test-vector work;
- SHA-256 domain-separated round-key derivation style;
- reproducible profiles, diagnostics, and CSV/JSON output organization;
- matched control philosophy from the existing diagnostic and control experiments.

The new GF(2^8) Cauchy-MDS layer, MILP model, beam searches, schedule optimizer,
and slide/reflection audits are separate additions. The original HESPN v4 files
should remain unchanged so prior manuscript results remain reproducible.

## Initial smoke-run expectation

A successful smoke run should verify the following certified activity bounds:

| Rounds | Minimum active S-boxes | Differential upper bound | Linear-correlation upper bound |
|---:|---:|---:|---:|
| 2 | 5 | 2^-30 | 2^-15 |
| 4 | 25 | 2^-150 | 2^-75 |
| 6 | 30 | 2^-180 | 2^-90 |
| 8 | 50 | 2^-300 | 2^-150 |

Ties among schedule-specific heuristic metrics are possible and scientifically
meaningful. The study is designed to report them rather than force a positive
rotor conclusion.
