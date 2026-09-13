# Source and reuse notes

This repository contains several generations of HESPN research code. The current IJIS manuscript uses the byte-local 8 x 8 GF(2) rotor-matrix construction as an experimental SPN linear-layer harness. Broader matched-schedule, trail-search, boomerang, randomness, cross-byte, and structural-audit materials remain in the repository as historical or separate research assets but are not part of the IJIS construction claim.

## Current IJIS evidence chain

The public repository should be read as supporting the following construction-level items:

- MSB-first byte and matrix representation;
- the explicitly defined 90-degree matrix-element rotation;
- the identity `R(M) = M^T J` and the resulting invertibility preservation;
- local differential and linear branch-number checks;
- sixteen-round rotor scheduling and balanced seed-orientation coverage;
- reversible round-function implementation;
- deterministic reference behavior and test vectors;
- admissibility-filter setup behavior;
- exact local one-bit diffusion profile;
- bounded plaintext-avalanche integration check.

The two machine-readable construction metrics remain under `cic_submission/metrics/` for provenance and are reused unchanged in the IJIS manuscript. Their path name does not make the current paper a CiC submission.

## Historical analyses retained for reproducibility

Older files include broader security diagnostics and later experimental branches. Examples include exact weight-one trails, schedule ablations, random-mask linear screens, sampled differential screens, boomerang calibration, NIST testing, algebraic-degree estimates, cross-byte Cauchy-MDS experiments, and slide/reflection audits.

Those files are intentionally preserved because deleting or silently rewriting them would impair reproducibility of earlier drafts and exploratory studies. They should not be cited as evidence that the current IJIS manuscript proves resistance to the corresponding attacks.

## Relationship to the separate orientation-scheduling study

The IJIS manuscript asks whether the rotating Hill-matrix family can be constructed and used as an SPN linear layer. A distinct orientation-scheduling study asks what cryptanalytic effect, if any, public scheduling has relative to matched static controls. Exact weight-one recurrence, support-growth analysis, and matched schedule comparisons belong to that separate question rather than to the IJIS construction paper.

## Reuse principle

When reusing code from this repository, distinguish the construction being implemented from the experiment being run. A script may be historically useful even when its output is outside the scope of the current paper. Preserve file provenance and avoid treating exploratory diagnostics as formal security guarantees.

See `docs/REPRODUCIBILITY_IJIS_2026_09_13.md` for the current construction-level evidentiary chain.
