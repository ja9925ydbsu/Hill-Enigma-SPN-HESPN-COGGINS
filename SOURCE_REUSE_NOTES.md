# Source and reuse notes

This repository contains several generations of HESPN research code. The current Communications in Cryptology manuscript uses the original byte-local 8 x 8 GF(2) rotor-matrix construction as an experimental SPN mix-layer harness. Later cross-byte MDS, matched-schedule, trail-search, boomerang, randomness, and structural-audit materials remain in the repository as historical research assets but are not part of the current CiC construction claim.

## Current CiC evidence chain

The public repository should be read as supporting the following construction-level items:

- MSB-first byte and matrix representation;
- 90-degree matrix-element rotations;
- invertibility checks;
- local differential and linear branch-number checks;
- sixteen-round rotor scheduling;
- reversible round-function implementation;
- deterministic reference behavior;
- admissibility-filter setup behavior;
- exact local one-bit diffusion profile;
- bounded plaintext-avalanche integration check.

The two CiC-specific machine-readable datasets are under `cic_submission/metrics/`.

## Historical analyses retained for reproducibility

Older files include broader security diagnostics and later experimental branches. Examples include exact weight-one trails, schedule ablations, random-mask linear screens, sampled differential screens, boomerang calibration, NIST testing, algebraic-degree estimates, cross-byte Cauchy-MDS experiments, and slide/reflection audits.

Those files are intentionally preserved because deleting or silently rewriting them would impair reproducibility of earlier drafts and exploratory studies. They should not be cited as evidence that the current CiC manuscript proves resistance to the corresponding attacks.

## Relationship to the separate orientation-scheduling study

The current CiC manuscript asks whether the rotating Hill-matrix family can be constructed and used as an SPN mix layer. A distinct orientation-scheduling study asks what cryptanalytic effect, if any, public scheduling has relative to matched static controls. Exact weight-one recurrence, support-growth analysis, and matched schedule comparisons belong to that separate question rather than to the CiC construction paper.

## Reuse principle

When reusing code from this repository, distinguish the construction being implemented from the experiment being run. A script may be historically useful even when its output is outside the scope of the current paper. Preserve file provenance and avoid treating exploratory diagnostics as formal security guarantees.
