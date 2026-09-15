# Source and reuse notes

This repository contains the current HESPN construction reference plus historical HESPN development material. The current *Cryptologia* manuscript uses the byte-local 8 x 8 GF(2) rotor-matrix construction as an experimental SPN mix-layer harness.

## Current HESPN construction evidence

The public repository should be read as supporting the following construction-level items:

- MSB-first byte and matrix representation;
- 90-degree matrix-element rotations;
- the identity `R(M) = M^T J` and consequent preservation of invertibility;
- local differential and linear branch-number checks;
- sixteen-round public rotor scheduling;
- reversible round-function implementation;
- deterministic reference behavior and test vectors;
- admissibility-filter setup behavior;
- exact local one-bit diffusion profile;
- bounded plaintext-avalanche integration check.

Current machine-readable construction-verification data are under `cryptologia_support/metrics/`.

## Relationship to the separate orientation-scheduling study

The HESPN construction manuscript asks whether the rotating Hill-matrix family can be defined and used as a reversible SPN mix layer. A distinct manuscript, **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, asks what cryptanalytic effect, if any, public scheduling has relative to matched static controls. That manuscript is currently under review.

Its exact weight-one recurrence calculations, matched schedule comparisons, support-growth analysis, cross-byte MDS boundary work, calibration panels, and related outputs belong in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

The September 2026 HESPN cleanup removes duplicate copies of that separate-study material from the current HESPN working tree. The earlier copies remain recoverable from Git history.

## Historical HESPN material

Older HESPN-v4 diagnostic scripts and July 2026 logs are preserved under `legacy_hespn_v4/`. They document development history but are not part of the present Cryptologia evidence chain and should not be interpreted as current security claims.

## Reuse principle

When reusing code from this repository, distinguish the construction being implemented from the experiment being run. The current reference implementation is `hespn_reference.py`. Historical scripts may still be useful for provenance, but their outputs should not be promoted into claims that the current construction manuscript does not make.
