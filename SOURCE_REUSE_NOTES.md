# Source and reuse notes

This repository contains the current HESPN reference implementation and CiC working-manuscript support materials together with historical HESPN development material. The current manuscript, **Rotor-Scheduled Byte-Local Linear Layers: Construction and Structural Limits in an SPN**, uses the byte-local 8 x 8 GF(2) rotor-matrix construction as an experimental SPN mix-layer harness and analyzes where its local diffusion guarantees end.

## Current HESPN evidence

The public repository should be read as supporting the following items:

- MSB-first byte and matrix representation;
- 90-degree matrix-element rotations;
- the identity `R(M) = M^T J` and consequent preservation of invertibility;
- local differential and linear branch-number checks;
- sixteen-round public rotor scheduling;
- reversible round-function implementation;
- deterministic reference behavior and test vectors;
- admissibility-filter setup behavior;
- exact local one-bit diffusion profile;
- bounded plaintext-avalanche integration checking;
- the proof that `S o M` is linearly equivalent to `S` for an invertible byte matrix `M`;
- the byte-level branch number 2 result for the composite map between successive S-box layers;
- one-active-S-box single-characteristic and single-trail searches for the reference key;
- reduced-round fixed-key endpoint checks used to show that selected single-trail products are not security margins for the fixed-key construction.

Current machine-readable validation data and trail-check summaries are under `iacr_cic_support/`.

## Interpretation boundary

The purpose of the manuscript is to define and analyze the mechanism, not to claim security for HESPN as a cipher. In particular, the local `B >= 4` condition is not a cross-byte MDS guarantee and does not imply a nontrivial multi-round active-S-box lower bound. The reduced-round endpoint measurements do not establish or rule out a 16-round distinguisher.

Full-round differential and linear hull analysis, boomerang, slide, reflection, related-key, and wide-trail cryptanalysis remain outside the current evidence set.

## Relationship to the separate orientation-scheduling study

The HESPN manuscript establishes the construction and analyzes its direct diffusion limits. The distinct comparative question has now been published as **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, published in *Cryptography* 2026, 10, 71 (23 September 2026), https://doi.org/10.3390/cryptography10050071; that study asks what effect, if any, public scheduling has relative to matched controls.

Its exact low-support recurrence calculations, matched schedule comparisons, support-growth analysis, cross-byte boundary work, calibration panels, and related outputs belong in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

The September 2026 HESPN cleanup removed duplicate copies of that separate-study material from the current HESPN working tree. Earlier copies remain recoverable from Git history.

## Historical HESPN material

Older HESPN-v4 diagnostic scripts and July 2026 logs are preserved under `legacy_hespn_v4/` for provenance. They document development history but are not part of the current CiC manuscript claim set unless a current support note explicitly promotes a result into the Revision 7A evidence chain.

## Reuse principle

When reusing code from this repository, distinguish the construction being implemented from the experiment being run. The current reference implementation is `hespn_reference.py`. The bounded one-active-S-box and endpoint-check driver is `hespn_trail_checks.py`. Historical scripts may still be useful for provenance, but their outputs should not be promoted into claims that the current manuscript does not make.
