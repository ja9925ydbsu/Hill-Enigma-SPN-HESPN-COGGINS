# Scope boundary and historical analyses

This repository originally accumulated both HESPN construction work and broader experiments asking whether public orientation scheduling changes cryptanalytic behavior. Those are now treated as two distinct research questions.

## Current HESPN scope

The *Cryptologia* construction manuscript **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer** addresses construction, algebra, admissibility, scheduling, reversibility, setup behavior, reference vectors, exact local profiling, and a bounded integration check.

It does not claim that rotor scheduling is superior to a static orientation, and it does not establish a deployment security level.

## Separate Structural Limits study

The comparative scheduling question is addressed separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, currently under review. Its working repository is:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

That repository is the current home for:

- exact weight-one recurrence and transfer analysis;
- static, rotor, round-only, and position-only schedule comparisons;
- matched avalanche and other schedule-control experiments;
- calibration panels and fixed-key checks;
- cross-byte Cauchy-MDS boundary experiments and trail searches;
- schedule optimization and related structural audit outputs.

Duplicate copies of those files were removed from the HESPN working tree on 2026-09-15. They remain available in the dedicated repository and are also recoverable from earlier HESPN Git commits.

## Historical HESPN-v4 diagnostics

Older HESPN-v4 differential, linear, NIST, and confirmation scripts/logs are preserved under `legacy_hespn_v4/` for provenance. Their presence does not make those diagnostics part of the present Cryptologia manuscript's claim set.

## Two structural observations retained

Two limited observations remain useful because they prevent terminology from being misunderstood:

1. HESPN has no Enigma-style reflector, no Enigma rotor wiring, and no self-inverse signal path.
2. A period-four public orientation schedule is not the same as repeating an identical keyed round, because the reference configuration derives distinct round keys by round index.

Neither statement is a proof of resistance to reflection, slide, or related-key attacks.
