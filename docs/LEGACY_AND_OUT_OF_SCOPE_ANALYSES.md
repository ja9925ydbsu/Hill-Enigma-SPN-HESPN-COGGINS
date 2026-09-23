# Scope boundary and historical analyses

This repository originally accumulated both HESPN construction work and broader experiments asking whether public orientation scheduling changes cryptanalytic behavior. Those remain distinct research questions. The current CiC working manuscript includes bounded analysis of the construction's direct diffusion limits, while the matched scheduling comparison has been published separately.

## Current HESPN scope

The *IACR Communications in Cryptology* working manuscript **Rotor-Scheduled Byte-Local Linear Layers: Construction and Structural Limits in an SPN** addresses construction, algebra, admissibility, scheduling, reversibility, setup behavior, reference vectors, exact local profiling, a bounded avalanche check, matrix-S-box linear equivalence, the byte branch number of the composite inter-round linear map, one-active-S-box trail searches, and reduced-round fixed-key endpoint checks.

The purpose of the paper is to define and analyze the mechanism, not to claim security for HESPN as a cipher. It does not claim that rotor scheduling is superior to a static orientation, it does not establish a deployment security level, and it does not establish or rule out a 16-round distinguisher.

## Separate Structural Limits study

The comparative scheduling question has been addressed separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, published in *Cryptography* 2026, 10, 71 (23 September 2026), https://doi.org/10.3390/cryptography10050071. Its working and reproducibility repository is:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

That repository is the current home for:

- exact low-support recurrence and transfer analysis used for matched schedule comparison;
- static, rotor, round-only, and position-only schedule comparisons;
- matched avalanche and other schedule-control experiments;
- calibration panels and fixed-key schedule checks;
- cross-byte Cauchy-MDS boundary experiments and associated trail searches;
- schedule optimization and related structural audit outputs.

The HESPN manuscript's one-active-S-box trail and reduced-round endpoint checks are therefore not classified as legacy or Structural Limits evidence. They are current CiC working-manuscript evidence and are documented under `iacr_cic_support/`.

Duplicate Structural Limits files were removed from the HESPN working tree on 2026-09-15. They remain available in the dedicated repository and are also recoverable from earlier HESPN Git commits.

## Historical HESPN-v4 diagnostics

Older HESPN-v4 differential, linear, NIST, boomerang, and confirmation scripts or logs are preserved under `legacy_hespn_v4/` for provenance. Their presence does not make those diagnostics part of the current CiC manuscript's claim set.

## Two structural observations retained

Two limited observations remain useful because they prevent terminology from being misunderstood:

1. HESPN has no Enigma-style reflector, no Enigma rotor wiring, and no self-inverse signal path.
2. A period-four public orientation schedule is not the same as repeating an identical keyed round, because the reference configuration derives distinct round keys by round index.

Neither statement is a proof of resistance to reflection, slide, or related-key attacks.
