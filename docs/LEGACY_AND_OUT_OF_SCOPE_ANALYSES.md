# Legacy and out-of-scope analyses

This repository predates the current IJIS construction-feasibility framing and therefore contains experiments that address broader cryptanalytic questions than the manuscript **Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**.

## Why the files are retained

They are retained to preserve research provenance and reproducibility. Deleting them would make earlier manuscript versions and exploratory analyses harder to reconstruct. Their presence should not be interpreted as making them part of the current IJIS claim.

## Outside the current IJIS evidentiary chain

The construction paper does not rely on the following categories as support for its conclusion:

- exact weight-one recurrence, transfer matrices, best paths, or random-permutation comparisons;
- static, rotor, round-only, position-only, or optimized schedule rankings;
- matched avalanche comparisons across schedule arms;
- differential-collision and random-mask linear screens;
- boomerang or returned-difference experiments;
- NIST SP 800-22 output tests;
- restricted-variable algebraic-degree estimates;
- cross-byte Cauchy-MDS boundary experiments and coefficient-sensitive trail searches;
- slide and reflection audits as claims of attack resistance.

Those analyses address what security contribution a scheduling mechanism might provide after the layer has been constructed. The IJIS paper stops at the construction question.

## Structural notes that remain relevant

Two limited observations remain useful because they prevent terminology from being misunderstood:

1. HESPN has no Enigma-style reflector and its round operation order is not self-inverse.
2. A period-four public orientation schedule is not the same thing as repeating an identical keyed round, because the reference configuration uses distinct round keys.

Neither statement is a proof of resistance to reflection, slide, or related-key cryptanalysis.

## Relationship to the current manuscript

The current evidentiary chain is listed in `REPRODUCIBILITY_IJIS_2026_09_13.md`. Historical analyses may be useful in separate research tracks, but they should not be cited as if the IJIS construction manuscript established their conclusions.

## Repository cleanup principle

Any later non-scientific reorganization should preserve file contents and provenance so earlier results remain reproducible. Historical files should be moved or relabelled rather than silently rewritten or deleted.
