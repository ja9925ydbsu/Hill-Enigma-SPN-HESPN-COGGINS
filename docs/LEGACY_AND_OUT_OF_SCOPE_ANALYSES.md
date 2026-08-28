# Legacy and out-of-scope analyses

This repository predates the current Communications in Cryptology framing and therefore contains experiments that address broader cryptanalytic questions than the current construction paper.

## Why the files are retained

They are retained to preserve research provenance and reproducibility. Deleting them would make earlier manuscript versions and exploratory analyses harder to reconstruct. Their presence should not be interpreted as making them part of the current CiC claim.

## Outside the current CiC evidentiary chain

The current construction paper does not rely on the following categories as support for its principal conclusion:

- exact weight-one recurrence, transfer matrices, best paths, or random-permutation comparisons;
- static, rotor, round-only, position-only, or optimized schedule rankings;
- matched avalanche comparisons across schedule arms;
- differential-collision and random-mask linear screens;
- boomerang or returned-difference experiments;
- NIST SP 800-22 output tests;
- restricted-variable algebraic-degree estimates;
- cross-byte Cauchy-MDS boundary experiments and coefficient-sensitive trail searches;
- slide and reflection audits as claims of attack resistance.

Those analyses ask what security contribution a scheduling mechanism might provide after the layer has been constructed. The CiC paper stops at the earlier construction question.

## Structural notes that remain relevant

Two limited observations are retained in the current framing because they prevent terminology from being misunderstood:

1. HESPN has no Enigma-style reflector and its round operation order is not self-inverse.
2. A period-four public orientation schedule is not the same thing as repeating an identical keyed round, because the reference configuration uses distinct round keys.

Neither statement is a proof of resistance to a reflection, slide, or related-key attack.

## Future cleanup

A later non-scientific repository cleanup may move older root-level experiments into archival directories. Any such move should preserve file contents and provenance so earlier results remain reproducible.
