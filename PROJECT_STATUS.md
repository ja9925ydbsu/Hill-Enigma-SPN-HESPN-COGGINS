# Project status: CiC construction-study alignment

Updated: 2026-08-28

The repository is aligned with the Communications in Cryptology manuscript **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN**.

## Current research claim

The current paper asks whether previously reported Hill-matrix element rotations can be used as a reversible, locally diffusion-bounded linear mix layer in an SPN. It does not propose HESPN as a deployment-ready cipher and does not claim that public rotor scheduling provides a security advantage over a static orientation.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- Every scheduled orientation is invertible.
- The four orientations require only two independent branch-number evaluations, B(M) and B(M^T).
- Every scheduled orientation satisfies the local floor B >= 4.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- The complete round function has an exact inverse.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The rejection filter is feasible for the reported prototype setup.

## CiC-specific empirical checks

The current revision adds only two bounded integration checks:

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A fresh plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

These checks do not establish full-cipher security or isolate a benefit caused by orientation scheduling.

## Analyses outside the current CiC paper

Weight-one transfer analysis, matched schedule comparisons, optimized differential and linear trails, boomerang analysis, NIST tests, algebraic-degree screens, cross-byte MDS experiments, and broader slide, reflection, and related-key cryptanalysis are outside the construction question. Historical files covering those topics remain available for reproducibility but are not part of the CiC evidentiary chain.

## Public repository versus submission package

The public repository contains the executable research code, historical reproducibility assets, scope documentation, and the two machine-readable CiC verification datasets. The complete `iacrj` and `iacrcc` manuscript submission packages are maintained separately as submission artifacts and are not mirrored here by default. This avoids treating a public code repository as the journal submission archive.
