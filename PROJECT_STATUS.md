# Project status: IJIS submission preparation

Updated: 2026-09-09

The current manuscript is being prepared for submission to Springer Nature's **International Journal of Information Security** under the title **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN**.

## Current research claim

The paper asks whether previously reported Hill-matrix element rotations can be used as a reversible, locally diffusion-bounded linear mix layer in an SPN. It does not propose HESPN as a deployment-ready cipher and does not claim that public rotor scheduling provides a security advantage over a static orientation.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- Every scheduled orientation is invertible.
- The four orientations require only two independent branch-number evaluations, B(M) and B(M^T).
- Every scheduled orientation satisfies the local floor B >= 4.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- The complete round function has an exact inverse.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The rejection filter is feasible for the reported prototype setup.

## Retained bounded empirical checks

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

These checks do not establish full-cipher security or isolate a benefit caused by orientation scheduling.

## Analyses outside the current paper

Weight-one transfer analysis, matched schedule comparisons, optimized differential and linear trails, boomerang analysis, NIST tests, algebraic-degree screens, cross-byte MDS experiments, and broader slide, reflection, and related-key cryptanalysis are outside the construction question. Historical files covering those topics remain available for reproducibility but are not part of the present evidentiary chain.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and the machine-readable verification datasets developed during the final Revision 5 preparation. The complete Springer Nature / IJIS manuscript package and cover letter are maintained separately as author-side submission artifacts and are not mirrored in the public code repository by default.

The substantive manuscript master is the final Revision 5 construction-feasibility paper dated 28 August 2026. The current work is a journal-format conversion and submission preparation, not a return to the broader July HESPN manuscript.
