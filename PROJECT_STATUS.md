# Project status: IJIS Revision 4

Updated: 2026-09-14

The current manuscript is being finalized for author review/pre-submission to Springer Nature's **International Journal of Information Security** under the title **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

## Current research claim

The paper asks whether matrix-element rotations previously reported for order-two Hill-derived constructions can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer in a byte-oriented SPN. The contribution is an algebraic and architectural extension: the order-eight formulation, its rotation identity and branch-number consequences, deterministic admissible-matrix setup, reproducible public scheduling, exact invertibility, and integration into a complete experimental SPN harness.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- For the defined clockwise rotation, `R(M) = M^T J`; every scheduled orientation is invertible when the seed is invertible.
- The four orientations require only two independent branch-number evaluations, `B(M)` and `B(M^T)`.
- Every scheduled orientation satisfies the local floor `B >= 4`. The threshold guarantees at least three active output bits for every one-bit input and is not claimed optimal.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally; it is selected for deterministic uniform coverage and reproducibility.
- The complete round function has an exact inverse.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The deterministic rejection filter is feasible for the reported prototype setup and represents master-key setup work rather than per-block encryption work.

## Retained bounded empirical checks

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

The avalanche statistic is used only as a bounded implementation sanity check for perturbation propagation in the completed harness.

## Principal limitations

- The candidate matrix layer is byte-local rather than cross-byte.
- No nontrivial multi-round active-S-box lower bound is established.
- No matched static-versus-rotor schedule comparison is part of this construction-feasibility paper.

## Revision 4

Revision 4 strengthens presentation rather than the scientific claim. It adopts the new title, makes the novelty statement explicit, defines `Hill-derived`, explains the `B >= 4` threshold and schedule choice, clarifies setup amortization, tightens avalanche interpretation, strengthens closure against the Section 1 construction criteria, and removes some repeated disclaimer language. Scientific results, numerical values, test vectors, figures, and bibliography are unchanged.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and machine-readable construction-verification datasets. The complete Springer Nature / IJIS manuscript package and cover letter are maintained separately as author-side submission artifacts.

See `docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` and `docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the current status and evidentiary chain.
