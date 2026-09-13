# Project status: IJIS Revision 3

Updated: 2026-09-13

The current manuscript is being finalized for author review/pre-submission to Springer Nature's **International Journal of Information Security** under the title **Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**.

## Current research claim

The paper asks whether previously reported Hill-matrix element rotations can be extended from order two to order eight and used as a reversible, locally diffusion-bounded linear layer in a byte-oriented SPN. The order-eight step is architecturally significant because an 8 x 8 binary matrix acts directly on one byte, allowing the mechanism to be scheduled at the same granularity as an 8-bit substitution layer.

The paper focuses on construction feasibility: it establishes the rotation algebra, deterministic admissible-matrix setup, public orientation schedule, exact invertibility, local branch-number floor, and integration into a complete experimental SPN harness. Mechanism-level differential, linear, boomerang, related-key, active-S-box, matched-schedule, and cross-byte analyses are separate from the IJIS construction claim.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- For the defined clockwise rotation, `R(M) = M^T J`; every scheduled orientation is therefore invertible when the seed is invertible.
- The four orientations require only two independent branch-number evaluations, `B(M)` and `B(M^T)`.
- Every scheduled orientation satisfies the local floor `B >= 4`.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- The complete round function has an exact inverse.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The deterministic rejection filter is feasible for the reported prototype setup.

## Retained bounded empirical checks

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

The avalanche statistic verifies propagation within the completed implementation; it is not used as evidence of differential or linear resistance.

## Principal limitations

- The candidate matrix layer is byte-local rather than cross-byte.
- No nontrivial multi-round active-S-box lower bound is established.
- No matched static-versus-rotor schedule comparison is part of this construction-feasibility paper.

## Revision 3

Revision 3 is an editorial/documentation finalization of IJIS Revision 2. The scientific results, numerical values, test vectors, figures, and bibliography are unchanged. First-person/self-referential language was removed from the technical narrative, and time-dependent "future work" wording was replaced by explicit scope boundaries.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and the machine-readable construction-verification datasets. The complete Springer Nature / IJIS manuscript package and cover letter are maintained separately as author-side submission artifacts and are not mirrored in the public code repository by default.

See `docs/IJIS_SUBMISSION_STATUS_2026_09_13.md` and `docs/REPRODUCIBILITY_IJIS_2026_09_13.md` for the current status and evidentiary chain.
