# Project status: IJIS Revision 5

Updated: 2026-09-14

The current manuscript is being finalized for author review/pre-submission to Springer Nature's **International Journal of Information Security** under the title **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

## Current research claim

The paper asks whether matrix-element rotations previously reported for order-two Hill-derived constructions can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer in a byte-oriented SPN. Revision 5 frames the contribution explicitly as a coherent construction framework comprising the order-eight rotation, orientation algebra `R(M) = M^T J`, two-value branch-number reduction, deterministic admissible-family construction, balanced public scheduling, and reversible SPN integration.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- The four orientations require only two independent branch-number evaluations, `B(M)` and `B(M^T)`.
- Every scheduled orientation is invertible and satisfies the local floor `B >= 4`.
- The public schedule has an explicit balance proposition: each labeled pair `(S_j, R^k)` occurs exactly four times in sixteen rounds.
- The deterministic rejection filter constructs reproducible admissible families and is feasible for the reported prototype setup.
- Every round and the complete sixteen-round mapping are reversible.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.

Because the rotation has order four, matrix orbits can in principle have size 1, 2, or 4. The 16 accepted seeds in the reference family all have orbit size four, giving 64 distinct oriented matrices.

## Retained bounded empirical checks

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

The avalanche statistic is used only as a bounded implementation sanity check for perturbation propagation in the completed harness.

## Principal limitations

- The candidate matrix layer is byte-local rather than cross-byte.
- No nontrivial multi-round active-S-box lower bound is established.
- No matched static-versus-rotor schedule comparison is part of this construction-feasibility paper.

## Revision 5

Revision 5 is a focused framing and mathematical-clarification pass over Revision 4. It formalizes schedule balance as a proposition, clarifies that shorter rotational orbits are possible in principle but absent from the reference family, and emphasizes deterministic admissible-family construction as one of the central elements of the contribution. Scientific results, numerical values, test vectors, figures, and bibliography remain unchanged.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and machine-readable construction-verification datasets. The complete Springer Nature / IJIS manuscript package and cover letter are maintained separately as author-side submission artifacts.

See `docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` and `docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the current status and evidentiary chain.
