# Project status: Cryptologia submission preparation

Updated: 2026-09-15

The current manuscript is being prepared for submission to Taylor & Francis **Cryptologia** under the title **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

The journal transition is a submission-format repackaging of the finalized HESPN Revision 6 scientific content. The construction, propositions, numerical results, test vectors, figures, and claim boundaries are unchanged.

## Current research claim

The paper asks whether matrix-element rotations previously reported for order-two Hill-derived constructions can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer in a byte-oriented SPN. The contribution is framed as a coherent construction framework comprising the order-eight rotation, orientation algebra `R(M) = M^T J`, two-value branch-number reduction, deterministic admissible-family construction, balanced public scheduling, and reversible SPN integration.

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

`active_sbox_bounds.csv` is explicitly outside this evidence chain. Its 5/25/30/50 active-S-box values come from `run_mds_rotor_study.py` for a separate 4 x 4 GF(2^8) MDS-rotor study and are not HESPN results.

## Cryptologia submission transition

The author-side package now contains a double-anonymized review manuscript, a full author-identified manuscript, a separate title page, separate figure files, a Cryptologia cover letter, and an anonymized HESPN-only reproducibility supplement. Citation presentation has been converted to author-year form for the Cryptologia review copy.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and machine-readable construction-verification datasets. The complete Cryptologia submission package is maintained separately as an author-side artifact.

See `docs/CRYPTOLOGIA_SUBMISSION_STATUS_2026_09_15.md`, `docs/REPRODUCIBILITY_CRYPTOLOGIA_2026_09_15.md`, and `docs/EXCLUDED_MDS_ROTOR_ARTIFACTS.md`.
