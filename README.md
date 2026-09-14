# Hill-Enigma-SPN (HESPN)

This repository supports the construction study **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

As of 14 September 2026, the IJIS-facing manuscript is at Revision 6 for author review/pre-submission finalization for Springer Nature's **International Journal of Information Security**. HESPN is the experimental harness used to answer a focused construction-feasibility question: can matrix-element rotations previously reported for order-two Hill-derived constructions be extended to order eight and used as a reversible, scheduled byte-local linear layer in a substitution-permutation network?

In this project, *Hill-derived* denotes the use of invertible matrix-based linear transformations whose construction lineage originates in Hill-cipher methodology; the term does not imply reliance on the security properties of the classical Hill cipher.

## Coherent construction framework

The manuscript's contribution is the combination of five mutually supporting components rather than any one isolated mechanism:

1. an explicit order-eight matrix-element rotation at byte granularity;
2. the orientation identity `R(M) = M^T J`;
3. reduction of four apparent orientation branch checks to the two independent values `B(M)` and `B(M^T)`;
4. deterministic construction and verification of admissible matrix families; and
5. balanced public scheduling and reversible integration into a complete 16-round SPN harness.

Revision 6 adds a compact manuscript comparison table that positions this integrated framework only against the three directly cited antecedent constructions used in the Introduction. The table is explicitly a lineage summary rather than a priority claim over the broader literature.

The admissible-family component requires invertibility and a local branch-number floor `B >= 4` for every scheduled orientation. The threshold guarantees at least three active output bits for every one-bit input, is feasible under the reported rejection audit, and is not claimed optimal.

The public schedule is formalized by a balance proposition: for every seed position `j` and orientation index `k`, the labeled pair `(S_j, R^k)` occurs in exactly four of the sixteen rounds. Thus all 64 labeled seed-orientation pairs occur exactly four times across the 256 byte-matrix applications. This balance is a construction property, not evidence of a security gain.

Because the rotation has order four, shorter matrix orbits are possible in principle when a matrix is invariant under one or more nontrivial powers of the rotation. The reference family contains no such degeneracy: all 16 accepted seeds have orbit size four, giving 64 distinct oriented matrices.

For the reference configuration, all 64 oriented matrices have branch number 4. Across the 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. At sixteen rounds, the plaintext-avalanche integration run has mean ciphertext Hamming distance 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187]. The avalanche statistic is used only as a whole-harness implementation sanity check, not as evidence of differential or linear resistance.

## Claim boundary

HESPN's `B >= 4` guarantee is **per byte over GF(2)**. It is not a cross-byte MDS guarantee over GF(2^8), a wide-trail bound, or a lower bound on multi-round active S-boxes. Comparative schedule cryptanalysis, optimized differential and linear trails, boomerang/rectangle analysis, related-key analysis, exact weight-one recurrence, and broader cross-byte studies are separate research questions.

See `docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` for the current Revision 6 status, `docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the construction-level reproducibility chain, and `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` for the boundary around historical or separate analyses.

The complete journal submission package, including the compiled manuscript and cover letter, is maintained separately as an author-side submission artifact.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
