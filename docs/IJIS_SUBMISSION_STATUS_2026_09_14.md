# IJIS submission status - 14 September 2026

## Manuscript

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target: Springer Nature, **International Journal of Information Security**.

Revision 5 is a focused framing and mathematical-clarification pass over Revision 4. It does not change the HESPN construction, numerical results, test vectors, figures, or bibliography.

## Coherent construction framework

The manuscript now states explicitly that its contribution is the integrated framework formed by:

1. order-eight matrix-element rotation at byte granularity;
2. the orientation identity `R(M) = M^T J`;
3. reduction of four apparent orientation branch checks to the two independent values `B(M)` and `B(M^T)`;
4. deterministic admissible-family construction and verification; and
5. balanced public scheduling with reversible SPN integration.

The contribution is therefore not presented as any one isolated mechanism. The pieces are mutually supporting: the order-eight formulation creates byte-scale applicability, the orientation algebra supplies the invariants needed for safe scheduling, the branch identities make admissibility tractable, the deterministic filter constructs reproducible families, and the SPN harness demonstrates that the resulting family can be scheduled and inverted consistently in an iterated architecture.

## New Revision 5 clarifications

- **Schedule balance is formalized.** For every byte position `j` and orientation index `k`, the labeled pair `(S_j, R^k)` occurs in exactly four of the sixteen rounds. Hence all 64 labeled seed-orientation pairs occur exactly four times across the 256 byte-matrix applications.
- **Rotation-orbit degeneracy is clarified.** Because `R^4` is the identity, orbit sizes can be 1, 2, or 4. Shorter orbits occur when a matrix is invariant under `R` or `R^2`. None occur in the reference family: all 16 accepted seeds have orbit size four.
- **Admissible-family construction is elevated in the novelty framing.** Deterministic rejection sampling converts the algebraic constraints into a reproducible family-selection procedure whose setup cost is measured by the reported audit.

## Technical claim boundary

The local `B >= 4` threshold guarantees at least three active output bits for every one-bit input and is feasible under the reported rejection audit. It is not claimed optimal. The guarantee is local to one byte over GF(2), not a cross-byte MDS guarantee, a wide-trail bound, a multi-round active-S-box lower bound, a maximum differential probability bound, or a maximum linear correlation bound.

The 5,000-pair plaintext-avalanche experiment remains a bounded implementation sanity check. It is not evidence of differential or linear resistance and does not establish a schedule advantage.

## Retained bounded verification

1. Exact local one-bit spreading across the 64 oriented reference matrices: 512 exact matrix applications, output Hamming weight 3 through 8, mean 4.5390625.
2. A 5,000-pair plaintext-avalanche integration check. At 16 rounds the mean ciphertext Hamming distance is 63.9664 bits with 95% CI [63.81093, 64.12187].
3. Reference vectors and decryption checks that fix bit packing, round order, matrix application, substitution, routing, and the complete 16-round mapping.

## Repository and submission artifacts

The IJIS-facing branch remains `ijis-submission-2026-09-09`. Protected `main` is not changed by this synchronization.

The complete journal submission package and cover letter are maintained separately as author-side artifacts. The public repository retains code, machine-readable verification data, and scope documentation. See `docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the current evidentiary chain and `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` for older analyses retained for provenance.
