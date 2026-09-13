# IJIS submission status - 13 September 2026

## Manuscript

**Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**

Target: Springer Nature, **International Journal of Information Security**.

Revision 3 is a final editorial and documentation synchronization of the IJIS construction-feasibility manuscript. It does not change the HESPN construction, any numerical result, the reference vectors, figures, or the bibliography.

## Current research claim

The paper asks whether the matrix-element rotation mechanism previously reported for order-two Hill-derived maps can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer at byte granularity inside an experimental SPN. The manuscript establishes the order-eight rotation algebra, deterministic admissible-matrix setup, public schedule, exact invertibility, local branch-number floor, and integration into a complete 16-round harness.

The paper is intentionally a construction study. Mechanism-level differential, linear, boomerang, related-key, active-S-box, and matched-schedule analyses are separate cryptanalytic questions and are not part of the IJIS evidentiary chain.

## Technical claim boundary

The reported `B >= 4` guarantee is local to an 8-bit matrix over GF(2). It is not a cross-byte MDS guarantee, a wide-trail bound, a nontrivial multi-round active-S-box lower bound, a maximum differential probability bound, or a maximum linear correlation bound.

Branch-number admissibility is evaluated from the defining condition, and exact branch numbers are obtained from the full minimum over all nonzero byte inputs. The later one-bit spreading profile is descriptive and is not used as a proof of branch number.

For the defined clockwise rotation,

`R(M) = M^T J`,

where `J` is the reversal permutation matrix. Consequently rotation preserves invertibility. The four orientations realize only the two independent local branch-number values `B(M)` and `B(M^T)`. Repeated implementation checks over all orientations are defensive consistency checks, not additional mathematical assumptions.

## Retained bounded verification

The construction paper retains two bounded implementation checks in addition to algebraic and test-vector verification:

1. Exact local one-bit spreading across the 64 oriented reference matrices: 512 exact matrix applications, output Hamming weight 3 through 8, mean 4.5390625.
2. A 5,000-pair plaintext-avalanche integration check. At 16 rounds the mean ciphertext Hamming distance is 63.9664 bits with 95% CI [63.81093, 64.12187].

The avalanche statistic verifies propagation through the completed implementation; it is not evidence of differential or linear resistance and does not isolate an incremental effect caused by rotor scheduling.

## Revision 3 editorial changes

- Removed first-person and self-referential phrasing from the scientific narrative.
- Recast references to separate cryptanalytic work as scope boundaries rather than as time-dependent "future work."
- Synchronized cover-letter date and author-name punctuation.
- Updated repository-facing IJIS metadata and status documents while preserving historical CiC materials and older experiments for provenance.

## Repository and submission artifacts

The IJIS-facing branch is `ijis-submission-2026-09-09`. Protected `main` is not changed by this documentation finalization.

The complete journal submission source package and cover letter are maintained separately as author-side artifacts. The public repository retains code, machine-readable verification data, and scope documentation. See `docs/REPRODUCIBILITY_IJIS_2026_09_13.md` for the current evidentiary chain and `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` for older analyses that remain available only for provenance.
