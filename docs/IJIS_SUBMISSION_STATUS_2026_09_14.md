# IJIS submission status - 14 September 2026

## Manuscript

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target: Springer Nature, **International Journal of Information Security**.

Revision 4 is a presentation-strengthening pass over Revision 3. It changes the title and sharpens the novelty statement and design rationale without changing the HESPN construction, numerical results, test vectors, figures, or bibliography.

## Current research claim

The paper asks whether matrix-element rotation previously reported for order-two Hill-derived constructions can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer at byte granularity inside an experimental SPN. The contribution is an algebraic and architectural extension: an explicit order-eight binary formulation, the identity `R(M) = M^T J` and its branch-number consequences, deterministic admissible-matrix setup, a reproducible public schedule, exact invertibility, and integration into a complete 16-round harness.

`Hill-derived` refers to matrix-based linear transformations whose construction lineage originates in Hill-cipher methodology; the term does not imply reliance on the security properties of the classical Hill cipher.

## Design-rationale clarifications

- The local `B >= 4` threshold guarantees at least three active output bits for every one-bit input and is feasible under the reported rejection audit. It is a concrete construction criterion and is not claimed optimal.
- The public schedule was selected because it guarantees deterministic, uniform coverage of all labeled seed-orientation pairs while remaining simple to specify and reproduce. It was not selected on the basis of a demonstrated cryptanalytic advantage.
- Rejection sampling is performed when the seed family is derived from a master key. Accepted seeds and orientations can then be reused, so this is a key-setup cost rather than a per-block encryption cost. No optimized setup-time or throughput claim is made.
- The 5,000-pair plaintext-avalanche experiment is a bounded implementation sanity check that tests whether one-bit perturbations are obviously trapped by the assembled implementation and whether large-scale output propagation occurs at the tested scale. It is not a differential or linear security bound.

## Technical claim boundary

The reported `B >= 4` guarantee is local to an 8-bit matrix over GF(2). It is not a cross-byte MDS guarantee, a wide-trail bound, a nontrivial multi-round active-S-box lower bound, a maximum differential probability bound, or a maximum linear correlation bound.

For the defined clockwise rotation, `R(M) = M^T J`, where `J` is the reversal permutation matrix. Rotation therefore preserves invertibility. The four orientations realize only the two independent local branch-number values `B(M)` and `B(M^T)`.

Mechanism-level differential, linear, boomerang, related-key, active-S-box, matched-schedule, and broader cross-byte analyses remain separate cryptanalytic questions and are not part of the IJIS evidentiary chain.

## Retained bounded verification

1. Exact local one-bit spreading across the 64 oriented reference matrices: 512 exact matrix applications, output Hamming weight 3 through 8, mean 4.5390625.
2. A 5,000-pair plaintext-avalanche integration check. At 16 rounds the mean ciphertext Hamming distance is 63.9664 bits with 95% CI [63.81093, 64.12187].
3. Reference vectors and decryption checks that fix bit packing, round order, matrix application, substitution, routing, and the complete 16-round mapping.

## Revision 4 editorial changes

- New title emphasizing the order-eight construction and validation contribution.
- Explicit novelty paragraph in Section 1.3 without an unsupported priority claim such as "first."
- One-sentence definition of `Hill-derived`.
- Rationale for the `B >= 4` threshold, schedule selection, and setup amortization.
- Tighter avalanche language and stronger closure against the construction criteria stated in Section 1.1.
- Reduced repetitive disclaimer language while preserving the full claim boundary in the abstract, branch-number discussion, avalanche section, limitations, and conclusion.
- No broad comparison table was added because binary yes/no entries could mischaracterize classical Hill and related constructions.

## Repository and submission artifacts

The IJIS-facing branch remains `ijis-submission-2026-09-09`. Protected `main` is not changed by this synchronization.

The complete journal submission package and cover letter are maintained separately as author-side artifacts. The public repository retains code, machine-readable verification data, and scope documentation. See `docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the current evidentiary chain and `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` for older analyses retained for provenance.
