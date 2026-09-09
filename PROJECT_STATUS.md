# Project status: IJIS submission preparation

Updated: 2026-09-09

The current manuscript is being prepared for submission to Springer Nature's **International Journal of Information Security** under the approved title **Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**.

## Current research claim

The paper asks whether previously reported Hill-matrix element rotations can be extended to order eight and used as a reversible, locally diffusion-bounded linear layer in an experimental SPN. It does not propose HESPN as a deployment-ready cipher and does not claim that public rotor scheduling provides a security advantage over a static orientation.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- Every scheduled orientation is invertible.
- The four orientations require only two independent branch-number evaluations, B(M) and B(M^T).
- Every scheduled orientation satisfies the local floor B >= 4.
- Branch-number admissibility is evaluated from the defining condition; the later one-bit profile is not used as a branch-number proof.
- Candidate generation includes an explicit deterministic counter, so rejection produces a defined new hash input.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- The complete round function has an exact inverse.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.

## Claim boundary emphasized for IJIS

The B >= 4 result is a **byte-local GF(2) branch-number guarantee**. It is not a cross-byte MDS result over GF(2^8), a wide-trail bound, or a nontrivial lower bound on the number of active S-boxes across multiple rounds. No maximum differential probability or maximum linear correlation bound is inferred from this local criterion.

The manuscript therefore keeps active-S-box/MILP analysis, optimized differential and linear trail searches, boomerang/rectangle analysis, related-key analysis, and matched static-versus-scheduled comparisons outside the present construction-feasibility claim. These are identified as separate cryptanalytic questions rather than silently replaced by empirical proxies.

## Retained bounded integration checks

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration run using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

These checks do not establish full-cipher security or isolate a benefit caused by orientation scheduling.

## Public repository versus journal submission package

The public repository contains executable research code, historical reproducibility assets, scope documentation, and the machine-readable verification datasets developed during the final Revision 5 preparation. The complete Springer Nature / IJIS manuscript package and cover letter are maintained separately as author-side submission artifacts.

The substantive manuscript basis remains the final Revision 5 construction-feasibility paper dated 28 August 2026. The IJIS work is a journal-format conversion plus reviewer-facing clarification of the specification and claim boundary, not a return to the broader July HESPN manuscript.
