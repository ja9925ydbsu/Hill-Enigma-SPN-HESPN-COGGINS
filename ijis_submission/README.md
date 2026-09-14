# IJIS submission preparation

Current manuscript title:

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target journal: Springer Nature, **International Journal of Information Security**.

Current author-review version: **IJIS Revision 4, 14 September 2026**.

Revision 4 is a presentation-strengthening pass over Revision 3. The scientific results, numerical values, reference vectors, figures, and bibliography entries are unchanged. The revision sharpens the novelty statement, defines `Hill-derived`, explains the `B >= 4` threshold and schedule choice, clarifies setup amortization, tightens the avalanche interpretation, strengthens closure against the Section 1 construction criteria, and reduces repeated scope disclaimers.

The author-side IJIS package uses Springer two-column LaTeX and includes the compiled manuscript, bibliography, vector figures, cover letter, revision notes, reproducibility manifest, and checksums. Those binary submission artifacts are maintained separately from this public software repository.

## Reviewer-facing technical clarifications in Revision 4

- The contribution is explicitly framed as an algebraic and architectural extension from order-two matrix-element rotation to an order-eight byte-scale scheduled SPN linear layer, not as a new nonlinear primitive or a cryptanalytic security result.
- `Hill-derived` refers to matrix-based linear transformations whose lineage originates in Hill-cipher methodology; it does not imply reliance on classical Hill-cipher security.
- `B >= 4` is a byte-local GF(2) branch-number guarantee only. The threshold guarantees at least three active output bits for a one-bit input, is feasible under the reported setup audit, and is not claimed optimal.
- `R(M) = M^T J`, so the defined matrix rotation preserves invertibility.
- Candidate rejection is deterministic and includes an explicit counter in the SHA-256 input.
- Rejection sampling is master-key setup work rather than a per-block encryption cost in the reference construction; no optimized setup-time claim is made.
- The public schedule was chosen for deterministic uniform coverage and reproducibility, not on the basis of a demonstrated cryptanalytic advantage.
- The 5,000-pair plaintext-avalanche experiment is a bounded whole-harness implementation sanity check, not a security bound.
- The manuscript does not claim that rotor scheduling is superior to a static orientation or that HESPN is deployment-ready.

See `../docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` for the current status and `../docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the public reproducibility chain.
