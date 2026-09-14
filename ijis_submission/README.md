# IJIS submission preparation

Current manuscript title:

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target journal: Springer Nature, **International Journal of Information Security**.

Current author-review version: **IJIS Revision 5, 14 September 2026**.

Revision 5 is a focused framing and mathematical-clarification pass over Revision 4. The scientific results, numerical values, reference vectors, figures, and bibliography entries are unchanged.

## Reviewer-facing clarifications in Revision 5

- The contribution is explicitly framed as a coherent construction framework rather than as any one isolated mechanism: order-eight rotation, orientation algebra, two-value branch-number reduction, deterministic admissible-family construction, balanced scheduling, and reversible SPN integration.
- Schedule balance is formalized as a proposition: every labeled pair `(S_j, R^k)` occurs exactly four times over the sixteen rounds.
- Rotation orbits can in principle have size 1, 2, or 4 because `R^4` is the identity. The reference family has no shorter-orbit degeneracy; all 16 accepted seeds have orbit size four.
- The admissible-family construction is treated as a central contribution: deterministic rejection sampling turns the algebraic requirements into a reproducible family-selection procedure whose setup behavior is measured.
- `B >= 4` remains a byte-local GF(2) criterion, is feasible under the reported setup audit, and is not claimed optimal.
- The plaintext-avalanche experiment remains a bounded implementation sanity check, not a security bound.
- The manuscript does not claim that rotor scheduling is superior to a static orientation or that HESPN is deployment-ready.

The author-side IJIS package uses Springer two-column LaTeX and includes the compiled manuscript, bibliography, vector figures, cover letter, revision notes, reproducibility manifest, and checksums. Those binary submission artifacts are maintained separately from this public software repository.

See `../docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` for the current status and `../docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the public reproducibility chain.
