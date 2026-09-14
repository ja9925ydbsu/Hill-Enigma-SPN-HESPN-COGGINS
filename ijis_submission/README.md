# IJIS submission preparation

Current manuscript title:

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target journal: Springer Nature, **International Journal of Information Security**.

Current author-review version: **IJIS Revision 6, 14 September 2026**.

Revision 6 is a focused positioning pass over Revision 5. The scientific results, numerical values, reference vectors, figures, and bibliography entries are unchanged.

## Reviewer-facing clarification in Revision 6

A compact comparison table has been added near the end of the Introduction. It compares the present framework only with the three directly cited antecedent constructions already used in the manuscript's research-lineage discussion. The table records matrix-element rotation, order-eight rotation, the orientation identity, the explicit admissible-family criterion, SPN realization, the rotor-scheduled SPN linear layer, and the formal schedule-balance result.

The caption explicitly states that the table is a positioning summary of those cited constructions and **not a claim of priority over the broader literature**.

Revision 6 retains the Revision 5 clarifications:

- the contribution is framed as a coherent construction framework rather than as any one isolated mechanism;
- schedule balance is formalized as a proposition, with every labeled pair `(S_j, R^k)` occurring exactly four times over the sixteen rounds;
- rotation orbits can in principle have size 1, 2, or 4, while all 16 reference seeds have orbit size four;
- deterministic rejection sampling is treated as a central admissible-family construction step;
- `B >= 4` remains a byte-local GF(2) criterion, is feasible under the reported setup audit, and is not claimed optimal;
- the plaintext-avalanche experiment remains a bounded implementation sanity check, not a security bound; and
- the manuscript does not claim that rotor scheduling is superior to a static orientation or that HESPN is deployment-ready.

The author-side IJIS package uses Springer two-column LaTeX and includes the compiled manuscript, bibliography, vector figures, cover letter, revision notes, reproducibility manifest, and checksums. Those binary submission artifacts are maintained separately from this public software repository.

See `../docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` for the current status and `../docs/REPRODUCIBILITY_IJIS_2026_09_14.md` for the public reproducibility chain.
