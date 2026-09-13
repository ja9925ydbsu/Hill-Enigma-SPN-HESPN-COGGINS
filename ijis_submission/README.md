# IJIS submission preparation

Current manuscript title:

**Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**

Target journal: Springer Nature, **International Journal of Information Security**.

Current author-review version: **IJIS Revision 3, 13 September 2026**.

Revision 3 is an editorial and documentation finalization of the Revision 2 construction-feasibility manuscript. Scientific results, numerical values, reference vectors, figures, and bibliography entries are unchanged. The technical narrative was made more objective and evergreen, and repository-facing documentation was synchronized with the IJIS claim boundary.

The author-side IJIS package uses Springer two-column LaTeX and includes the compiled manuscript, bibliography, vector figures, cover letter, revision notes, reproducibility manifest, and checksums. Those binary submission artifacts are maintained separately from this public software repository.

## Reviewer-facing technical clarifications retained in Revision 3

- `B >= 4` is a byte-local GF(2) branch-number guarantee only.
- It is not a cross-byte MDS guarantee, wide-trail bound, or multi-round active-S-box lower bound.
- Branch-number admissibility is checked from the defining condition rather than inferred from one-bit probes.
- `R(M) = M^T J`, so the defined matrix rotation preserves invertibility.
- The later exact one-bit spreading distribution is an implementation profile, not a proof of branch number.
- Candidate rejection is deterministic and includes an explicit counter in the SHA-256 input.
- The 5,000-pair plaintext-avalanche experiment is an integration sanity check, not a security bound.
- The manuscript does not claim that rotor scheduling is superior to a static orientation or that HESPN is deployment-ready.
- Mechanism-level comparative cryptanalysis is intentionally outside the construction paper's evidentiary scope.

See `../docs/IJIS_SUBMISSION_STATUS_2026_09_13.md` for the current status and `../docs/REPRODUCIBILITY_IJIS_2026_09_13.md` for the public reproducibility chain.
