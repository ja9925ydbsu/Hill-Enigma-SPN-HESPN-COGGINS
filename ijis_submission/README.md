# IJIS submission preparation

Current manuscript title:

**Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**

Target journal: Springer Nature, **International Journal of Information Security**.

The substantive manuscript basis is the final Revision 5 construction-feasibility paper. The author-side IJIS package has been converted to a Springer two-column LaTeX build and includes the compiled manuscript, bibliography, vector figures, and a new cover letter. Those binary submission artifacts are maintained separately from this public software repository.

## Reviewer-facing clarifications in the IJIS version

- B >= 4 is a byte-local GF(2) branch-number guarantee only.
- It is not a cross-byte MDS guarantee, wide-trail bound, or multi-round active-S-box lower bound.
- Branch-number admissibility is checked from the defining condition rather than inferred from one-bit probes.
- The later exact one-bit spreading distribution is an implementation profile, not a proof of branch number.
- Candidate rejection is deterministic and includes an explicit counter in the SHA-256 input.
- The 5,000-pair plaintext-avalanche experiment is an integration sanity check, not a security bound.
- The manuscript does not claim that rotor scheduling is superior to a static orientation or that HESPN is deployment-ready.

See `../docs/IJIS_SUBMISSION_STATUS_2026_09_09.md` for the full status note.
