# IJIS submission status — 9 September 2026

## Manuscript

**Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**

Target: Springer Nature, **International Journal of Information Security**.

The manuscript is based on the final Revision 5 construction-feasibility paper. The journal conversion preserves the narrow research question and does not reinstate the broader empirical-security claims from earlier HESPN drafts.

## Technical claim boundary

The reported branch-number guarantee B >= 4 is local to an 8-bit matrix over GF(2). It is not a cross-byte MDS guarantee, a wide-trail bound, or a nontrivial multi-round active-S-box lower bound. The manuscript does not derive maximum differential probability or maximum linear correlation from this local result.

Branch-number admissibility is checked from the defining condition, and exact branch numbers are obtained from the full minimum over nonzero byte inputs. The later weight-one spreading profile is descriptive and is not used as proof of branch number.

Seed rejection is deterministic. Candidate rows are derived from SHA-256 using the master key, the `MATRIX` domain label, the byte index, and an explicit counter. Rejection increments the counter, producing a defined new hash input.

## Relation to the MD-Hill-SPN specification critique

The published critique of MD-Hill-SPN concerns a different construction using Cauchy matrices over GF(2^8). HESPN's byte-local matrices are binary 8 x 8 matrices and do not use that Cauchy construction. The critique is nevertheless treated as a specification-quality checklist: deterministic rejection is explicit, invertibility is checked, branch number is evaluated from its definition, and weight-one observations are not confused with a proof of branch number.

## Remaining cryptanalytic questions

Active-S-box/MILP bounds, optimized differential and linear trail searches, boomerang/rectangle analysis, related-key analysis, and matched static-versus-scheduled comparisons remain outside this construction-feasibility paper. The manuscript states those exclusions directly so the local B >= 4 guarantee cannot reasonably be read as a surrogate for a wide-trail result.

## Repository and submission artifacts

This branch records IJIS-facing status and scope documentation. The complete submission package, including the compiled manuscript, figures, bibliography, and cover letter, is maintained separately as an author-side artifact rather than mirrored as a binary journal archive in the public code repository.
