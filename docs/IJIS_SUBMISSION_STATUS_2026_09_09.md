# IJIS submission status — 9 September 2026

## Manuscript

**Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**

Target: Springer Nature, **International Journal of Information Security**.

The manuscript is based on the final Revision 5 construction-feasibility paper. The IJIS revision now gives a stronger architectural rationale for the order-eight extension: an 8 x 8 binary matrix acts directly on one byte, so extending matrix-element rotation from order two to order eight is a necessary prerequisite for testing the mechanism at the native granularity of a byte-oriented SPN.

The paper focuses on construction feasibility. It establishes a reversible rotor-scheduled Hill-derived linear layer, its algebraic properties, deterministic setup, and its integration into a complete SPN harness. Detailed differential, linear, boomerang, related-key, active-S-box, and wide-trail analyses remain follow-on work.

## Technical claim boundary

The reported branch-number guarantee B >= 4 is local to an 8-bit matrix over GF(2). It is not a cross-byte MDS guarantee, a wide-trail bound, or a nontrivial multi-round active-S-box lower bound. The manuscript does not derive maximum differential probability or maximum linear correlation from this local result.

Branch-number admissibility is checked from the defining condition, and exact branch numbers are obtained from the full minimum over nonzero byte inputs. For any weight-one input, B(M) >= 4 implies output Hamming weight at least three. The later weight-one spreading profile is descriptive and is not used as proof of branch number.

Seed rejection is deterministic. Candidate rows are derived from SHA-256 using the master key, the `MATRIX` domain label, the byte index, and an explicit counter. Rejection increments the counter, producing a defined new hash input.

## Avalanche interpretation

The retained 5,000-pair plaintext-avalanche experiment is an implementation-propagation diagnostic for the completed harness. It is not interpreted as evidence of resistance to differential or linear cryptanalysis and does not isolate the incremental contribution of the orientation schedule.

## Principal limitations

1. The matrix layer is byte-local rather than cross-byte.
2. No nontrivial multi-round active-S-box bound is derived.
3. No matched static-versus-rotor schedule comparison is included in this construction-feasibility paper.

An actual schedule ablation would directly address the third point, but adding such results here would change the paper from a construction study into a mechanism-comparison study. The current IJIS revision therefore keeps that analysis separate.

## Relation to the MD-Hill-SPN specification critique

The published critique of MD-Hill-SPN concerns a different construction using Cauchy matrices over GF(2^8). HESPN's byte-local matrices are binary 8 x 8 matrices and do not use that Cauchy construction. The critique is nevertheless treated as a specification-quality checklist: deterministic rejection is explicit, invertibility is checked, branch number is evaluated from its definition, and weight-one observations are not confused with a proof of branch number.

## Figure readability

Figure 1 has been cropped to the core harness and enlarged within its column, with the removed explanatory side and bottom text moved into the caption. Figure 2 has been promoted to a two-column figure so its round-level and rotor-construction labels remain readable in the Springer layout.

## Repository and submission artifacts

This branch records IJIS-facing status and scope documentation. The complete submission package, including the compiled manuscript, revised figures, bibliography, and cover letter, is maintained separately as an author-side artifact rather than mirrored as a binary journal archive in the public code repository.
