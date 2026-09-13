# Hill-Enigma-SPN (HESPN)

This repository supports the construction study currently titled **Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**.

As of 13 September 2026, the IJIS-facing manuscript is at Revision 3 for author review/pre-submission finalization for Springer Nature's **International Journal of Information Security**. HESPN is the experimental harness used to answer a focused construction-feasibility question: can matrix-element rotations previously reported for Hill-cipher variants be extended to order eight, scheduled, inverted, and used as a byte-local linear layer in a substitution-permutation network?

Order eight is an important architectural step because an 8 x 8 binary matrix acts directly on the eight bits of one byte. Extending matrix-element rotation from order two to order eight therefore places the mechanism at the native granularity of a byte-oriented SPN and makes it possible to evaluate the construction inside a complete iterated round structure.

## Construction studied

The candidate layer uses sixteen key-derived 8 x 8 binary seed matrices over GF(2). Each seed is accepted only after deterministic candidate generation and verification of invertibility and the required local branch-number floor. A public four-orientation schedule selects a rotated matrix by round and byte position. A fixed, well-characterized 8-bit S-box and explicit state-motion steps provide the surrounding SPN harness.

The current manuscript supports these construction claims:

1. For the defined clockwise rotation, `R(M) = M^T J`; matrix rotation therefore preserves invertibility.
2. The four orientations reduce to two independent local branch-number values, `B(M)` and `B(M^T)`.
3. Accepted seeds satisfy a local branch-number floor `B >= 4` for every scheduled orientation.
4. The public schedule uses every labeled seed-orientation pair equally across sixteen rounds.
5. Every round and the complete sixteen-round mapping are reversible.
6. The deterministic rejection filter is feasible for the reported reference setup.
7. Reference vectors permit independent implementation checking.
8. Exact local one-bit spreading and a 5,000-pair plaintext-avalanche experiment verify local behavior and propagation through the completed implementation at the stated scale.

For the reference configuration, all 64 oriented matrices have branch number 4. Across the 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. At sixteen rounds, the retained plaintext-avalanche integration run has mean ciphertext Hamming distance 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187]. Avalanche statistics are used as an implementation-propagation diagnostic rather than as evidence of differential or linear resistance.

## Branch-number granularity

HESPN's `B >= 4` guarantee is **per byte over GF(2)**. It is not a cross-byte MDS guarantee over GF(2^8), a wide-trail bound, or a lower bound on multi-round active S-boxes. Branch-number admissibility is checked from the defining condition over the relevant nonzero byte inputs; the later weight-one spreading profile is not used as a proof of branch number.

The deterministic candidate procedure includes an explicit counter in the hash input. A rejected candidate therefore changes the next candidate deterministically.

## Separate cryptanalytic analyses

The IJIS construction paper does not make mechanism-level security claims about the public schedule. Active-S-box bounds, optimized differential and linear trails, matched static-versus-scheduled controls, boomerang/rectangle analysis, related-key analysis, exact weight-one recurrence, and broader cross-byte studies are separate cryptanalytic questions. Some historical or separate-analysis files remain in this repository for provenance; their presence does not enlarge the IJIS evidentiary chain.

See `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` for that boundary and `docs/REPRODUCIBILITY_IJIS_2026_09_13.md` for the construction-level reproducibility chain.

## Repository layout

- `docs/IJIS_SUBMISSION_STATUS_2026_09_13.md` records the current IJIS Revision 3 status and claim boundary.
- `docs/REPRODUCIBILITY_IJIS_2026_09_13.md` identifies the public materials that support the IJIS construction claims.
- `ijis_submission/README.md` describes the IJIS-facing author-side manuscript package and what is intentionally not mirrored in this public code repository.
- `cic_submission/` is retained as a historical support snapshot; its two machine-readable construction metrics are reused unchanged by the IJIS manuscript for provenance.
- Root-level scripts and older analysis assets are retained for reproducibility and are scoped by the documentation above.

The complete journal submission package, including the compiled manuscript and cover letter, is maintained separately as an author-side submission artifact.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
