# Hill-Enigma-SPN (HESPN)

This repository supports the construction study currently titled **Rotor-Scheduled Hill Matrices as a Linear Layer in an Experimental Substitution-Permutation Network**.

As of 9 September 2026, the manuscript is being prepared for submission to Springer Nature's **International Journal of Information Security**. HESPN is the experimental harness used to answer a focused construction-feasibility question: can matrix-element rotations previously reported for Hill-cipher variants be extended to order eight, scheduled, inverted, and used as a byte-local linear layer in a substitution-permutation network?

Order eight is an important architectural step because an 8 x 8 binary matrix acts directly on the eight bits of one byte. Extending matrix-element rotation from order two to order eight therefore places the mechanism at the native granularity of a byte-oriented SPN and makes it possible to evaluate the idea inside a complete iterated round structure. The manuscript establishes that construction first; detailed comparative cryptanalysis of the scheduling rule is a subsequent question.

## Construction studied

The candidate layer uses sixteen key-derived 8 x 8 binary seed matrices over GF(2). Each seed is accepted only after deterministic candidate generation and verification of invertibility and a local branch-number floor. A public four-orientation schedule selects a rotated matrix by round and byte position. A fixed, well-characterized 8-bit S-box and explicit state-motion steps provide the surrounding SPN harness.

The current manuscript supports these construction claims:

1. Matrix rotation preserves invertibility for the scheduled family.
2. The four orientations reduce to two independent branch-number values, B(M) and B(M^T).
3. Accepted seeds satisfy a local branch-number floor B >= 4 for every scheduled orientation.
4. The public schedule uses every labeled seed-orientation pair equally across sixteen rounds.
5. Every round and the complete sixteen-round mapping are reversible.
6. The rejection filter is feasible for the reported reference setup.
7. Reference vectors permit independent implementation checking.
8. Exact local one-bit spreading and a 5,000-pair plaintext-avalanche experiment verify local behavior and propagation through the completed implementation.

For the reference configuration, all 64 oriented matrices have branch number 4. Across the 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. At sixteen rounds, the retained plaintext-avalanche integration run has mean ciphertext Hamming distance 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187]. Avalanche statistics are used as an implementation-propagation diagnostic rather than as evidence of differential or linear resistance.

## Branch-number granularity

HESPN's B >= 4 guarantee is **per byte over GF(2)**. It is not a cross-byte MDS guarantee over GF(2^8), a wide-trail bound, or a lower bound on multi-round active S-boxes. Branch-number admissibility is checked from the defining condition over the relevant nonzero byte inputs; the later weight-one spreading profile is not used as a proof of branch number.

The deterministic candidate procedure includes an explicit counter in the hash input. A rejected candidate therefore changes the next candidate deterministically.

## Next cryptanalytic questions

The construction paper leaves several mechanism-level questions for follow-on analysis: nontrivial active-S-box bounds, optimized differential and linear trails, matched static-versus-scheduled controls, boomerang/rectangle analysis, related-key analysis, and broader slide/reflection analysis. These questions concern what security contribution, if any, follows from the public orientation schedule after the order-eight construction has been fixed and verified.

Older files covering broader HESPN experiments remain in the repository for historical reproducibility. They do not enlarge the evidentiary scope of the current construction paper. See `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md`.

## Repository layout

- `cic_submission/` retains the final Revision 5 verification notes and machine-readable data on which the current IJIS format conversion is based.
- `docs/IJIS_SUBMISSION_STATUS_2026_09_09.md` records the current IJIS target, approved title, and claim boundary.
- `ijis_submission/README.md` describes the author-side IJIS manuscript package and what is intentionally not mirrored in this public code repository.
- Root-level scripts and `legacy_hespn_v4/` preserve historical implementation and experimental assets.

The complete journal submission package, including the compiled manuscript and cover letter, is maintained separately as an author-side submission artifact.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
