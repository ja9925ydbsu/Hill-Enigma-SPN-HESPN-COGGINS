# Hill Enigma Substitution-Permutation Network (HESPN)

This repository supports the construction and validation study **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**, prepared for submission to *Cryptologia*.

## What HESPN means

**HESPN** is the acronym for **Hill Enigma Substitution-Permutation Network**.

- **Hill** identifies the matrix-cipher lineage of the linear layer.
- **Enigma** refers only to the public stepping inspiration used to move matrix entries through successive geometric orientations according to a round-and-position schedule.
- **Substitution-Permutation Network (SPN)** identifies the experimental architecture in which the candidate linear layer is exercised.

The Enigma analogy is deliberately narrow. HESPN has no historical Enigma reflector, no Enigma rotor wiring, and no self-inverse signal path.

## Research question and significance

The present work establishes a construction and validation framework around a deliberately limited question: can previously reported matrix-element rotations be extended to an order-eight binary family, filtered for explicit local properties, scheduled reproducibly, inverted, and used as the linear mix layer of a complete experimental SPN?

The significance of the present work is not that an order-eight rotor schedule is shown to improve security. Rather, the significance is that a previously published order-two mechanism is shown to admit a mathematically consistent byte-scale realization together with explicit admissibility conditions, reproducible scheduling, and reversible SPN integration. These properties establish a common framework against which future comparative and cryptanalytic studies may be posed.

HESPN is a research harness for that construction and validation question. It is not presented as a deployment-ready cipher, a replacement for AES or another standardized primitive, or evidence that a public orientation schedule is more secure than a static matrix layer.

## Separate orientation-scheduling study

The comparative question has not been left unexamined. The limits of public orientation scheduling in the byte-local setting have been investigated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**.

That study contains matched static-versus-scheduled controls, exact low-support transfer analysis, support-growth analysis, and the cross-byte boundary experiments. Its current code and results belong in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

Those analyses are not part of the evidentiary chain for the HESPN construction and validation framework.

## Construction and validation claims supported here

The current HESPN manuscript and repository support the following limited claims:

1. The order-eight matrix-element rotation is explicitly defined over the stated MSB-first representation.
2. Clockwise rotation satisfies `R(M) = M^T J`, so rotation preserves invertibility.
3. The four orientations reduce to two independent branch-number values, `B(M)` and `B(M^T)`.
4. Accepted seeds satisfy the stated local branch-number floor `B >= 4` for every scheduled orientation.
5. The public schedule uses every labeled seed-orientation pair equally across sixteen rounds.
6. Every round and the complete sixteen-round mapping are reversible.
7. Rejection sampling is feasible for the reported reference setup.
8. Reference vectors permit independent implementation checking.
9. Exact one-bit local spreading and a bounded plaintext-avalanche integration check provide implementation-level validation, not full-cipher security proofs.

For the reference configuration, all 64 oriented matrices have branch number 4. Across 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. In the bounded plaintext-avalanche check, the mean ciphertext Hamming distance at sixteen rounds is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

## Current files

- `hespn_reference.py` is the current executable reference implementation and test-vector generator.
- `hespn_test_vector_v4.py` is a compatibility entry point that re-exports the current reference implementation.
- `cryptologia_support/` contains construction-and-validation data and submission-aligned reproducibility notes.
- `legacy_hespn_v4/` preserves older HESPN-v4 diagnostic material for research provenance. These files are historical and are not current Cryptologia evidence.
- `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` explains the scope boundary and the September 2026 repository cleanup.

The public repository is intentionally not a mirror of the double-anonymous journal submission package. Author-identifying submission files, cover letters, and anonymous-review artifacts are maintained separately.

## Reproducibility boundary

The repository separates three kinds of evidence:

- **formal construction properties**, such as invertibility and the local branch-number floor;
- **implementation checks**, such as reference vectors, round-trip verification, and exact local profiling;
- **bounded empirical integration checks**, such as plaintext avalanche under the reference configuration.

None of these categories establishes a deployment security level or substitutes for full differential, linear, boomerang, related-key, slide, or other cryptanalysis.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
