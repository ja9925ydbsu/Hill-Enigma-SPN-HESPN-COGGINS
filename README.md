# Hill Enigma Substitution-Permutation Network (HESPN)

This repository supports the manuscript **Order-Eight Rotor-Scheduled Hill Matrices: Construction, Validation, and Diffusion Limits of a Byte-Local SPN Linear Layer**, prepared for submission to *Cryptologia*.

## Purpose

The purpose of the paper is to define and analyze the mechanism, not to claim security for HESPN as a cipher. The current manuscript therefore combines construction and implementation validation with a bounded analysis of where the byte-local diffusion argument stops providing cryptanalytic leverage.

## What HESPN means

**HESPN** is the acronym for **Hill Enigma Substitution-Permutation Network**.

- **Hill** identifies the matrix-cipher lineage of the linear layer.
- **Enigma** refers only to the public stepping inspiration used to move matrix entries through successive geometric orientations according to a round-and-position schedule.
- **Substitution-Permutation Network (SPN)** identifies the experimental architecture in which the candidate linear layer is exercised.

The Enigma analogy is deliberately narrow. HESPN has no historical Enigma reflector, no Enigma rotor wiring, and no self-inverse signal path.

## Research question and significance

The construction question is whether the previously reported matrix-element rotation mechanism can be extended from order two to an order-eight binary family, filtered for explicit local properties, scheduled reproducibly, inverted, and used as the linear mix layer of a complete experimental SPN.

The analytical question is where the resulting diffusion guarantees end. The current manuscript therefore also examines the linear equivalence of the scheduled byte matrix with the following S-box, the byte-level branch number of the composite linear map between successive S-box layers, one-active-S-box trails, and reduced-round fixed-key endpoint behavior.

The significance is not that an order-eight rotor schedule is shown to improve security. Rather, a previously published order-two mechanism is given a mathematically consistent byte-scale realization with explicit admissibility conditions, reproducible scheduling, reversible SPN integration, and an explicit account of its structural limits.

HESPN is a research harness. It is not presented as a deployment-ready cipher, a replacement for AES or another standardized primitive, or evidence that a public orientation schedule is more secure than a static matrix layer.

## Claims supported by the current manuscript and repository

The current HESPN manuscript and repository support the following bounded claims:

1. The order-eight matrix-element rotation is explicitly defined over the stated MSB-first representation.
2. Clockwise rotation satisfies `R(M) = M^T J`, so rotation preserves invertibility.
3. The four orientations reduce to two independent local branch-number values, `B(M)` and `B(M^T)`.
4. Accepted seeds satisfy the stated local branch-number floor `B >= 4` for every scheduled orientation in the reference configuration.
5. The public schedule uses every labeled seed-orientation pair equally across sixteen rounds.
6. Every round and the complete sixteen-round mapping are reversible.
7. For a scheduled byte matrix `M`, the composition `S o M` is linearly equivalent to `S`; the matrix therefore does not improve the S-box maximum differential probability or maximum absolute linear correlation.
8. The composite linear map between successive S-box layers has byte-level branch number 2. Consequently, the local `B >= 4` condition does not imply a nontrivial multi-round active-S-box lower bound.
9. For the reference key, one-active-S-box differential characteristics and linear trails exist for every round count from 1 through 16.
10. Reduced-round fixed-key endpoint measurements depart substantially from the corresponding best single-characteristic or single-trail products. These measurements show that those products are not security margins for the fixed-key construction; they do not establish a full-round distinguisher.
11. Reference vectors, exact local profiling, setup statistics, and a bounded plaintext-avalanche check provide implementation-level validation of the reported construction.

For the reference configuration, all 64 oriented matrices have branch number 4. Across 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. In the bounded plaintext-avalanche check, the mean ciphertext Hamming distance at sixteen rounds is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

The reduced-round trail analysis reports best one-active-S-box differential log2 probabilities of -6, -12, -18, -24, -30, -36, -43, -49, -55, -61, -68, -74, -80, -86, -92, and -99 through rounds 1 to 16, while the corresponding best linear single-trail values are `-3R`. Fixed-key endpoint checks under the reference key include a three-round differential frequency of about `2^-11.01` versus a selected single-characteristic product of `2^-18`, together with three- to six-round endpoint linear correlations materially larger than the selected single-trail magnitudes.

No full-round security claim follows from these observations. Full-round differential and linear hull analysis, boomerang, slide, reflection, related-key, and wide-trail cryptanalysis remain future work.

## Separate orientation-scheduling study

The comparative question of whether public orientation scheduling changes cryptanalytic behavior relative to a matched static orientation is treated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**. Its working materials are maintained in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

That separate study contains matched schedule controls, exact low-support transfer analysis, support-growth analysis, and cross-byte boundary experiments. Those analyses are not used here as evidence that HESPN's public schedule provides a security advantage.

## Current files

- `hespn_reference.py` is the current executable reference implementation and test-vector generator.
- `hespn_test_vector_v4.py` is a compatibility entry point that re-exports the current reference implementation.
- `hespn_trail_checks.py` is the NumPy-based author-review driver for the one-active-S-box trail search and reduced-round endpoint checks.
- `cryptologia_support/` contains submission-aligned validation data, the independent trail-check summary, and interpretation notes.
- `legacy_hespn_v4/` preserves older HESPN-v4 diagnostic material for research provenance. These files are historical and are not current Cryptologia evidence.
- `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md` records the current scope boundary and the September 2026 repository cleanup.

The public repository is intentionally not a mirror of the double-anonymous journal submission package. Author-identifying submission files, cover letters, and anonymous-review artifacts are maintained separately.

## Reproducibility boundary

The repository separates four kinds of evidence:

- **formal construction properties**, such as invertibility and the local branch-number floor;
- **formal diffusion-limit results**, such as matrix-S-box linear equivalence and composite byte branch number 2;
- **implementation checks**, such as reference vectors, round-trip verification, setup behavior, and exact local profiling;
- **bounded empirical checks**, including plaintext avalanche and reduced-round fixed-key endpoint measurements.

None of these categories establishes a deployment security level or a comparative advantage from public orientation scheduling.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
