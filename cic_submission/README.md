# Communications in Cryptology support materials

This directory contains public repository materials aligned with the construction study **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN**.

The complete journal submission source packages are maintained separately from this public code repository. The current preferred journal format is `iacrj`; the older `iacrcc` package is retained separately as a compatibility fallback.

## Verification data

`metrics/cic_local_diffusion_reference_key.json` contains the exact one-bit output-weight profile of the reference matrix family.

`metrics/cic_plaintext_avalanche_reference_key.csv` contains the fresh CiC-specific plaintext-avalanche integration results.

See `VERIFICATION_METRICS_NOTE.md` for methods and interpretation limits.

## Scope

The paper verifies architectural workability and bounded integration behavior. It does not present a deployment security claim and does not ask whether a public orientation schedule is cryptanalytically superior to a static matrix layer. Exact weight-one analysis, matched schedule comparisons, optimized differential or linear trails, boomerang analysis, and related-key analysis are outside this manuscript.

The purpose of this directory is to keep the public repository's evidence and interpretation synchronized with the manuscript without turning the repository into a duplicate journal-submission archive.
