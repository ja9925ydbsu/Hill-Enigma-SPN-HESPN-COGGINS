# Communications in Cryptology submission materials

This directory contains the submission-aligned source for the construction study **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN**.

## Preferred format

Use `iacrj/` as the primary current IACR source set.

- `main.tex`: author-visible preprint
- `main_submission.tex`: anonymous submission
- `main_submission_named.tex`: named submission
- `main_final.tex`: final-version source
- `references.bib`: active bibliography
- `Fig1.pdf`, `Fig2.pdf`: manuscript figures
- `figure1_source.tex`, `figure2_source.tex`: editable figure sources

The parallel `iacrcc/` directory contains the same scientific manuscript in the older class syntax and is retained only as a compatibility fallback.

## Verification data

`metrics/cic_local_diffusion_reference_key.json` contains the exact one-bit output-weight profile of the reference matrix family.

`metrics/cic_plaintext_avalanche_reference_key.csv` contains the fresh CiC-specific plaintext-avalanche integration results.

See `VERIFICATION_METRICS_NOTE.md` for methods and interpretation limits.

## Scope

The paper verifies architectural workability and bounded integration behavior. It does not present a deployment security claim and does not ask whether a public orientation schedule is cryptanalytically superior to a static matrix layer. Exact weight-one analysis, matched schedule comparisons, optimized differential or linear trails, boomerang analysis, and related-key analysis are outside this manuscript.
