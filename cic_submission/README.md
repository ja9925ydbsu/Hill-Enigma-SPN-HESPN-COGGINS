# Historical Communications in Cryptology support snapshot

> **Status:** This directory is retained for provenance from the earlier Communications in Cryptology preparation. It is not the current journal-submission directory. Current IJIS-facing status and scope are documented in `../ijis_submission/README.md`, `../docs/IJIS_SUBMISSION_STATUS_2026_09_14.md`, and `../docs/REPRODUCIBILITY_IJIS_2026_09_14.md`.

This directory contains public repository materials originally aligned with the construction study **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN** during the CiC formatting stage.

The complete journal submission source packages have always been maintained separately from this public code repository. The two machine-readable construction metrics below remain canonical provenance records and are reused unchanged by the current IJIS construction manuscript.

## Verification data retained for provenance

`metrics/cic_local_diffusion_reference_key.json` contains the exact one-bit output-weight profile of the reference matrix family.

`metrics/cic_plaintext_avalanche_reference_key.csv` contains the construction-specific plaintext-avalanche integration results.

See `VERIFICATION_METRICS_NOTE.md` for the original methods and interpretation limits. Its references to CiC describe the historical context in which those measurements were added; the numerical records themselves are unchanged.

## Scope

The current IJIS paper verifies architectural workability and bounded integration behavior. It does not present a deployment security claim and does not ask whether a public orientation schedule is cryptanalytically superior to a static matrix layer. Exact weight-one analysis, matched schedule comparisons, optimized differential or linear trails, boomerang analysis, related-key analysis, and broader cross-byte work are outside the IJIS construction manuscript.

This directory is preserved so the public repository retains a clear provenance trail rather than silently renaming or rewriting historical artifacts.
