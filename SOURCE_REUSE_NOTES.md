# Source and reuse notes

This new study is intentionally separate from the original HESPN v4 scripts.
The original files should remain unchanged for reproducibility.

## Existing HESPN conventions used as starting references

- AES S-box table and byte representation conventions.
- SHA-256 domain-separated round-key derivation pattern.
- Deterministic self-check and reproducibility style.
- Profile-based experiment execution.
- CSV/JSON result output and matched-control comparisons.

These conventions are visible in the public repository's reference test-vector,
diagnostic, rerun, and control scripts.

## New implementation in this package

- Asymmetric 4x4 Cauchy MDS matrix over AES GF(2^8).
- Four 90-degree matrix-element orientations and inverse matrices.
- Cross-byte AES-style SPN state layer.
- Five matched schedule controls.
- SciPy/HiGHS active-S-box MILP and LP export.
- Capped optimum-support enumeration.
- Exact AES DDT and LAT construction.
- Differential and linear beam searches.
- Captured aggregate low-active trail mass search.
- Deterministic schedule optimization.
- Slide and reflection structural audits.

No claim is made that the new implementation reproduces the original HESPN v4
ciphertext. It is a distinct experiment designed to test a stronger mix-layer
hypothesis.
