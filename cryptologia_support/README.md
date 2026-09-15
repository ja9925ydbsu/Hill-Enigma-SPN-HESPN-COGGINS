# Cryptologia construction-and-validation support materials

This directory contains public reproducibility material aligned with **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

It is intentionally not a mirror of the double-anonymous journal submission package.

## Contents

- `metrics/hespn_local_diffusion_reference_key.json`: exact one-bit output-weight profile of the 64 oriented matrices in the reference family.
- `metrics/hespn_plaintext_avalanche_reference_key.csv`: bounded plaintext-avalanche integration results under the reference key.
- `reference_test_vector_output.txt`: deterministic reference output for the current implementation.
- `VERIFICATION_METRICS_NOTE.md`: methods and interpretation limits for the two reported construction-and-validation datasets.

The executable current reference implementation is at repository root as `hespn_reference.py`; `hespn_test_vector_v4.py` remains as a compatibility entry point.

## Scope

These files support construction and implementation validation. They do not show that public orientation scheduling is cryptanalytically superior to a static matrix layer. The limits of public orientation scheduling are investigated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, with code and results maintained at:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>
