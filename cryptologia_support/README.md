# Cryptologia Revision 7A support materials

This directory contains public reproducibility material aligned with **Order-Eight Rotor-Scheduled Hill Matrices: Construction, Validation, and Diffusion Limits of a Byte-Local SPN Linear Layer**.

It is intentionally not a mirror of the double-anonymous journal submission package.

## Contents

- `metrics/hespn_local_diffusion_reference_key.json`: exact one-bit output-weight profile of the 64 oriented matrices in the reference family.
- `metrics/hespn_plaintext_avalanche_reference_key.csv`: bounded plaintext-avalanche integration results under the reference key.
- `reference_test_vector_output.txt`: deterministic reference output for the current implementation.
- `trail_check_output_revision7.txt`: independent summary of the one-active-S-box trail search and reduced-round fixed-key endpoint checks used in the current manuscript.
- `VERIFICATION_METRICS_NOTE.md`: methods, numerical results, and interpretation limits for the current validation and diffusion-limit evidence.

The executable current reference implementation is at repository root as `hespn_reference.py`; `hespn_test_vector_v4.py` remains as a compatibility entry point. The NumPy-based trail-check driver is at repository root as `hespn_trail_checks.py`.

## Scope

These files support construction, implementation validation, and bounded analysis of the direct diffusion limits of the HESPN reference configuration. They establish neither a deployment security level nor a comparative advantage from public orientation scheduling.

The current manuscript proves that a scheduled byte matrix composed with the following S-box is linearly equivalent to that S-box alone and that the composite inter-round linear map has byte branch number 2. It also reports one-active-S-box trail searches and reduced-round fixed-key endpoint checks. Those bounded results do not replace full-round differential or linear hull analysis.

The matched static-versus-scheduled question is treated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, with working materials at:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>
