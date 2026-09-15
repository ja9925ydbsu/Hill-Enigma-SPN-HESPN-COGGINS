# Verification metrics for the Cryptologia construction manuscript

Updated: 2026-09-15

These measurements strengthen construction-level verification of **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**. They are not full-cipher security evidence and do not test whether the public rotor schedule is better than a matched static schedule.

## Exact local matrix profile

The reference master key is:

`15C6D44AA434C83CB8C87A63969EC64513E2446B37DE5AC60B513C99FC1756E3`

The 16 accepted seed matrices are derived as specified by the reference implementation. For each seed, all four 90-degree orientations are enumerated. All 16 seeds have orbit size four, giving 64 distinct oriented matrices. All 64 have branch number 4.

Across all 512 one-bit matrix applications, output Hamming weights are:

| Output weight | Count | Share |
|---:|---:|---:|
| 3 | 108 | 21.09% |
| 4 | 160 | 31.25% |
| 5 | 144 | 28.13% |
| 6 | 64 | 12.50% |
| 7 | 32 | 6.25% |
| 8 | 4 | 0.78% |

Mean output weight is 4.5390625 and median output weight is 4. The minimum of 3 is exactly the one-bit consequence of the stated local branch-number floor `B >= 4`. These observations describe the reference family and do not strengthen the formal floor.

Machine-readable data: `metrics/hespn_local_diffusion_reference_key.json`.

## Plaintext-avalanche integration check

For each round count in {1, 2, 4, 5, 8, 12, 16}, the same panel of 5,000 deterministic plaintexts and uniformly selected plaintext-bit flips is used under the rotor-scheduled reference harness.

| Rounds | Mean | SD | 95% CI for mean |
|---:|---:|---:|---:|
| 1 | 3.9912 | 1.37895 | [3.95298, 4.02942] |
| 2 | 7.3532 | 2.37014 | [7.28750, 7.41890] |
| 4 | 18.0410 | 6.77546 | [17.85319, 18.22881] |
| 5 | 32.5800 | 12.02588 | [32.24666, 32.91334] |
| 8 | 54.0444 | 11.09435 | [53.73688, 54.35192] |
| 12 | 63.4918 | 6.01840 | [63.32498, 63.65862] |
| 16 | 63.9664 | 5.60885 | [63.81093, 64.12187] |

Machine-readable data: `metrics/hespn_plaintext_avalanche_reference_key.csv`.

The avalanche measurement is an implementation/integration sanity check. It does not isolate an incremental contribution of orientation scheduling and is not a differential or linear security bound.

## Deliberately separate analyses

Exact weight-one recurrence, matched schedule ablations, optimized trail work, calibration panels, cross-byte boundary experiments, and broader comparative cryptanalysis belong to the separate Structural Limits study and are maintained in its dedicated repository.
