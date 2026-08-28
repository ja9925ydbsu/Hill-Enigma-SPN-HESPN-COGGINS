# Verification metrics added in CiC Revision 2

Date: 2026-08-28

## Purpose

These measurements were added only to strengthen the construction-level verification of the Communications in Cryptology manuscript. They are not presented as full-cipher security evidence and do not test whether the public rotor schedule is better than a matched static schedule.

## Exact local matrix profile

The reference master key is the key fixed by Appendix A of the manuscript:

`15C6D44AA434C83CB8C87A63969EC64513E2446B37DE5AC60B513C99FC1756E3`

The 16 accepted seed matrices were derived exactly as specified in the manuscript. For each seed, all four 90-degree orientations were enumerated. All 16 seeds had rotation orbit size four, giving 64 distinct oriented matrices. All 64 oriented matrices had branch number 4.

Each oriented matrix was then applied to all eight one-bit byte inputs. Across 512 exact applications, output Hamming weights were:

| Output weight | Count | Share |
|---:|---:|---:|
| 3 | 108 | 21.09% |
| 4 | 160 | 31.25% |
| 5 | 144 | 28.13% |
| 6 | 64 | 12.50% |
| 7 | 32 | 6.25% |
| 8 | 4 | 0.78% |

Mean output weight was 4.5390625 and median output weight was 4. The minimum of 3 is exactly the one-bit consequence of the stated branch-number floor B >= 4. These observations describe the reference family only and do not strengthen the formal lower bound.

Machine-readable data: `metrics/cic_local_diffusion_reference_key.json`.

## Plaintext-avalanche integration check

A fresh CiC-specific integration run was performed under the same reference key. This is not the matched static-versus-rotor avalanche experiment used in the neighboring orientation-scheduling study.

For each round count in {1, 2, 4, 5, 8, 12, 16}, the same panel of 5,000 deterministic plaintexts and uniformly selected plaintext-bit flips was used. Each original and modified plaintext was encrypted with the rotor-scheduled HESPN reference harness, and ciphertext Hamming distance was recorded. The deterministic panel was seeded from the label:

`HESPN-CIC-PLAINTEXT-AVALANCHE-2026-08-28`

Results:

| Rounds | Mean | SD | 95% CI for mean |
|---:|---:|---:|---:|
| 1 | 3.9912 | 1.37895 | [3.95298, 4.02942] |
| 2 | 7.3532 | 2.37014 | [7.28750, 7.41890] |
| 4 | 18.0410 | 6.77546 | [17.85319, 18.22881] |
| 5 | 32.5800 | 12.02588 | [32.24666, 32.91334] |
| 8 | 54.0444 | 11.09435 | [53.73688, 54.35192] |
| 12 | 63.4918 | 6.01840 | [63.32498, 63.65862] |
| 16 | 63.9664 | 5.60885 | [63.81093, 64.12187] |

Machine-readable data: `metrics/cic_plaintext_avalanche_reference_key.csv`.

## Deliberately omitted metrics

Key avalanche remains omitted because a master-key change regenerates both round keys and seed matrices, so it primarily measures wholesale rekeying rather than the candidate mix layer. Random-mask linear screens, sampled differential screens, NIST statistical tests, algebraic-degree screens, boomerang/returned-difference analysis, exact weight-one recurrence, matched schedule ablations, and cross-byte boundary experiments remain outside the main CiC manuscript because they address a broader or distinct cryptanalytic question.
