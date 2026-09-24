# Verification and diffusion-limit metrics for the IACR CiC working manuscript

Updated: 2026-09-24

These materials support **Rotor-Scheduled Linear Layers for Byte-Oriented SPNs: Construction and Cryptanalytic Characterization**, prepared for *IACR Communications in Cryptology* (CiC). The purpose of the paper is to define and analyze the mechanism, not to claim security for HESPN as a cipher.

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

At 16 rounds the sample standard deviation of 5.60885 bits is close to `sqrt(32) = 5.65685`, the standard deviation expected for the Hamming distance between independent uniform 128-bit strings.

Machine-readable data: `metrics/hespn_plaintext_avalanche_reference_key.csv`.

The avalanche measurement is an implementation and integration sanity check. It does not isolate an incremental contribution of orientation scheduling and is not a differential or linear security bound. Three rounds were not part of the recorded deterministic avalanche panel and no three-round value is inferred.

## Formal diffusion-limit results

The current manuscript adds two structural results beyond the earlier construction checks.

First, for an invertible byte matrix `M`, the permutation `T = S o M` is linearly equivalent to `S`. Therefore `T` and `S` have the same maximum nontrivial difference-distribution entry and the same maximum absolute linear-approximation entry. The local matrix does not strengthen the substitution layer in those metrics.

Second, the composite linear map carrying one round's S-box outputs to the next round's S-box inputs has byte-level branch number 2. The local `B >= 4` criterion therefore does not yield a nontrivial multi-round active-S-box lower bound.

For the reference key, dynamic programming finds one-active-S-box differential characteristics and linear trails for every round count from 1 through 16. The best single-characteristic differential log2 probabilities are:

`-6, -12, -18, -24, -30, -36, -43, -49, -55, -61, -68, -74, -80, -86, -92, -99`

The best linear single-trail values are exactly `-3R` in log2 absolute correlation at round count `R`.

## Reduced-round fixed-key endpoint checks

The single-characteristic and single-trail products above use the usual independent-round, or Markov, model. They are not security bounds for the fixed-key construction. The reference implementation was therefore checked directly at reduced rounds using endpoint differences and masks selected from the best one-active-S-box trails.

| Test | Selected single-trail model | Samples | Fixed-key endpoint observation |
|---|---:|---:|---|
| 2-round differential | `2^-12` | `2^18` pairs | 0 right pairs; one-sided 95% upper bound about `2^-16.4` |
| 3-round differential | `2^-18` | `2^22` pairs | 2,036 right pairs, about `2^-11.01` |
| 3-round linear | `|c| = 2^-9` | `2^22` texts | `c = 0.014906`, about `2^-6.07` |
| 4-round linear | `|c| = 2^-12` | `2^22` texts | `c = -0.003358`, about `2^-8.22` |
| 5-round linear | `|c| = 2^-15` | `2^24` texts | `c = -0.002003`, about `2^-8.96` |
| 6-round linear | `|c| = 2^-18` | `2^27` texts | `c = -0.000801`, about `2^-10.29` |

The differential rows measure the complete fixed-key endpoint difference, not whether a particular internal characteristic was followed round by round. The linear rows measure endpoint correlation and therefore include linear-hull effects.

These measurements depart substantially from the selected single-trail products. They show that the latter cannot be used as security margins for the fixed-key construction. The zero count at two rounds is reported only as an observation with a confidence bound; it is not proof that an internal characteristic is impossible. No claim is made about the existence or absence of a 16-round distinguisher.

The author-review trail driver is `../hespn_trail_checks.py`. The independent Revision 7A numerical summary is `trail_check_output_revision7.txt`. The trail driver requires NumPy in addition to the Python standard library.

## Separate analyses

Full-round differential and linear hull analysis, boomerang, slide, reflection, related-key, and wide-trail cryptanalysis are not established by the current manuscript.

The matched comparison of public orientation scheduling against fixed and other schedule controls, together with broader low-support transfer and cross-byte boundary studies, is reported separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, published in *Cryptography* 2026, 10, 71 (23 September 2026), https://doi.org/10.3390/cryptography10050071.
