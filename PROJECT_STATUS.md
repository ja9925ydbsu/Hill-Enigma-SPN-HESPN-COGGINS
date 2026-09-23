# Project status: IACR Communications in Cryptology working-manuscript alignment

Updated: 2026-09-23

This repository is aligned with the working manuscript **Rotor-Scheduled Byte-Local Linear Layers: Construction and Structural Limits in an SPN**, prepared for submission to *IACR Communications in Cryptology* (CiC).

## Current research claim

The purpose of the paper is to define and analyze the HESPN mechanism, not to claim security for HESPN as a cipher.

The construction result is that the previously reported Hill-matrix element-rotation mechanism can be extended to order eight, filtered by explicit byte-local admissibility conditions, scheduled reproducibly, and integrated into a reversible experimental SPN. The analysis then identifies limits of that construction: the byte matrix composed with the following S-box is linearly equivalent to the S-box alone, the composite map between successive S-box layers has byte branch number 2, and one-active-S-box trails remain possible through all 16 rounds of the reference configuration.

The reduced-round fixed-key endpoint checks further show that selected single-characteristic and single-trail products are not reliable security margins for the fixed-key construction. These bounded results do not establish a 16-round distinguisher, a deployment security level, or a security advantage from public rotor scheduling.

HESPN means **Hill Enigma Substitution-Permutation Network**. The term *Enigma* refers only to the public stepping inspiration behind scheduled geometric reorientation of the matrix entries. HESPN has no reflector, no Enigma rotor wiring, and no self-inverse signal path.

## Verified construction properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- Clockwise rotation satisfies `R(M) = M^T J` and therefore preserves invertibility.
- The four orientations require only two independent local branch-number evaluations, `B(M)` and `B(M^T)`.
- Every scheduled orientation satisfies the local floor `B >= 4` after successful setup.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- Every round and the complete sixteen-round mapping have exact inverses.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The rejection filter is feasible for the reported prototype setup.

## Diffusion-limit results

- For each invertible byte matrix `M`, `S o M` is linearly equivalent to `S`, so the scheduled matrix does not improve the S-box maximum differential probability or maximum absolute linear correlation.
- The composite inter-round linear map has byte-level branch number 2.
- The local `B >= 4` floor therefore does not imply a nontrivial multi-round active-S-box bound.
- Dynamic programming finds one-active-S-box differential characteristics and linear trails for every round count from 1 through 16 under the reference key.
- Best one-active-S-box differential log2 probabilities through rounds 1 to 16 are `-6, -12, -18, -24, -30, -36, -43, -49, -55, -61, -68, -74, -80, -86, -92, -99`; best linear single-trail values are `-3R`.
- Fixed-key reduced-round endpoint checks depart substantially from these single-trail products. The three-round endpoint differential was observed at about `2^-11.01` versus a selected single-characteristic product of `2^-18`. Three- to six-round endpoint linear correlations likewise exceed the selected single-trail magnitudes.

These results delimit the construction claim. They do not constitute a full-round hull analysis or prove the existence or absence of a 16-round distinguisher.

## Bounded implementation and integration checks

The current manuscript reports:

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration check using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].
3. Reduced-round fixed-key endpoint checks for differences and masks selected from the best one-active-S-box trails.

These checks do not isolate a benefit caused by orientation scheduling.

## Separate orientation-scheduling study

The matched comparative question is treated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, published in *Cryptography* 2026, 10, 71 (23 September 2026), https://doi.org/10.3390/cryptography10050071. Code, data, and reproducibility materials are maintained in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

The HESPN manuscript does not rely on that separate study to claim a scheduling advantage.

## Repository alignment

The September 2026 cleanup removed duplicate Structural Limits experiment files from the HESPN working tree while preserving them in the dedicated Structural Limits repository and in Git history. On 23 September 2026, the public support directory was renamed from `cryptologia_support/` to `iacr_cic_support/` to reflect the new journal target; the underlying validation data remain the same. Older HESPN-v4 diagnostics remain under `legacy_hespn_v4/` as historical research provenance rather than current manuscript evidence.

Current working-manuscript support material is under `iacr_cic_support/`. The executable reference implementation is `hespn_reference.py`, and the bounded trail-check driver is `hespn_trail_checks.py`.
