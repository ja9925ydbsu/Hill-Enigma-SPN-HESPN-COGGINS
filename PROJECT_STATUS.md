# Project status: Cryptologia construction-and-validation alignment

Updated: 2026-09-15

This repository is aligned with the manuscript **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**, prepared for submission to *Cryptologia*.

## Current research claim

The HESPN paper establishes a construction and validation framework for asking whether previously reported Hill-matrix element rotations can be extended to order eight and used as a reversible, locally diffusion-bounded linear mix layer in an experimental substitution-permutation network. It does not propose HESPN as a deployment-ready cipher and does not claim that public rotor scheduling provides a security advantage over a static orientation.

The significance is not a claimed security improvement from the order-eight schedule. It is the mathematically consistent byte-scale realization of a previously published order-two mechanism, together with explicit admissibility conditions, reproducible scheduling, and reversible SPN integration. These properties provide a common framework for later comparative and cryptanalytic studies.

HESPN means **Hill Enigma Substitution-Permutation Network**. The term *Enigma* refers only to the public stepping inspiration behind scheduled geometric reorientation of the matrix entries. HESPN has no reflector, no Enigma rotor wiring, and no self-inverse signal path.

## Verified construction and validation properties

- Sixteen accepted 8 x 8 binary seed matrices are used in the reference configuration.
- Clockwise rotation satisfies `R(M) = M^T J` and therefore preserves invertibility.
- The four orientations require only two independent branch-number evaluations, `B(M)` and `B(M^T)`.
- Every scheduled orientation satisfies the local floor `B >= 4` after successful setup.
- The sixteen-round public schedule uses all 64 labeled seed-orientation pairs equally.
- Every round and the complete sixteen-round mapping have exact inverses.
- Reference vectors check bit packing, round order, matrix application, substitution, routing, and decryption.
- The rejection filter is feasible for the reported prototype setup.

## Bounded integration checks

The construction and validation study reports two deliberately limited empirical checks:

1. Exact local one-bit spreading over all 64 oriented matrices under the reference key. Output weight ranges from 3 to 8 bits with mean 4.5390625.
2. A plaintext-avalanche integration check using 5,000 deterministic pairs per tested round count. At sixteen rounds the mean ciphertext Hamming distance is 63.9664 bits with 95 percent confidence interval [63.81093, 64.12187].

These checks do not establish full-cipher security or isolate a benefit caused by orientation scheduling.

## Separate orientation-scheduling study

The limits of public orientation scheduling in the byte-local setting have been investigated separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**. Its matched schedule experiments, exact weight-one transfer analysis, structural support arguments, and cross-byte boundary experiments are maintained in the dedicated repository:

<https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>

They are not part of the HESPN construction and validation framework's evidentiary chain.

## Repository cleanup completed for Cryptologia alignment

The September 2026 cleanup removes duplicate Structural Limits experiment files from the HESPN working tree, while preserving them in the dedicated Structural Limits repository and in Git history. Older HESPN-v4 diagnostic material is retained under `legacy_hespn_v4/` as historical research provenance rather than current manuscript evidence.

Current construction-and-validation support material is under `cryptologia_support/`, and the current executable reference implementation is `hespn_reference.py`.
