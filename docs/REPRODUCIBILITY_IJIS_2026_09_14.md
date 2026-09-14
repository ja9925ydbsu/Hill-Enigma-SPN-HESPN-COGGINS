# HESPN IJIS reproducibility manifest - 14 September 2026

This note identifies the public materials that support the construction-feasibility claims in **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**. It deliberately does not promote older or separate cryptanalytic experiments into the IJIS evidence chain.

## Reference implementation and test vector

Canonical script: `hespn_test_vector_v4.py`

Standard-library-only reference run:

```text
python hespn_test_vector_v4.py
```

The script prints the 16 round keys, the 16 accepted seed matrices with branch-number checks, round-zero intermediate states, the 16-round ciphertext, and a decryption round-trip check. The test-vector path uses a SHA-256 stub only to obtain a reproducible 256-bit master key without an external password-hashing package. The construction itself takes a 256-bit master key as its cryptographic input.

## Algebraic, admissibility, and schedule properties

Revision 5 presents the construction as a coherent framework and establishes:

- `R(M) = M^T J` for the defined clockwise matrix-element rotation;
- rotation preserves invertibility;
- the four orientations require only two independent local branch-number values, `B(M)` and `B(M^T)`;
- an admissible seed combines invertibility with the stated local branch-number requirements;
- deterministic rejection sampling converts those requirements into a reproducible admissible-family construction;
- `B >= 4` guarantees at least three active output bits for every one-bit input, is feasible under the reported rejection audit, and is not claimed to be an optimal threshold;
- the 16-round public schedule is exactly balanced: for every `j` and `k`, `(S_j, R^k)` occurs in exactly four rounds;
- every round and the complete 16-round composition are invertible.

Because `R^4` is the identity, rotation orbits can have size 1, 2, or 4. Shorter orbits are possible when a matrix is invariant under `R` or `R^2`. The reference family contains no such degeneracy: all 16 accepted seeds have orbit size four, giving 64 distinct oriented matrices.

Seed derivation is performed once per master key in the reference construction. The accepted seed family and scheduled orientations can be reused across subsequent block evaluations; rejection sampling is therefore setup work rather than a per-block encryption cost. No optimized setup-time or throughput claim is made.

## Exact local diffusion profile

Machine-readable record retained under its historical CiC path for provenance:

`cic_submission/metrics/cic_local_diffusion_reference_key.json`

For the reference family, all 64 oriented matrices have branch number 4. Across all eight one-bit inputs for each orientation (512 exact applications), output Hamming weights range from 3 to 8, with mean 4.5390625. This finite profile describes the reference family and does not strengthen the formal local branch-number floor.

## Plaintext-avalanche integration check

Machine-readable record retained under its historical CiC path for provenance:

`cic_submission/metrics/cic_plaintext_avalanche_reference_key.csv`

The same 5,000 deterministic plaintext/bit-flip pairs are reused at each reported round count. At 16 rounds the ciphertext Hamming-distance mean is 63.9664 bits with 95% CI [63.81093, 64.12187]. The manuscript uses this only as a bounded whole-harness implementation sanity check. It is not a differential/linear security bound and not evidence that rotor scheduling is superior to a static layer.

## Outside the IJIS evidence chain

The following categories may remain elsewhere in the repository for provenance but do not support the current construction-feasibility claim:

- exact weight-one recurrence or transfer-operator results;
- matched static/rotor/round-only/position-only schedule comparisons;
- optimized differential or linear trails;
- sampled differential-collision and random-mask linear screens;
- boomerang/rectangle or returned-difference experiments;
- related-key analysis;
- NIST SP 800-22 output testing;
- algebraic-degree estimates;
- cross-byte MDS or other boundary experiments;
- slide/reflection audits.

Those materials address separate mechanism-level or security-analysis questions. They should not be cited as if the IJIS manuscript established attack resistance or a schedule-derived security advantage.

## Claim boundary

The reproducible conclusion is architectural: the order-eight rotor-scheduled Hill-derived linear layer is explicitly specified, locally diffusion-bounded at the stated byte-level granularity, reproducibly selected from an admissible family, exactly balanced under the public schedule, reversible, and usable inside the reported 16-round experimental SPN harness. These materials do not establish a deployment security level, an advantage over AES, an advantage of rotor scheduling over a matched static orientation, or a full-cipher differential/linear bound.
