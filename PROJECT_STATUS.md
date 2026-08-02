# Project status after validated smoke run

The code package is complete enough for a first controlled run and passes all
included unit tests.

## Validated algebraic properties

- The default base matrix is an asymmetric 4x4 Cauchy matrix over GF(2^8).
- All four 90-degree element orientations are distinct.
- All four orientations are invertible.
- All four orientations are MDS with symbol branch number 5.
- Encryption/decryption round trips pass for all five schedule variants.

## Certified MILP results

| Rounds | Minimum active S-boxes | Differential upper bound | Linear-correlation upper bound |
|---:|---:|---:|---:|
| 2 | 5 | 2^-30 | 2^-15 |
| 4 | 25 | 2^-150 | 2^-75 |
| 6 | 30 | 2^-180 | 2^-90 |
| 8 | 50 | 2^-300 | 2^-150 |

These bounds are schedule-independent because every orientation has the same MDS
branch number. This is expected and is not evidence against the rotor hypothesis.
It means the schedule must be assessed through coefficient-sensitive properties.

## Smoke-profile coefficient-sensitive results

At the deliberately small smoke settings, all five schedules tied on the retained
best differential and linear trail magnitudes, and tied on captured low-active
mass. These are heuristic, heavily pruned searches. The result may indicate true
invariance in the tested class or simply insufficient search depth. The standard
and paper profiles are provided to distinguish those possibilities.

## Slide and reflection status

- Static and position-only schedules have period 1 at the orientation-row level.
- Rotor and round-only schedules have period 4.
- The bundled optimized schedule has period 8.
- No exact full keyed round fingerprint repeats because SHA-256-derived round keys
  are distinct in the tested 16-round instance.
- No exact encryption/decryption reflection was found by the structural audit.

These are preliminary structural audits, not proofs of resistance to advanced
slide, related-key, or reflection attacks.
