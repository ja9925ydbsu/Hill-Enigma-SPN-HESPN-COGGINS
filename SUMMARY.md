# GF(2^8) MDS-Rotor SPN Study Summary

This experiment tests whether 90-degree element rotations of an asymmetric 
4x4 Cauchy MDS matrix can serve as a scheduled cross-byte SPN mix layer. 
It does not claim a replacement for AES or a deployment-ready cipher.

## Certified wide-trail activity bounds

| Rounds | Minimum active S-boxes | Differential trail upper bound | Linear-correlation upper bound |
|---:|---:|---:|---:|
| 2 | 5 | 2^(-30) | 2^(-15) |
| 4 | 25 | 2^(-150) | 2^(-75) |
| 6 | 30 | 2^(-180) | 2^(-90) |
| 8 | 50 | 2^(-300) | 2^(-150) |

Because every orientation is MDS with branch number 5, these certified 
activity bounds are schedule-independent. Schedule effects, if any, must 
appear in coefficient-sensitive trail multiplicities, aggregate classes, 
or structural self-similarity—not in the one-layer branch number.

## Heuristic coefficient-sensitive searches

Candidate trail searches are beam searches and are not proofs of global optima.

| Kind | Variant | Rounds | Candidate log2 magnitude | Active S-boxes |
|---|---|---:|---:|---:|
| differential | static | 2 | -30.000 | 5 |
| differential | static | 3 | -126.000 | 21 |
| differential | static | 4 | -216.000 | 36 |
| differential | rotor | 2 | -30.000 | 5 |
| differential | rotor | 3 | -126.000 | 21 |
| differential | rotor | 4 | -210.000 | 35 |
| differential | round_only | 2 | -30.000 | 5 |
| differential | round_only | 3 | -126.000 | 21 |
| differential | round_only | 4 | -210.000 | 35 |
| differential | position_only | 2 | -30.000 | 5 |
| differential | position_only | 3 | -126.000 | 21 |
| differential | position_only | 4 | -210.000 | 35 |
| differential | optimized | 2 | -30.000 | 5 |
| differential | optimized | 3 | -126.000 | 21 |
| differential | optimized | 4 | -210.000 | 35 |
| linear | static | 2 | -15.000 | 5 |
| linear | static | 3 | -63.000 | 21 |
| linear | static | 4 | -105.000 | 35 |
| linear | rotor | 2 | -15.000 | 5 |
| linear | rotor | 3 | -63.000 | 21 |
| linear | rotor | 4 | -108.000 | 36 |
| linear | round_only | 2 | -15.000 | 5 |
| linear | round_only | 3 | -63.000 | 21 |
| linear | round_only | 4 | -105.000 | 35 |
| linear | position_only | 2 | -15.000 | 5 |
| linear | position_only | 3 | -63.000 | 21 |
| linear | position_only | 4 | -105.000 | 35 |
| linear | optimized | 2 | -15.000 | 5 |
| linear | optimized | 3 | -63.000 | 21 |
| linear | optimized | 4 | -105.000 | 35 |

## Captured low-active differential mass

These are lower bounds on captured class probability because local transitions 
and global states are pruned.

| Variant | Rounds | Active budget | Captured log2 mass |
|---|---:|---:|---:|
| static | 4 | 40 | -207.35543954121403 |
| rotor | 4 | 40 | -206.9957795336818 |
| round_only | 4 | 40 | -209.03421571533792 |
| position_only | 4 | 40 | -206.97832595714164 |
| optimized | 4 | 40 | -206.3342199716705 |

## Schedule periods

| Variant | Detected period |
|---|---:|
| static | 1 |
| rotor | 4 |
| round_only | 4 |
| position_only | 1 |
| optimized | 8 |

## Interpretation boundary

A favorable rotor result on one trail metric is evidence about that metric only. 
A tie or unfavorable result is also informative. The central research question is 
whether rotated Hill-derived MDS layers alter multi-round trail structure while 
retaining a certified branch-number floor.

Profile: `standard`. Runtime: 741.34 s.
