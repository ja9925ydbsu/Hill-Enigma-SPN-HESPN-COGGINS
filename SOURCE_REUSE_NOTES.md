# Source and reuse notes

This repository contains several generations of HESPN research code and separate experimental branches. The current Cryptologia manuscript, **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**, uses the byte-local 8 x 8 GF(2) rotor-matrix construction as an experimental SPN linear-layer harness. Broader matched-schedule, trail-search, boomerang, randomness, cross-byte, MDS-rotor, and structural-audit materials remain in the repository as historical or separate research assets but are not part of the Cryptologia construction claim.

## Current Cryptologia evidence chain

The public repository should be read as supporting the following construction-level items:

- MSB-first byte and matrix representation;
- the explicitly defined 90-degree matrix-element rotation;
- the identity `R(M) = M^T J` and the resulting invertibility preservation;
- local differential and linear branch-number checks;
- a feasible `B >= 4` construction threshold, not claimed optimal;
- sixteen-round rotor scheduling and deterministic balanced seed-orientation coverage;
- reversible round-function implementation;
- deterministic reference behavior and test vectors;
- admissibility-filter setup behavior, treated as master-key setup work;
- exact local one-bit diffusion profile;
- bounded plaintext-avalanche integration sanity check.

The machine-readable local-diffusion and plaintext-avalanche records support this construction-level chain. The author-side Cryptologia reproducibility supplement renames the historically `cic_`-prefixed copies to HESPN-specific filenames so their role is clear.

## Explicit MDS-rotor exclusion

`active_sbox_bounds.csv` is not a HESPN support file. Its 5/25/30/50 active-S-box values are produced by `run_mds_rotor_study.py` for the separate **4 x 4 GF(2^8) MDS-rotor study**. Those values must not be cited, summarized, or imported as evidence for the HESPN/Cryptologia manuscript.

This exclusion is especially important because the HESPN paper expressly establishes **no nontrivial multi-round active-S-box lower bound**. Its local `B >= 4` criterion cannot be converted into the active-S-box figures from the separate MDS-rotor model.

## Historical analyses retained for reproducibility

Older files include broader security diagnostics and later experimental branches. Examples include exact weight-one trails, schedule ablations, random-mask linear screens, sampled differential screens, boomerang calibration, NIST testing, algebraic-degree estimates, cross-byte Cauchy-MDS experiments, MDS-rotor active-S-box calculations, and slide/reflection audits.

Those files are intentionally preserved because deleting or silently rewriting them would impair reproducibility of earlier drafts and exploratory studies. They should not be cited as evidence that the current Cryptologia manuscript proves resistance to the corresponding attacks.

## Relationship to separate orientation-scheduling and MDS-rotor studies

The Cryptologia manuscript asks whether the rotating Hill-matrix family can be constructed and used as an SPN linear layer. A distinct orientation-scheduling study asks what cryptanalytic effect, if any, public scheduling has relative to matched static controls. A separate 4 x 4 GF(2^8) MDS-rotor study investigates cross-byte MDS constructions and active-S-box bounds. Neither separate study is part of the Cryptologia construction paper.

## Reuse principle

When reusing code from this repository, distinguish the construction being implemented from the experiment being run. A script may be historically useful even when its output is outside the scope of the current paper. Preserve file provenance and avoid treating exploratory diagnostics as formal HESPN security guarantees.

See `docs/REPRODUCIBILITY_CRYPTOLOGIA_2026_09_15.md` and `docs/EXCLUDED_MDS_ROTOR_ARTIFACTS.md` for the current construction-level evidentiary boundary.
