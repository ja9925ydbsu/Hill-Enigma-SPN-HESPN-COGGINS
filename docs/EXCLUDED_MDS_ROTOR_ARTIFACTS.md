# Excluded MDS-rotor artifacts

The HESPN/Cryptologia manuscript and reproducibility chain must remain separate from the 4 x 4 GF(2^8) MDS-rotor study.

## Explicit exclusion

The file `active_sbox_bounds.csv`, including the values **5 / 25 / 30 / 50 active S-boxes**, is produced by `run_mds_rotor_study.py` for the separate MDS-rotor study. Those numbers are **not HESPN results**.

They must not be:

- inserted into the HESPN manuscript;
- quoted as a HESPN active-S-box bound;
- added to HESPN tables or figures;
- included in the Cryptologia reproducibility supplement;
- used to strengthen the byte-local `B >= 4` claim.

## Why the separation matters

HESPN uses 8 x 8 binary matrices over GF(2) as byte-local maps. The separate MDS-rotor study uses a 4 x 4 cross-byte construction over GF(2^8). Their diffusion models, state granularity, and active-S-box analyses are different.

The HESPN manuscript expressly states that its local branch-number criterion does not yield a nontrivial multi-round active-S-box lower bound. Importing the MDS-rotor figures would therefore misstate the evidentiary basis of the paper.

For the current HESPN evidence chain, use `docs/REPRODUCIBILITY_CRYPTOLOGIA_2026_09_15.md`.
