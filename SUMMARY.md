# HESPN / IACR CiC working-manuscript summary

HESPN, the **Hill Enigma Substitution-Permutation Network**, is used as an experimental SPN harness for a construction and analysis question: can a family of rotated Hill-derived 8 x 8 matrices over GF(2) occupy the linear mix-layer position of an SPN while remaining explicit, reversible, locally diffusion-bounded, and reproducible, and what limits follow directly from that architecture?

The term *Enigma* refers only to the public stepping inspiration behind scheduled geometric reorientation of matrix entries. HESPN does not reproduce the historical Enigma machine's reflector, rotor wiring, or self-inverse signal path.

The current working manuscript, **Rotor-Scheduled Byte-Local Linear Layers: Construction and Structural Limits in an SPN**, is prepared for submission to *IACR Communications in Cryptology* (CiC). Its purpose is to define and analyze the mechanism, not to claim security for HESPN as a cipher.

The construction result is affirmative. Matrix rotation preserves invertibility; accepted seeds satisfy the local branch-number floor in all scheduled orientations; the public schedule uses each labeled seed-orientation pair equally; and the complete sixteen-round map is invertible. Reference vectors and setup statistics make the prototype independently checkable.

The manuscript also sharpens the limits of those claims. For a scheduled byte matrix `M`, `S o M` is linearly equivalent to `S`, so the matrix does not improve the S-box maximum differential probability or maximum absolute linear correlation. The composite linear map between successive S-box layers has byte branch number 2, and one-active-S-box differential characteristics and linear trails exist through all 16 rounds of the reference configuration.

Reduced-round fixed-key endpoint checks differ substantially from selected single-characteristic and single-trail products. In particular, the tested three-round endpoint differential is observed at about `2^-11.01` versus a selected single-characteristic product of `2^-18`, and the tested three- to six-round endpoint linear correlations are materially larger than the selected single-trail magnitudes. These results show that the single-trail products are not security margins for the fixed-key construction. They do not establish a full-round distinguisher or a deployment security level.

The current validation evidence also includes an exact local diffusion profile and one bounded plaintext-avalanche integration check. Those measurements are implementation and integration checks, not evidence that scheduling is superior to a static matrix layer.

The matched orientation-scheduling comparison has now been published separately as **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, published in *Cryptography* 2026, 10, 71 (23 September 2026), https://doi.org/10.3390/cryptography10050071. Working materials remain at <https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling>.

Current working-manuscript support materials are under `iacr_cic_support/`. Historical HESPN-v4 diagnostic material is retained under `legacy_hespn_v4/` only for provenance.
