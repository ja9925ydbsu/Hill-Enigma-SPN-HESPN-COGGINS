# HESPN Cryptologia construction-study summary

HESPN, the **Hill Enigma Substitution-Permutation Network**, is used as an experimental SPN harness for one construction question: can a family of rotated Hill-derived 8 x 8 matrices over GF(2) occupy the linear mix-layer position of an SPN while remaining explicit, reversible, locally diffusion-bounded, and reproducible?

The term *Enigma* refers only to the public stepping inspiration behind the scheduled geometric reorientation of matrix entries. HESPN does not reproduce the historical Enigma machine's reflector, rotor wiring, or self-inverse signal path.

The current manuscript, **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**, is prepared for submission to *Cryptologia*. Its result is limited but affirmative. Matrix rotation preserves invertibility; accepted seeds satisfy the local branch-number floor in all scheduled orientations; the public schedule uses each labeled seed-orientation pair equally; and the complete sixteen-round map is invertible. Reference vectors and setup statistics make the prototype independently checkable.

The current construction evidence also includes an exact local diffusion profile and one bounded plaintext-avalanche integration check. Those measurements are implementation and integration checks, not security proofs and not evidence that scheduling is superior to a static matrix layer.

The comparative question is handled separately in **Structural Limits of Orientation Scheduling in Byte-Local GF(2) Diffusion Layers**, a manuscript currently under review. Its code and results are maintained at <https://github.com/ja9925ydbsu/structural-limits-orientation-scheduling> rather than in the current HESPN evidentiary chain.

Current Cryptologia-aligned support materials are under `cryptologia_support/`. Historical HESPN-v4 diagnostic material is retained under `legacy_hespn_v4/` only for provenance.
