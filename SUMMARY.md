# HESPN IJIS construction-study summary

The current manuscript is **Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**.

HESPN is used as an experimental SPN harness for one construction question: can a family of rotated Hill-derived 8 x 8 matrices over GF(2) occupy the linear-layer position of a byte-oriented SPN while remaining explicit, reversible, locally diffusion-bounded, deterministically schedulable, and reproducible?

The answer established by the IJIS manuscript is limited but affirmative. The defined matrix rotation satisfies `R(M) = M^T J` and therefore preserves invertibility; accepted seeds satisfy the local `B >= 4` floor for every scheduled orientation; the public schedule gives deterministic uniform coverage of each labeled seed-orientation pair; and the complete sixteen-round map is invertible. Reference vectors and setup statistics make the prototype independently checkable.

The `B >= 4` threshold is a concrete feasible construction criterion that guarantees at least three active output bits for every one-bit input; it is not claimed optimal. Rejection sampling is master-key setup work rather than a per-block encryption cost in the reference construction.

The manuscript also reports an exact local one-bit diffusion profile and one plaintext-avalanche integration check. Those measurements are implementation checks on the completed harness, not security proofs and not evidence that scheduling is superior to a static matrix layer.

The paper deliberately keeps multi-round wide-trail bounds, exact weight-one recurrence, differential and linear trail optimization, matched schedule ablations, boomerang analysis, related-key analysis, and broader cross-byte cryptanalysis outside its evidentiary scope. Historical files for several of those experiments remain in this repository solely for provenance and separate research use.

Current IJIS-facing status and reproducibility documentation are in `docs/IJIS_SUBMISSION_STATUS_2026_09_14.md` and `docs/REPRODUCIBILITY_IJIS_2026_09_14.md`. The complete journal submission package is maintained separately as an author-side artifact.
