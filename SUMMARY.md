# HESPN CiC construction-study summary

HESPN is used here as an experimental SPN harness for one construction question: can a family of rotated Hill-derived 8 x 8 matrices over GF(2) occupy the linear mix-layer position of an SPN while remaining explicit, reversible, locally diffusion-bounded, and reproducible?

The answer established by the current manuscript is limited but affirmative. Matrix rotation preserves invertibility, all scheduled orientations of accepted seeds satisfy B >= 4, the public schedule uses each labeled seed-orientation pair equally, and the complete sixteen-round map is invertible. Reference vectors and setup statistics make the prototype independently checkable.

The current revision adds an exact local diffusion profile and one plaintext-avalanche integration check. Those measurements are sanity checks on the completed harness, not security proofs and not evidence that scheduling is superior to a static matrix layer.

The paper deliberately leaves multi-round wide-trail bounds, exact weight-one recurrence, differential and linear trail optimization, matched schedule ablations, boomerang analysis, related-key analysis, and broader slide/reflection cryptanalysis outside scope. Historical files for several of those experiments remain in this repository solely for reproducibility.

Current submission materials are under `cic_submission/`, with `iacrj` as the preferred IACR format and `iacrcc` retained as a compatibility fallback.
