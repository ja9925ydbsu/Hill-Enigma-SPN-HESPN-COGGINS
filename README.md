# Hill-Enigma-SPN (HESPN): Rotor-Scheduled Hill Matrices as an SPN Mix Layer

This repository supports the construction study **Hill-Enigma-SPN: Rotor-Scheduled Hill Matrices as a Mix Layer in an Experimental SPN**.

As of 9 September 2026, the manuscript is being prepared for submission to Springer Nature's **International Journal of Information Security**. The IJIS manuscript preserves the narrow construction-feasibility scope developed in the final Revision 5 manuscript: **can matrix-element rotations previously reported for Hill-cipher variants be specified, filtered, scheduled, inverted, and used as the linear mix layer of a substitution-permutation network (SPN)?**

HESPN is the experimental harness used to answer that construction question. It is not presented as a deployment-ready cipher, a replacement for AES or another standardized primitive, or evidence that a public orientation schedule is more secure than a static matrix layer.

## What is being studied

The candidate mix layer uses sixteen key-derived 8 x 8 binary seed matrices over GF(2). Each seed is accepted only after verification of invertibility and a local branch-number floor. A public four-orientation schedule selects a rotated matrix by round and byte position. A fixed, well-characterized 8-bit S-box and explicit state-motion steps provide the surrounding SPN structure so that the linear layer can be exercised and inverted in a complete iterated harness.

The fixed nonlinear component is a methodological reference, not part of the novelty claim. References to Rijndael or MixColumns are used only to locate the construction within familiar SPN terminology and to distinguish local bit-level branch number over GF(2) from cross-byte MDS diffusion over GF(2^8).

## Construction-level claims supported here

The current IJIS submission manuscript supports the following limited claims:

1. Matrix rotation preserves invertibility for the scheduled family.
2. The four orientations reduce to two independent branch-number checks, B(M) and B(M^T).
3. Accepted seeds satisfy a local branch-number floor B >= 4 for every scheduled orientation.
4. The public schedule uses every labeled seed-orientation pair equally across sixteen rounds.
5. Every round and the complete sixteen-round mapping are reversible.
6. The rejection filter is feasible for the reported reference setup.
7. Reference vectors permit independent implementation checking.
8. Exact local one-bit spreading and a plaintext-avalanche experiment provide bounded integration checks, not security proofs.

For the reference configuration, all 64 oriented matrices have branch number 4. Across the 512 exact one-bit matrix applications, output weight ranges from 3 to 8 bits with mean 4.5390625. In the retained plaintext-avalanche integration run, the mean ciphertext Hamming distance reaches 63.9664 bits at sixteen rounds, with 95 percent confidence interval [63.81093, 64.12187]. The machine-readable verification material remains under `cic_submission/metrics/` because those data were generated during the Revision 5 preparation and are unchanged by the journal-format conversion.

## What this repository does not claim

The current construction paper does **not** establish a deployment security level or a nontrivial multi-round differential or linear bound. It does not claim that rotor scheduling improves security relative to a static orientation.

The following topics remain outside the construction question:

- exact weight-one recurrence and transfer analysis;
- matched static-versus-scheduled ablations;
- optimized differential or linear trail searches;
- random-mask linear screens;
- sampled differential collision screens;
- boomerang or returned-difference analysis;
- NIST statistical testing as security evidence;
- algebraic-degree screening;
- cross-byte MDS boundary experiments;
- related-key, slide, or reflection cryptanalysis beyond limited structural observations.

Older files covering some of these topics remain in the repository for historical reproducibility. They should not be read as evidence supporting the current manuscript's construction claims. See `docs/LEGACY_AND_OUT_OF_SCOPE_ANALYSES.md`.

## Rotor terminology, reflection, and slide structure

The Enigma analogy refers only to public stepping among matrix orientations. HESPN contains no reflector, and its round operation order is not self-inverse. The reference configuration also uses distinct round keys, so the period-four orientation schedule should not be confused with exact repetition of identical keyed rounds. These are structural observations only, not proofs of resistance to reflection, slide, or related-key attacks.

## Repository layout

### Submission-aligned verification materials

- `cic_submission/` contains the Revision 5 source notes and verification data from the final Communications in Cryptology formatting stage. These remain the evidentiary basis for the current IJIS format conversion.
- `cic_submission/metrics/` contains the two machine-readable construction-verification datasets.
- `cic_submission/VERIFICATION_METRICS_NOTE.md` documents the purpose, method, and interpretation boundary of those measurements.
- `docs/IJIS_SUBMISSION_STATUS_2026_09_09.md` records the current journal target and the manuscript-scope boundary.

### Historical implementation and experiments

The existing root-level HESPN scripts, result files, and `legacy_hespn_v4/` materials are retained to preserve prior reproducibility. Their presence does not enlarge the scope of the current paper.

## Manuscript status

The substantive manuscript master is the final Revision 5 construction-feasibility version. The current author-side submission package is being converted to Springer Nature / International Journal of Information Security formatting. The complete journal submission package and cover letter are maintained separately from this public software repository; they are not mirrored here by default.

## Reproducibility boundary

The repository separates three kinds of evidence:

- **formal construction properties**, such as invertibility and the local branch-number floor;
- **implementation checks**, such as reference vectors and round-trip verification;
- **bounded empirical integration checks**, such as local one-bit spreading and plaintext avalanche.

None of these categories should be interpreted as a complete cryptanalysis of the resulting permutation.

## License

The MIT License applies to the software in this repository. Manuscript text, figures, submission files, and result data should be cited and reused according to their applicable publication or repository terms.
