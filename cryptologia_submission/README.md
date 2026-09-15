# Cryptologia submission preparation

Current manuscript title:

**Order-Eight Rotor-Scheduled Hill Matrices: Construction and Validation of a Byte-Local SPN Linear Layer**

Target journal: Taylor & Francis, **Cryptologia**.

Current submission-preparation date: **15 September 2026**.

The scientific content is the finalized HESPN Revision 6 construction. The Cryptologia transition changes journal-facing format and double-anonymous file organization; it does not change the construction, numerical results, reference vectors, figures, or claim boundaries.

## Submission files maintained author-side

- anonymous review manuscript, single-column/double-spaced/line-numbered;
- full author-identified manuscript;
- separate title page;
- Fig1 and Fig2 as separate PDF figure files;
- Cryptologia cover letter;
- anonymized HESPN-only reproducibility supplement.

The review copy uses author-year citation presentation. Repository-identifying information is omitted from the anonymous manuscript and supplement.

## Reviewer-facing claim boundary

- `B >= 4` is a byte-local GF(2) criterion and is not claimed optimal.
- No nontrivial multi-round active-S-box lower bound is established.
- The plaintext-avalanche experiment is a bounded implementation sanity check, not a security bound.
- The manuscript does not claim that rotor scheduling is superior to a matched static orientation or that HESPN is deployment-ready.

## Separate MDS-rotor study is not part of this submission

`active_sbox_bounds.csv` and its 5/25/30/50 active-S-box values come from `run_mds_rotor_study.py` for the separate **4 x 4 GF(2^8) MDS-rotor study**. They are excluded from the manuscript and the Cryptologia reproducibility package.

See `../docs/CRYPTOLOGIA_SUBMISSION_STATUS_2026_09_15.md`, `../docs/REPRODUCIBILITY_CRYPTOLOGIA_2026_09_15.md`, and `../docs/EXCLUDED_MDS_ROTOR_ARTIFACTS.md`.
