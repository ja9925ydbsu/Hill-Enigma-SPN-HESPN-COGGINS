# Hill-Enigma-SPN / HESPN

This repository contains experimental Python code and reproducibility materials for the Hill-Enigma-SPN, abbreviated **HESPN**, and related studies of rotor-scheduled Hill-derived diffusion layers in substitution-permutation networks.

The repository supports three research tracks:

1. **Original HESPN v4 implementation**
2. **Matched static-versus-rotor byte-local ablation**
3. **Cross-byte 4 x 4 GF(2^8) MDS-rotor boundary study**

This project is intended for research, manuscript review, and reproducibility support. It is not production cryptographic software, and it does not claim to replace the Advanced Encryption Standard, AES.

## Research tracks

### 1. Original HESPN v4 implementation

The original HESPN v4 programs implement and diagnose the byte-local rotor-scheduled construction used in the earlier HESPN study.

| File | Purpose |
|---|---|
| `HESPNv4Rerun.py` | Main HESPN v4 rerun program and experimental framework. |
| `HESPNv4Diagnostics.py` | Diagnostic script for round-count, keystream, avalanche, branch-number, and related characterization tests. |
| `hespn_test_vector_v4.py` | Normative test-vector generator for the 16-round HESPN v4 protocol. |

### 2. Matched static-versus-rotor byte-local ablation

The `matched_schedule_ablation/` directory contains a controlled comparison of the byte-local static and rotor schedules under matched deterministic key contexts and experimental conditions.

Principal materials include:

| Path | Purpose |
|---|---|
| `matched_schedule_ablation/matched_static_vs_rotor_experiment.py` | Main matched-ablation program. |
| `matched_schedule_ablation/results/paper_20260731/` | Validated result tables, metadata, and manuscript-support outputs. |

The experiment includes exact restricted weight-one trail enumeration, matched plaintext-avalanche testing, a sampled-differential collision screen, mean output-difference measurements, and structured-counter distance comparisons.

The exact inertness result is limited to the byte-local weight-one position geometry analyzed in the manuscript. It is not a general claim that every possible rotor schedule or wider diffusion layer is inert.

### 3. Cross-byte 4 x 4 GF(2^8) MDS-rotor boundary study

The `mds_rotor_spn_study/` directory contains a separate experimental SPN harness using an asymmetric 4 x 4 Cauchy MDS matrix over `GF(2^8)` and its four 90-degree orientations.

Five schedules are compared:

- `static`
- `rotor`
- `round_only`
- `position_only`
- `optimized`

Principal analyses include:

- verification that all four orientations are distinct, invertible, and MDS with branch number 5;
- certified active-S-box MILP bounds for 2, 4, 6, and 8 rounds;
- capped enumeration of minimum-activity support patterns;
- coefficient-sensitive differential and linear beam searches;
- captured low-active differential mass estimates;
- schedule optimization diagnostics;
- slide and reflection structural audits.

| Path | Purpose |
|---|---|
| `mds_rotor_spn_study/run_mds_rotor_study.py` | Main study runner. |
| `mds_rotor_spn_study/test_mds_rotor_study.py` | Unit tests. |
| `mds_rotor_spn_study/mds_rotor_core.py` | GF(2^8) arithmetic, matrix orientations, schedules, and SPN core. |
| `mds_rotor_spn_study/mds_rotor_milp.py` | Active-S-box MILP model and support-pattern enumeration. |
| `mds_rotor_spn_study/mds_rotor_trails.py` | Differential and linear trail-search routines. |
| `mds_rotor_spn_study/mds_rotor_schedule_optimizer.py` | Deterministic schedule-search heuristic. |
| `mds_rotor_spn_study/slide_reflection_audit.py` | Structural slide and reflection audit. |
| `mds_rotor_spn_study/results/standard_20260731/` | Validated standard-profile results. |

Because every matrix orientation retains MDS branch number 5, the certified activity bounds are schedule-independent. Schedule effects, when observed, arise in coefficient-sensitive candidates, multiplicities, aggregate retained classes, or structural periodicity.

The differential and linear beam-search outputs are heuristic candidates, not proofs of global optima. Captured low-active mass values are lower bounds on the probability mass retained by the pruned search, not complete differential-hull probabilities.

## Repository structure

```text
Hill-Enigma-SPN-HESPN-COGGINS/
├── README.md
├── CITATION.cff
├── LICENSE
├── HESPNv4Rerun.py
├── HESPNv4Diagnostics.py
├── hespn_test_vector_v4.py
├── matched_schedule_ablation/
│   ├── matched_static_vs_rotor_experiment.py
│   └── results/
│       └── paper_20260731/
└── mds_rotor_spn_study/
    ├── run_mds_rotor_study.py
    ├── test_mds_rotor_study.py
    ├── requirements.txt
    └── results/
        └── standard_20260731/
```

## Requirements

Use Python 3.10 or later when possible.

The original HESPN v4 programs may require:

```bash
python -m pip install argon2-cffi
```

The MDS-rotor study requires NumPy and SciPy:

```bash
python -m pip install -r mds_rotor_spn_study/requirements.txt
```

Matplotlib is optional for plots produced by the matched-ablation program:

```bash
python -m pip install matplotlib
```

## How to run

Clone the repository:

```bash
git clone https://github.com/ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS.git
cd Hill-Enigma-SPN-HESPN-COGGINS
```

### Original HESPN v4

Run the main rerun program:

```bash
python HESPNv4Rerun.py
```

Run the diagnostics program:

```bash
python HESPNv4Diagnostics.py
```

Generate the v4 normative test vector:

```bash
python hespn_test_vector_v4.py
```

### Matched byte-local ablation

```bash
cd matched_schedule_ablation
python matched_static_vs_rotor_experiment.py
```

This full experiment can require substantial runtime.

### Cross-byte MDS-rotor study

```bash
cd mds_rotor_spn_study
python -m pip install -r requirements.txt
python -m unittest -v test_mds_rotor_study
python run_mds_rotor_study.py --profile smoke --out smoke_results_local
```

For the larger validated profile:

```bash
python run_mds_rotor_study.py --profile standard --out standard_results_local
```

The standard and paper profiles can require considerably more time and memory than the smoke profile.

## Reproducibility

The repository includes deterministic test vectors, fixed seeds where appropriate, experiment metadata, CSV result tables, compact structural-audit summaries, and validated result directories.

The principal manuscript-support result directories are:

```text
matched_schedule_ablation/results/paper_20260731/
mds_rotor_spn_study/results/standard_20260731/
```

## Interpretation boundaries

The repository supports investigation of whether previously reported Hill-cipher matrix-element rotations can serve as scheduled modified mix layers in SPN architectures.

It does not claim:

- that HESPN is a replacement for AES;
- that any included construction is deployment-ready;
- that heuristic trail candidates are certified global optima;
- that structural periodicity alone demonstrates a slide or reflection attack;
- that one tested schedule is uniformly superior across all cryptanalytic metrics.

## Citation

Please cite this software using the metadata in [`CITATION.cff`](CITATION.cff). When the citation file is present in the repository root, GitHub may also display a **Cite this repository** option.

## License

This repository is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Author and concept

**Porter E. Coggins, III**  
Repository: `ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS`

## Disclaimer

This code is provided for research and reproducibility purposes. It has not been independently audited for production cryptographic use.
