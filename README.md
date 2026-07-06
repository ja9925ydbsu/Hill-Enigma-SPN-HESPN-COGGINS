# Hill-Enigma-SPN / HESPN

This repository contains Python code for the Hill-Enigma-SPN, abbreviated **HESPN**, a prototype cryptographic construction developed for experimental and manuscript-support purposes.

The code supports rerunning and checking the computational experiments associated with the HESPN manuscript, including round-count diagnostics, NIST SP 800-22 style keystream evaluation, avalanche testing, branch-number filtering, algebraic-degree estimation, and reference test-vector generation.

## Repository contents

| File                      | Purpose                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `HESPNv4Rerun.py`         | Main HESPN v4 rerun program and experimental framework.                                                |
| `HESPNv4Diagnostics.py`   | Diagnostic script for reproducing characterization results, including round-count and keystream tests. |
| `hespn_test_vector_v4.py` | Reference test-vector generator for the 16-round HESPN v4 protocol.                                    |

## Requirements

This project is written in Python.

Recommended:

```bash
python --version
```

Use Python 3.10 or later if available.

Some parts of the code may require the following package:

```bash
pip install argon2-cffi
```

## How to run

Clone the repository:

```bash
git clone https://github.com/ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS.git
cd Hill-Enigma-SPN-HESPN-COGGINS
```

Run the main rerun script:

```bash
python HESPNv4Rerun.py
```

Run the diagnostics script and save the output:

```bash
python HESPNv4Diagnostics.py > diagnostics_output.txt
```

Generate the v4 reference test vector:

```bash
python hespn_test_vector_v4.py
```

## Notes on computation time

Some diagnostic or confirmation runs may be computationally expensive. The heavier NIST-style confirmation settings may require significant runtime depending on the machine.

## Reproducibility

The diagnostic script is designed to support reproducible reruns. Some tests use deterministic seeds by default so that outputs can be compared across reruns.

## Project status

This repository is intended for research, manuscript review, and reproducibility support. It should be treated as experimental research code, not production cryptographic software.

## Citation

If you use this code in academic work, please cite the associated HESPN manuscript.

A formal citation file may be added later as `CITATION.cff`.

## Author / concept

Concept: Porter Coggins
Repository: `ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS`

## License

No license file is currently included. Until a license is added, all rights are reserved by default. Add a `LICENSE` file if you want to specify how others may use, copy, or modify this code.
