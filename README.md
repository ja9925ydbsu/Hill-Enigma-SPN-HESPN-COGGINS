# Hill-Enigma-SPN / HESPN

This repository contains Python code for the Hill-Enigma-SPN, abbreviated **HESPN**, a prototype cryptographic construction developed for experimental and manuscript-support purposes.

The code supports rerunning and checking computational experiments associated with the HESPN manuscript, including round-count diagnostics, NIST SP 800-22 style keystream evaluation, avalanche testing, branch-number filtering, algebraic-degree estimation, and reference test-vector generation.

## Repository contents

| File                      | Purpose                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `HESPNv4Rerun.py`         | Main HESPN v4 rerun program and experimental framework.                                                |
| `HESPNv4Diagnostics.py`   | Diagnostic script for reproducing characterization results, including round-count and keystream tests. |
| `hespn_test_vector_v4.py` | Reference test-vector generator for the 16-round HESPN v4 protocol.                                    |
| `README.md`               | Overview and usage instructions for this repository.                                                   |
| `LICENSE`                 | MIT License for this repository.                                                                       |
| `CITATION.cff`            | Citation metadata for users who wish to cite this software.                                            |

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

If you use this software in academic work, please cite it using the information provided in the `CITATION.cff` file included in this repository.

GitHub may also display a **Cite this repository** option when the `CITATION.cff` file is present in the repository root.

## Author / concept

Concept: Porter Coggins
Repository: `ja9925ydbsu/Hill-Enigma-SPN-HESPN-COGGINS`

## License

This repository is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This code is provided for research and reproducibility purposes. It has not been independently audited for production cryptographic use.


