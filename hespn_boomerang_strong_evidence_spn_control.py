#!/usr/bin/env python3
"""
hespn_boomerang_strong_evidence.py

A statistically strengthened, checkpointed HESPN boomerang assessment suite.

This program is a complete replacement/companion runner for the earlier
16-round panel script. It imports the existing HESPN cipher implementation
rather than reimplementing HESPN.

Main improvements
-----------------
1. Many independently domain-separated keys.
2. Separate discovery and confirmation phases with fresh keys/random streams.
3. Correct family-wise and false-discovery-rate adjustments.
4. Exact binomial tests and exact Clopper-Pearson confidence intervals.
5. Key-cluster summaries and key-resampling bootstrap confidence intervals.
6. Full Hamming-weight and active-byte histograms when the oracle exposes
   encrypt/decrypt methods, plus output-bit and byte-activity assessments.
7. Expanded position/value panels through compact/strong/exhaustive profiles.
8. Reduced-round sensitivity calibration, a reversible Feistel null control,
   and a structurally comparable randomized SPN null control.
9. All, nondegenerate, and degenerate-swap accounting in the detailed backend.
10. Resume/configuration fingerprint protection and duplicate-run rejection.
11. Explicit counter-limit handling.
12. Stored/null probabilities are validated rather than silently recomputed.

Dependencies
------------
Python 3.10+ and SciPy:

    python -m pip install scipy

Expected engine file
--------------------
Place this script beside one of:

    boomerang_diagnositics_20260722.py
    boomerang_diagnostics_20260722.py
    HESPN_Boomerang_Analysis.py

or use --engine with the full path.

Recommended examples
--------------------
Write a strong panel plan without running:

    python hespn_boomerang_strong_evidence.py \
        --profile strong --phase plan --out-dir study_plan

Run discovery with 16 keys and 20,000 quartets per key/job:

    python hespn_boomerang_strong_evidence.py \
        --profile strong --phase discovery \
        --discovery-keys 16 --discovery-samples 20000 \
        --out-dir study_01

Resume safely:

    python hespn_boomerang_strong_evidence.py \
        --profile strong --phase discovery \
        --discovery-keys 16 --discovery-samples 20000 \
        --out-dir study_01 --resume

Run discovery followed by confirmation of the top ten candidates:

    python hespn_boomerang_strong_evidence_spn_control.py \
        --profile compact --phase full \
        --discovery-keys 16 --discovery-samples 20000 \
        --confirmation-keys 64 --confirmation-samples 100000 \
        --confirm-top-k 10 --out-dir study_full

Run HESPN beside both the generic Feistel and randomized-SPN controls:

    python hespn_boomerang_strong_evidence_spn_control.py \
        --profile compact --phase calibration \
        --null-control --spn-null-control \
        --spn-sbox random --control-scope calibration \
        --out-dir study_controls

Research caution
----------------
This is empirical cryptanalysis. Failure to detect a deviation is not a proof
that no boomerang distinguisher exists. Report per-candidate confidence bounds,
key-to-key variation, multiple-testing corrections, and the exact experimental
population tested.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import inspect
import json
import math
import os
import random
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence

try:
    from scipy import stats
except ImportError as exc:  # pragma: no cover - user environment dependent
    raise SystemExit(
        "SciPy is required. Install it with: python -m pip install scipy"
    ) from exc


PROGRAM_VERSION = "2.1.0"
BLOCK_BYTES = 16
BLOCK_BITS = 128
NONZERO_DIFFERENCE_SPACE = (1 << BLOCK_BITS) - 1
DEFAULT_ENGINE_NAMES = (
    "boomerang_diagnositics_20260722.py",
    "boomerang_diagnostics_20260722.py",
    "HESPN_Boomerang_Analysis.py",
)

BROAD_METRICS = (
    "mean_hw",
    "mean_active",
    "weight_leq_48",
    "active_bytes_leq_14",
    "hw_distribution",
    "active_distribution",
    "output_bits",
    "byte_activity",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PanelJob:
    job_id: str
    panel: str
    alpha: bytes
    delta: bytes
    alpha_description: str
    delta_description: str
    value_score: Optional[int] = None

    def metadata(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "panel": self.panel,
            "alpha_hex": self.alpha.hex().upper(),
            "delta_hex": self.delta.hex().upper(),
            "alpha_description": self.alpha_description,
            "delta_description": self.delta_description,
            "value_score": self.value_score,
        }


@dataclass(frozen=True)
class RunSpec:
    phase: str
    control: str
    rounds: int
    key_index: int
    samples: int
    job: PanelJob

    @property
    def run_id(self) -> str:
        return (
            f"{self.phase}|{self.control}|r{self.rounds:02d}|"
            f"k{self.key_index:04d}|{self.job.job_id}"
        )


@dataclass
class Moments:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        if self.count < 2:
            return float("nan")
        return self.m2 / (self.count - 1)

    @property
    def sd(self) -> float:
        variance = self.variance
        return math.sqrt(variance) if math.isfinite(variance) else float("nan")


@dataclass
class PopulationTelemetry:
    criteria: Sequence[str]
    full_byte_histograms: bool = False
    samples: int = 0
    hw_moments: Moments = field(default_factory=Moments)
    active_moments: Moments = field(default_factory=Moments)
    hw_histogram: list[int] = field(default_factory=lambda: [0] * 129)
    active_histogram: list[int] = field(default_factory=lambda: [0] * 17)
    output_bit_ones: list[int] = field(default_factory=lambda: [0] * 128)
    byte_nonzero: list[int] = field(default_factory=lambda: [0] * 16)
    byte_value_counts: Optional[list[list[int]]] = None
    criterion_successes: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.criterion_successes = {name: 0 for name in self.criteria}
        if self.full_byte_histograms:
            self.byte_value_counts = [[0] * 256 for _ in range(16)]

    def update(self, returned_difference: bytes, alpha: bytes) -> None:
        if len(returned_difference) != BLOCK_BYTES:
            raise ValueError("returned difference must be 16 bytes")

        value = int.from_bytes(returned_difference, "big")
        hw = value.bit_count()
        active = sum(byte != 0 for byte in returned_difference)

        self.samples += 1
        self.hw_moments.update(float(hw))
        self.active_moments.update(float(active))
        self.hw_histogram[hw] += 1
        self.active_histogram[active] += 1

        for bit_index in range(BLOCK_BITS):
            mask = 1 << (BLOCK_BITS - 1 - bit_index)
            if value & mask:
                self.output_bit_ones[bit_index] += 1

        for byte_index, byte_value in enumerate(returned_difference):
            if byte_value != 0:
                self.byte_nonzero[byte_index] += 1
            if self.byte_value_counts is not None:
                self.byte_value_counts[byte_index][byte_value] += 1

        for criterion in self.criteria:
            if evaluate_standard_criterion(
                criterion,
                returned_difference=returned_difference,
                alpha=alpha,
            ):
                self.criterion_successes[criterion] += 1

    def summary(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "mean_returned_hw": safe_float(self.hw_moments.mean),
            "sd_returned_hw": safe_float(self.hw_moments.sd),
            "mean_returned_active_bytes": safe_float(self.active_moments.mean),
            "sd_returned_active_bytes": safe_float(self.active_moments.sd),
            "criterion_successes": dict(self.criterion_successes),
            "hw_histogram": self.hw_histogram,
            "active_histogram": self.active_histogram,
            "output_bit_ones": self.output_bit_ones,
            "byte_nonzero": self.byte_nonzero,
            "byte_value_counts": self.byte_value_counts,
        }


@dataclass
class DetailedExperimentResult:
    samples_requested: int
    attempts: int
    degenerate_swaps: int
    all_population: PopulationTelemetry
    nondegenerate_population: PopulationTelemetry
    degenerate_population: PopulationTelemetry
    strict_quartets: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# General utilities
# ---------------------------------------------------------------------------


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def config_fingerprint(value: Any) -> str:
    return sha256_hex(canonical_json(value).encode("utf-8"))


def safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def active_mask(value: bytes) -> int:
    mask = 0
    for index, byte_value in enumerate(value):
        if byte_value:
            mask |= 1 << (len(value) - 1 - index)
    return mask


def clean_hex(text: str) -> str:
    value = text.strip().lower().replace("0x", "")
    for character in " _:-'":
        value = value.replace(character, "")
    return value


def parse_int_list(
    text: str,
    *,
    minimum: int,
    maximum: int,
    allow_empty: bool = False,
) -> list[int]:
    values: list[int] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item, 0)
        if not minimum <= value <= maximum:
            raise ValueError(
                f"value {value} is outside the permitted range "
                f"{minimum}..{maximum}"
            )
        values.append(value)
    if not values and not allow_empty:
        raise ValueError("at least one integer is required")
    return values


def parse_byte_pairs(text: str) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    for item in text.split(";"):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) != 2:
            raise ValueError("byte pairs must use the form AA:BB;CC:DD")
        alpha = int(parts[0], 16)
        delta = int(parts[1], 16)
        if not 1 <= alpha <= 0xFF or not 1 <= delta <= 0xFF:
            raise ValueError("byte differences must be nonzero values in 01..FF")
        pairs.append((alpha, delta))
    if not pairs:
        raise ValueError("at least one byte pair is required")
    return pairs


def format_eta(seconds: float) -> str:
    if seconds < 0 or not math.isfinite(seconds):
        return "unknown"
    minutes, second = divmod(int(seconds), 60)
    hours, minute = divmod(minutes, 60)
    if hours:
        return f"{hours:d}h {minute:02d}m {second:02d}s"
    if minutes:
        return f"{minute:d}m {second:02d}s"
    return f"{second:d}s"


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n")


def write_rows_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        atomic_write_text(path, "")
        return

    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def append_row_csv(path: Path, row: Mapping[str, Any]) -> None:
    """Append safely, expanding the CSV schema if a later backend adds fields."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size == 0:
        write_rows_csv(path, [row])
        return

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        existing_fields = next(reader)

    new_fields = [key for key in row if key not in existing_fields]
    if new_fields:
        existing_rows = read_csv_rows(path)
        expanded_fields = existing_fields + new_fields
        normalized_rows: list[dict[str, Any]] = []
        for existing in existing_rows:
            normalized_rows.append({key: existing.get(key, "") for key in expanded_fields})
        normalized_rows.append({key: row.get(key, "") for key in expanded_fields})
        write_rows_csv(path, normalized_rows)
        return

    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=existing_fields,
            extrasaction="ignore",
        )
        writer.writerow({key: row.get(key, "") for key in existing_fields})
        handle.flush()
        os.fsync(handle.fileno())


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSONL in {path} at line {line_number}"
                ) from exc
    return rows


def ensure_unique(rows: Sequence[Mapping[str, Any]], key_name: str) -> None:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        counts[str(row[key_name])] += 1
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    if duplicates:
        preview = ", ".join(duplicates[:5])
        raise ValueError(
            f"duplicate {key_name} values detected ({len(duplicates)}): {preview}"
        )


# ---------------------------------------------------------------------------
# Engine loading and key derivation
# ---------------------------------------------------------------------------


def find_engine_path(explicit: Optional[str]) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"engine file not found: {path}")
        return path

    script_dir = Path(__file__).resolve().parent
    for filename in DEFAULT_ENGINE_NAMES:
        candidate = script_dir / filename
        if candidate.is_file():
            return candidate

    names = ", ".join(DEFAULT_ENGINE_NAMES)
    raise FileNotFoundError(
        "Could not find the HESPN engine beside this script. "
        f"Expected one of: {names}. Use --engine with the full path."
    )


def load_engine(path: Path):
    specification = importlib.util.spec_from_file_location(
        "hespn_boomerang_engine",
        path,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load engine module from {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def key_namespace(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        master_key_hex=args.master_key_hex,
        kdf=args.kdf,
        password=args.password,
        salt_hex=args.salt_hex,
    )


def derive_session_key(
    engine,
    base_key: bytes,
    *,
    phase: str,
    control: str,
    rounds: int,
    key_index: int,
    mode: str,
) -> bytes:
    if mode == "engine":
        namespace_material = (
            f"{phase}|{control}|r{rounds}|k{key_index}"
        ).encode("utf-8")
        synthetic_index = int.from_bytes(
            hashlib.sha256(namespace_material).digest()[:8],
            "big",
        )
        return engine.derive_session_key(base_key, synthetic_index)

    if mode != "shake256":
        raise ValueError(f"unsupported session-key mode: {mode}")

    domain = b"HESPN-Boomerang-Strong-Evidence-v2\x00"
    material = b"|".join(
        (
            domain,
            phase.encode("utf-8"),
            control.encode("utf-8"),
            str(rounds).encode("ascii"),
            str(key_index).encode("ascii"),
            base_key,
        )
    )
    return hashlib.shake_256(material).digest(len(base_key))


def derive_rng_seed(
    base_seed: int,
    *,
    phase: str,
    control: str,
    rounds: int,
    key_index: int,
    job_id: str,
) -> int:
    material = b"|".join(
        (
            b"HESPN-Boomerang-RNG-v2",
            str(base_seed).encode("ascii"),
            phase.encode("utf-8"),
            control.encode("utf-8"),
            str(rounds).encode("ascii"),
            str(key_index).encode("ascii"),
            job_id.encode("utf-8"),
        )
    )
    return int.from_bytes(hashlib.sha256(material).digest()[:16], "big")


# ---------------------------------------------------------------------------
# Panel construction
# ---------------------------------------------------------------------------


def single_byte_difference(engine, byte_index: int, value: int) -> bytes:
    return engine.single_byte_difference(byte_index, value)


def single_bit_difference(engine, bit_index: int) -> bytes:
    return engine.single_bit_difference(bit_index)


def compute_bct_pairs(
    engine,
    number: int,
    include_manuscript_pair: bool = True,
) -> list[tuple[int, int, int]]:
    if number <= 0:
        return []

    bct = engine.compute_bct(engine.AES_SBOX)
    candidates: list[tuple[int, int, int, int]] = []
    for alpha in range(1, 256):
        for delta in range(1, 256):
            score = int(bct[alpha][delta])
            weight = alpha.bit_count() + delta.bit_count()
            candidates.append((score, -weight, alpha, delta))
    candidates.sort(reverse=True)

    selected: list[tuple[int, int, int]] = []
    seen_pairs: set[tuple[int, int]] = set()
    used_alpha: set[int] = set()
    used_delta: set[int] = set()

    if include_manuscript_pair:
        score = int(bct[0x07][0x10])
        selected.append((0x07, 0x10, score))
        seen_pairs.add((0x07, 0x10))
        used_alpha.add(0x07)
        used_delta.add(0x10)

    for score, _, alpha, delta in candidates:
        if len(selected) >= number:
            break
        pair = (alpha, delta)
        if pair in seen_pairs:
            continue
        if alpha in used_alpha or delta in used_delta:
            continue
        selected.append((alpha, delta, score))
        seen_pairs.add(pair)
        used_alpha.add(alpha)
        used_delta.add(delta)

    for score, _, alpha, delta in candidates:
        if len(selected) >= number:
            break
        pair = (alpha, delta)
        if pair in seen_pairs:
            continue
        selected.append((alpha, delta, score))
        seen_pairs.add(pair)

    return selected[:number]


def curated_pairs() -> list[tuple[int, int, Optional[int]]]:
    raw = [
        (0x07, 0x10),
        (0x01, 0x01),
        (0x02, 0x02),
        (0x04, 0x04),
        (0x08, 0x08),
        (0x10, 0x10),
        (0x20, 0x20),
        (0x40, 0x40),
        (0x80, 0x80),
        (0x03, 0x0C),
        (0x0F, 0xF0),
        (0x1B, 0x63),
        (0x55, 0xAA),
        (0xAA, 0x55),
        (0xFE, 0x01),
        (0xFF, 0xFF),
    ]
    return [(alpha, delta, None) for alpha, delta in raw]


def deduplicate_jobs(jobs: Iterable[PanelJob]) -> list[PanelJob]:
    seen: set[tuple[bytes, bytes, str]] = set()
    result: list[PanelJob] = []
    for job in jobs:
        key = (job.alpha, job.delta, job.panel)
        if key not in seen:
            seen.add(key)
            result.append(job)
    return result


def build_value_jobs(engine, args: argparse.Namespace) -> list[PanelJob]:
    byte_positions = parse_int_list(
        args.value_byte_positions,
        minimum=0,
        maximum=15,
    )

    pairs: list[tuple[int, int, Optional[int]]] = []
    if args.value_source in ("bct", "both"):
        pairs.extend(compute_bct_pairs(engine, args.top_bct_pairs))
    if args.value_source in ("curated", "both"):
        pairs.extend(curated_pairs())
    if args.byte_pairs:
        pairs.extend(
            (alpha, delta, None)
            for alpha, delta in parse_byte_pairs(args.byte_pairs)
        )

    unique_pairs: list[tuple[int, int, Optional[int]]] = []
    seen_pairs: set[tuple[int, int]] = set()
    for alpha_value, delta_value, score in pairs:
        pair = (alpha_value, delta_value)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_pairs.append((alpha_value, delta_value, score))

    jobs: list[PanelJob] = []
    for byte_index in byte_positions:
        for alpha_value, delta_value, score in unique_pairs:
            alpha = single_byte_difference(engine, byte_index, alpha_value)
            delta = single_byte_difference(engine, byte_index, delta_value)
            jobs.append(
                PanelJob(
                    job_id=(
                        f"value_b{byte_index:02d}_"
                        f"a{alpha_value:02X}_d{delta_value:02X}"
                    ),
                    panel="byte_values",
                    alpha=alpha,
                    delta=delta,
                    alpha_description=(
                        f"byte {byte_index}, value 0x{alpha_value:02X}, "
                        f"weight {alpha_value.bit_count()}"
                    ),
                    delta_description=(
                        f"byte {byte_index}, value 0x{delta_value:02X}, "
                        f"weight {delta_value.bit_count()}"
                    ),
                    value_score=score,
                )
            )
    return jobs


def build_bit_jobs(engine, args: argparse.Namespace) -> list[PanelJob]:
    bit_positions = parse_int_list(
        args.bit_positions,
        minimum=0,
        maximum=127,
    )
    offsets = parse_int_list(
        args.bit_offsets,
        minimum=-127,
        maximum=127,
    )

    jobs: list[PanelJob] = []
    for alpha_bit in bit_positions:
        for offset in offsets:
            delta_bit = (alpha_bit + offset) % 128
            alpha = single_bit_difference(engine, alpha_bit)
            delta = single_bit_difference(engine, delta_bit)
            jobs.append(
                PanelJob(
                    job_id=(
                        f"bit_a{alpha_bit:03d}_d{delta_bit:03d}_"
                        f"off{offset:+04d}"
                    ),
                    panel="bit_positions",
                    alpha=alpha,
                    delta=delta,
                    alpha_description=(
                        f"single bit {alpha_bit} "
                        f"(byte {alpha_bit // 8}, bit-in-byte {alpha_bit % 8}, "
                        "MSB-first)"
                    ),
                    delta_description=(
                        f"single bit {delta_bit} "
                        f"(byte {delta_bit // 8}, bit-in-byte {delta_bit % 8}, "
                        f"offset {offset:+d})"
                    ),
                )
            )
    return jobs


def build_byte_position_jobs(engine, args: argparse.Namespace) -> list[PanelJob]:
    byte_positions = parse_int_list(
        args.byte_positions,
        minimum=0,
        maximum=15,
    )
    offsets = parse_int_list(
        args.byte_offsets,
        minimum=-15,
        maximum=15,
    )
    alpha_value = int(args.position_alpha, 16)
    delta_value = int(args.position_delta, 16)
    if not 1 <= alpha_value <= 0xFF or not 1 <= delta_value <= 0xFF:
        raise ValueError("--position-alpha and --position-delta must be 01..FF")

    jobs: list[PanelJob] = []
    for alpha_byte in byte_positions:
        for offset in offsets:
            delta_byte = (alpha_byte + offset) % 16
            alpha = single_byte_difference(engine, alpha_byte, alpha_value)
            delta = single_byte_difference(engine, delta_byte, delta_value)
            jobs.append(
                PanelJob(
                    job_id=(
                        f"bytepos_ab{alpha_byte:02d}_db{delta_byte:02d}_"
                        f"a{alpha_value:02X}_d{delta_value:02X}_"
                        f"off{offset:+03d}"
                    ),
                    panel="byte_positions",
                    alpha=alpha,
                    delta=delta,
                    alpha_description=(
                        f"byte {alpha_byte}, value 0x{alpha_value:02X}"
                    ),
                    delta_description=(
                        f"byte {delta_byte}, value 0x{delta_value:02X}, "
                        f"byte offset {offset:+d}"
                    ),
                )
            )
    return jobs


def build_jobs(engine, args: argparse.Namespace) -> list[PanelJob]:
    jobs: list[PanelJob] = []
    selected_panels = set(args.panel)

    if "all" in selected_panels or "byte-values" in selected_panels:
        jobs.extend(build_value_jobs(engine, args))
    if "all" in selected_panels or "bit-positions" in selected_panels:
        jobs.extend(build_bit_jobs(engine, args))
    if "all" in selected_panels or "byte-positions" in selected_panels:
        jobs.extend(build_byte_position_jobs(engine, args))

    jobs = deduplicate_jobs(jobs)
    if not jobs:
        raise ValueError("the selected panel configuration produced no jobs")
    return jobs


def select_evenly_spaced(jobs: Sequence[PanelJob], number: int) -> list[PanelJob]:
    if number <= 0 or not jobs:
        return []
    if number >= len(jobs):
        return list(jobs)
    indices = {
        round(i * (len(jobs) - 1) / (number - 1))
        for i in range(number)
    } if number > 1 else {0}
    return [jobs[index] for index in sorted(indices)]


# ---------------------------------------------------------------------------
# Standard criteria and ideal model
# ---------------------------------------------------------------------------


def normalize_criterion_name(name: str) -> str:
    return name.strip().lower().replace(":", "_")


def parse_standard_criteria(text: str) -> list[str]:
    criteria = [normalize_criterion_name(item) for item in text.split(",") if item.strip()]
    supported = {
        "exact",
        "weight1",
        "same_weight",
        "active_mask",
        "weight_leq_48",
        "active_bytes_leq_14",
    }
    unsupported = [name for name in criteria if name not in supported]
    if unsupported:
        raise ValueError(
            "detailed backend supports only these criteria: "
            + ", ".join(sorted(supported))
            + "; unsupported: "
            + ", ".join(unsupported)
        )
    return criteria


def evaluate_standard_criterion(
    criterion: str,
    *,
    returned_difference: bytes,
    alpha: bytes,
) -> bool:
    criterion = normalize_criterion_name(criterion)
    returned_value = int.from_bytes(returned_difference, "big")
    alpha_value = int.from_bytes(alpha, "big")
    returned_hw = returned_value.bit_count()

    if criterion == "exact":
        return returned_difference == alpha
    if criterion == "weight1":
        return returned_hw == 1
    if criterion == "same_weight":
        return returned_hw == alpha_value.bit_count()
    if criterion == "active_mask":
        return active_mask(returned_difference) == active_mask(alpha)
    if criterion == "weight_leq_48":
        return returned_hw <= 48
    if criterion == "active_bytes_leq_14":
        return sum(byte != 0 for byte in returned_difference) <= 14
    raise ValueError(f"unknown criterion: {criterion}")


def standard_ideal_probability(criterion: str, alpha: bytes) -> float:
    criterion = normalize_criterion_name(criterion)
    alpha_value = int.from_bytes(alpha, "big")
    alpha_hw = alpha_value.bit_count()
    alpha_active = sum(byte != 0 for byte in alpha)

    if criterion == "exact":
        numerator = 1
    elif criterion == "weight1":
        numerator = BLOCK_BITS
    elif criterion == "same_weight":
        numerator = math.comb(BLOCK_BITS, alpha_hw)
    elif criterion == "active_mask":
        numerator = 255 ** alpha_active
    elif criterion == "weight_leq_48":
        numerator = sum(math.comb(BLOCK_BITS, weight) for weight in range(1, 49))
    elif criterion == "active_bytes_leq_14":
        numerator = sum(
            math.comb(BLOCK_BYTES, count) * (255 ** count)
            for count in range(1, 15)
        )
    else:
        raise ValueError(f"unknown criterion: {criterion}")

    return numerator / NONZERO_DIFFERENCE_SPACE


def ideal_hw_probabilities() -> list[float]:
    probabilities = [0.0] * 129
    denominator = float(NONZERO_DIFFERENCE_SPACE)
    for weight in range(1, 129):
        probabilities[weight] = math.comb(128, weight) / denominator
    return probabilities


def ideal_active_probabilities() -> list[float]:
    probabilities = [0.0] * 17
    denominator = float(NONZERO_DIFFERENCE_SPACE)
    for count in range(1, 17):
        probabilities[count] = (
            math.comb(16, count) * (255 ** count) / denominator
        )
    return probabilities


def ideal_byte_value_probabilities() -> list[float]:
    """Marginal byte distribution under a uniform nonzero 128-bit difference."""
    denominator = float(NONZERO_DIFFERENCE_SPACE)
    zero_probability = ((1 << 120) - 1) / denominator
    nonzero_probability = (1 << 120) / denominator
    return [zero_probability] + [nonzero_probability] * 255


# ---------------------------------------------------------------------------
# Oracle adapters and reversible null control
# ---------------------------------------------------------------------------


def _find_callable(obj: Any, candidates: Sequence[str]) -> Optional[Callable[[bytes], Any]]:
    for name in candidates:
        method = getattr(obj, name, None)
        if callable(method):
            return method
    return None


def oracle_supports_detailed_backend(oracle: Any) -> bool:
    encrypt = _find_callable(
        oracle,
        ("encrypt", "encrypt_block", "forward", "encipher"),
    )
    decrypt = _find_callable(
        oracle,
        ("decrypt", "decrypt_block", "inverse", "decipher"),
    )
    return encrypt is not None and decrypt is not None


def call_oracle_block(oracle: Any, direction: str, block: bytes) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("oracle block must be 16 bytes")

    if direction == "encrypt":
        method = _find_callable(
            oracle,
            ("encrypt", "encrypt_block", "forward", "encipher"),
        )
    elif direction == "decrypt":
        method = _find_callable(
            oracle,
            ("decrypt", "decrypt_block", "inverse", "decipher"),
        )
    else:
        raise ValueError(f"invalid direction: {direction}")

    if method is None:
        raise RuntimeError(
            f"oracle {type(oracle).__name__} does not expose a recognized "
            f"{direction} method"
        )

    result = method(block)
    if isinstance(result, tuple):
        result = result[0]
    if not isinstance(result, (bytes, bytearray)) or len(result) != BLOCK_BYTES:
        raise RuntimeError(
            f"oracle {direction} method returned {type(result).__name__}; "
            "expected 16-byte bytes"
        )
    return bytes(result)


class FeistelPermutationOracle:
    """A deterministic reversible 128-bit pseudorandom-permutation control."""

    def __init__(self, key: bytes, rounds: int = 10):
        if rounds < 4:
            raise ValueError("Feistel control requires at least four rounds")
        self.key = bytes(key)
        self.rounds = rounds

    def _f(self, round_index: int, right: int) -> int:
        digest = hashlib.sha256(
            b"HESPN-Feistel-Control-v1|"
            + self.key
            + round_index.to_bytes(4, "big")
            + right.to_bytes(8, "big")
        ).digest()
        return int.from_bytes(digest[:8], "big")

    def encrypt(self, block: bytes) -> bytes:
        value = int.from_bytes(block, "big")
        left = value >> 64
        right = value & ((1 << 64) - 1)
        for round_index in range(self.rounds):
            left, right = right, left ^ self._f(round_index, right)
        return ((left << 64) | right).to_bytes(16, "big")

    def decrypt(self, block: bytes) -> bytes:
        value = int.from_bytes(block, "big")
        left = value >> 64
        right = value & ((1 << 64) - 1)
        for round_index in range(self.rounds - 1, -1, -1):
            left, right = right ^ self._f(round_index, left), left
        return ((left << 64) | right).to_bytes(16, "big")


# The randomized SPN structure is deliberately independent of the experimental
# key. This gives every experimental key the same S-box/linear-layer structure,
# while the round keys remain independent across key indices. Reduced-round
# controls use prefixes of the same 16-round structure.
_SPN_STRUCTURE_CACHE: dict[tuple[int, str, str], dict[str, Any]] = {}
MASK_128 = (1 << 128) - 1


def _seeded_random(domain: bytes, seed: int, round_index: int = -1) -> random.Random:
    material = (
        domain
        + b"|"
        + str(seed).encode("ascii")
        + b"|"
        + str(round_index).encode("ascii")
    )
    value = int.from_bytes(hashlib.sha256(material).digest()[:16], "big")
    return random.Random(value)


def _rotate_left_128(value: int, amount: int) -> int:
    amount %= 128
    if amount == 0:
        return value & MASK_128
    return ((value << amount) | (value >> (128 - amount))) & MASK_128


def _rotate_right_128(value: int, amount: int) -> int:
    amount %= 128
    if amount == 0:
        return value & MASK_128
    return ((value >> amount) | (value << (128 - amount))) & MASK_128


def _undo_xor_shift_left_128(value: int, amount: int) -> int:
    result = value & MASK_128
    shift = amount
    while shift < 128:
        result ^= (result << shift) & MASK_128
        shift *= 2
    return result & MASK_128


def _undo_xor_shift_right_128(value: int, amount: int) -> int:
    result = value & MASK_128
    shift = amount
    while shift < 128:
        result ^= result >> shift
        shift *= 2
    return result & MASK_128


def _apply_linear_operations(
    value: int,
    operations: Sequence[tuple[str, int]],
) -> int:
    result = value & MASK_128
    for operation, amount in operations:
        if operation == "rotl":
            result = _rotate_left_128(result, amount)
        elif operation == "xsl":
            result ^= (result << amount) & MASK_128
        elif operation == "xsr":
            result ^= result >> amount
        else:
            raise ValueError(f"unknown SPN linear operation: {operation}")
    return result & MASK_128


def _invert_linear_operations(
    value: int,
    operations: Sequence[tuple[str, int]],
) -> int:
    result = value & MASK_128
    for operation, amount in reversed(operations):
        if operation == "rotl":
            result = _rotate_right_128(result, amount)
        elif operation == "xsl":
            result = _undo_xor_shift_left_128(result, amount)
        elif operation == "xsr":
            result = _undo_xor_shift_right_128(result, amount)
        else:
            raise ValueError(f"unknown SPN linear operation: {operation}")
    return result & MASK_128


def _linear_diffusion_statistics(
    operations: Sequence[tuple[str, int]],
) -> dict[str, float]:
    weights: list[int] = []
    inverse_weights: list[int] = []
    for bit_index in range(128):
        basis = 1 << bit_index
        transformed = _apply_linear_operations(basis, operations)
        recovered = _invert_linear_operations(transformed, operations)
        if recovered != basis:
            raise AssertionError("generated SPN linear layer is not invertible")
        weights.append(transformed.bit_count())
        inverse_weights.append(
            _invert_linear_operations(basis, operations).bit_count()
        )
    return {
        "minimum_single_bit_output_weight": min(weights),
        "mean_single_bit_output_weight": statistics.fmean(weights),
        "maximum_single_bit_output_weight": max(weights),
        "minimum_inverse_single_bit_output_weight": min(inverse_weights),
        "mean_inverse_single_bit_output_weight": statistics.fmean(inverse_weights),
        "maximum_inverse_single_bit_output_weight": max(inverse_weights),
    }


def _generate_invertible_linear_operations(
    *,
    structure_seed: int,
    round_index: int,
    minimum_single_bit_weight: int = 24,
) -> tuple[tuple[tuple[str, int], ...], dict[str, float]]:
    """
    Generate a fast, full-state, invertible GF(2)-linear layer.

    Rotations and xor-shifts are individually invertible and linear over GF(2).
    Their composition mixes across byte and bit boundaries while remaining much
    faster in Python than a dense 128x128 matrix multiplication.
    """
    rng = _seeded_random(
        b"HESPN-Randomized-SPN-Linear-v2",
        structure_seed,
        round_index,
    )
    for _attempt in range(100_000):
        operations: list[tuple[str, int]] = []
        # Alternating left/right triangular maps with rotations creates dense
        # full-state diffusion and avoids a fixed byte/column partition.
        for _stage in range(6):
            operations.append(("xsl", rng.randrange(1, 64)))
            operations.append(("xsr", rng.randrange(1, 64)))
            operations.append(("rotl", rng.randrange(1, 128)))
        candidate = tuple(operations)
        diffusion = _linear_diffusion_statistics(candidate)
        if (
            diffusion["minimum_single_bit_output_weight"]
            >= minimum_single_bit_weight
            and diffusion["minimum_inverse_single_bit_output_weight"]
            >= minimum_single_bit_weight
        ):
            return candidate, diffusion
    raise RuntimeError(
        "could not generate a sufficiently diffusive invertible SPN linear layer"
    )


def _generate_round_sbox(
    *,
    structure_seed: int,
    round_index: int,
) -> tuple[list[int], list[int]]:
    rng = _seeded_random(
        b"HESPN-Randomized-SPN-Sbox-v1",
        structure_seed,
        round_index,
    )
    sbox = list(range(256))
    rng.shuffle(sbox)
    inverse = [0] * 256
    for input_value, output_value in enumerate(sbox):
        inverse[output_value] = input_value
    return sbox, inverse


def _validate_aes_sbox(aes_sbox: Optional[Sequence[int]]) -> list[int]:
    if aes_sbox is None:
        raise ValueError(
            "--spn-sbox aes requires the imported engine to expose AES_SBOX"
        )
    values = [int(value) for value in aes_sbox]
    if len(values) != 256 or set(values) != set(range(256)):
        raise ValueError("engine AES_SBOX is not a 256-entry permutation")
    return values


def build_randomized_spn_structure(
    *,
    structure_seed: int,
    sbox_mode: str,
    aes_sbox: Optional[Sequence[int]],
    maximum_rounds: int = 16,
) -> dict[str, Any]:
    if maximum_rounds <= 0:
        raise ValueError("maximum SPN rounds must be positive")

    aes_values = _validate_aes_sbox(aes_sbox) if sbox_mode == "aes" else None
    aes_digest = (
        hashlib.sha256(bytes(aes_values)).hexdigest()
        if aes_values is not None
        else "random"
    )
    cache_key = (int(structure_seed), str(sbox_mode), aes_digest)
    cached = _SPN_STRUCTURE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    sboxes: list[tuple[int, ...]] = []
    inverse_sboxes: list[tuple[int, ...]] = []
    linear_operations: list[tuple[tuple[str, int], ...]] = []
    diffusion_statistics: list[dict[str, float]] = []

    for round_index in range(maximum_rounds):
        if sbox_mode == "random":
            sbox, inverse_sbox = _generate_round_sbox(
                structure_seed=structure_seed,
                round_index=round_index,
            )
        elif sbox_mode == "aes":
            assert aes_values is not None
            sbox = list(aes_values)
            inverse_sbox = [0] * 256
            for input_value, output_value in enumerate(sbox):
                inverse_sbox[output_value] = input_value
        else:
            raise ValueError(f"unsupported SPN S-box mode: {sbox_mode}")

        operations, diffusion = _generate_invertible_linear_operations(
            structure_seed=structure_seed,
            round_index=round_index,
        )
        sboxes.append(tuple(sbox))
        inverse_sboxes.append(tuple(inverse_sbox))
        linear_operations.append(operations)
        diffusion_statistics.append(diffusion)

    encoded = bytearray()
    encoded.extend(str(structure_seed).encode("ascii"))
    encoded.extend(sbox_mode.encode("ascii"))
    for round_index in range(maximum_rounds):
        encoded.extend(bytes(sboxes[round_index]))
        for operation, amount in linear_operations[round_index]:
            encoded.extend(operation.encode("ascii"))
            encoded.extend(int(amount).to_bytes(2, "big"))

    structure = {
        "structure_seed": int(structure_seed),
        "sbox_mode": sbox_mode,
        "maximum_rounds": maximum_rounds,
        "sboxes": tuple(sboxes),
        "inverse_sboxes": tuple(inverse_sboxes),
        "linear_operations": tuple(linear_operations),
        "diffusion_statistics": tuple(diffusion_statistics),
        "structure_fingerprint": hashlib.sha256(bytes(encoded)).hexdigest(),
    }
    _SPN_STRUCTURE_CACHE[cache_key] = structure
    return structure


class RandomizedSPNOracle:
    """
    Reversible randomized 128-bit SPN control.

    Structure:
      * 16-byte state / 128-bit block.
      * One independently generated bijective S-box per round, or the AES
        S-box in every round.
      * One independently generated invertible full-state 128-bit GF(2)-linear
        layer per round, implemented as a dense xorshift/rotation network.
      * One independent 128-bit round key before the first round and after
        every round.

    The randomized S-boxes and linear layers are fixed by structure_seed and
    shared across experimental keys. Round keys are derived independently from
    each session key.
    """

    def __init__(
        self,
        key: bytes,
        *,
        rounds: int,
        structure_seed: int,
        sbox_mode: str = "random",
        aes_sbox: Optional[Sequence[int]] = None,
    ):
        if not 1 <= rounds <= 16:
            raise ValueError("randomized SPN control supports 1..16 rounds")
        self.key = bytes(key)
        self.rounds = int(rounds)
        self.structure = build_randomized_spn_structure(
            structure_seed=int(structure_seed),
            sbox_mode=sbox_mode,
            aes_sbox=aes_sbox,
            maximum_rounds=16,
        )
        key_material = hashlib.shake_256(
            b"HESPN-Randomized-SPN-Round-Keys-v1|" + self.key
        ).digest(16 * (self.rounds + 1))
        self.round_keys = tuple(
            key_material[offset:offset + 16]
            for offset in range(0, len(key_material), 16)
        )

    @staticmethod
    def _substitute(state: bytes, sbox: Sequence[int]) -> bytes:
        return bytes(sbox[value] for value in state)

    @staticmethod
    def _linear(
        state: bytes,
        operations: Sequence[tuple[str, int]],
    ) -> bytes:
        value = int.from_bytes(state, "big")
        return _apply_linear_operations(value, operations).to_bytes(16, "big")

    @staticmethod
    def _inverse_linear(
        state: bytes,
        operations: Sequence[tuple[str, int]],
    ) -> bytes:
        value = int.from_bytes(state, "big")
        return _invert_linear_operations(value, operations).to_bytes(16, "big")

    def encrypt(self, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("SPN control block must be 16 bytes")
        state = xor_bytes(block, self.round_keys[0])
        for round_index in range(self.rounds):
            state = self._substitute(
                state,
                self.structure["sboxes"][round_index],
            )
            state = self._linear(
                state,
                self.structure["linear_operations"][round_index],
            )
            state = xor_bytes(state, self.round_keys[round_index + 1])
        return state

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != BLOCK_BYTES:
            raise ValueError("SPN control block must be 16 bytes")
        state = bytes(block)
        for round_index in range(self.rounds - 1, -1, -1):
            state = xor_bytes(state, self.round_keys[round_index + 1])
            state = self._inverse_linear(
                state,
                self.structure["linear_operations"][round_index],
            )
            state = self._substitute(
                state,
                self.structure["inverse_sboxes"][round_index],
            )
        return xor_bytes(state, self.round_keys[0])

    def metadata(self) -> dict[str, Any]:
        active = self.structure["diffusion_statistics"][:self.rounds]
        return {
            "control_design": "randomized_spn",
            "block_bits": 128,
            "state_bytes": 16,
            "effective_rounds": self.rounds,
            "sbox_mode": self.structure["sbox_mode"],
            "linear_layer": (
                "independent invertible full-state 128-bit GF(2) "
                "xorshift/rotation network per round"
            ),
            "round_keys": "independent 128-bit SHAKE256-derived keys",
            "structure_seed": self.structure["structure_seed"],
            "structure_fingerprint": self.structure["structure_fingerprint"],
            "minimum_active_round_single_bit_output_weight": min(
                int(item["minimum_single_bit_output_weight"])
                for item in active
            ),
            "minimum_active_round_inverse_single_bit_output_weight": min(
                int(item["minimum_inverse_single_bit_output_weight"])
                for item in active
            ),
        }

    def export_structure(self) -> dict[str, Any]:
        return {
            **self.metadata(),
            "maximum_rounds": self.structure["maximum_rounds"],
            "rounds": [
                {
                    "round": round_index + 1,
                    "sbox_sha256": hashlib.sha256(
                        bytes(self.structure["sboxes"][round_index])
                    ).hexdigest(),
                    "sbox": list(self.structure["sboxes"][round_index]),
                    "linear_operations": [
                        {"operation": operation, "amount": amount}
                        for operation, amount in self.structure[
                            "linear_operations"
                        ][round_index]
                    ],
                    **self.structure["diffusion_statistics"][round_index],
                }
                for round_index in range(self.structure["maximum_rounds"])
            ],
        }


# ---------------------------------------------------------------------------
# Detailed experiment backend
# ---------------------------------------------------------------------------


def run_detailed_boomerang_experiment(
    *,
    oracle: Any,
    alpha: bytes,
    delta: bytes,
    samples: int,
    criteria: Sequence[str],
    rng: random.Random,
    full_byte_histograms: bool,
    save_strict_quartets: int,
    progress: bool,
) -> DetailedExperimentResult:
    all_population = PopulationTelemetry(criteria, full_byte_histograms)
    nondegenerate_population = PopulationTelemetry(criteria, full_byte_histograms)
    degenerate_population = PopulationTelemetry(criteria, full_byte_histograms)
    strict_quartets: list[dict[str, Any]] = []
    degenerate_swaps = 0

    progress_step = max(samples // 20, 1)
    for sample_index in range(samples):
        plaintext_1 = rng.getrandbits(128).to_bytes(16, "big")
        plaintext_2 = xor_bytes(plaintext_1, alpha)

        ciphertext_1 = call_oracle_block(oracle, "encrypt", plaintext_1)
        ciphertext_2 = call_oracle_block(oracle, "encrypt", plaintext_2)

        modified_ciphertext_1 = xor_bytes(ciphertext_1, delta)
        modified_ciphertext_2 = xor_bytes(ciphertext_2, delta)

        degenerate = xor_bytes(ciphertext_1, ciphertext_2) == delta
        if degenerate:
            degenerate_swaps += 1

        returned_plaintext_1 = call_oracle_block(
            oracle,
            "decrypt",
            modified_ciphertext_1,
        )
        returned_plaintext_2 = call_oracle_block(
            oracle,
            "decrypt",
            modified_ciphertext_2,
        )
        returned_difference = xor_bytes(
            returned_plaintext_1,
            returned_plaintext_2,
        )

        all_population.update(returned_difference, alpha)
        if degenerate:
            degenerate_population.update(returned_difference, alpha)
        else:
            nondegenerate_population.update(returned_difference, alpha)

        if (
            returned_difference == alpha
            and len(strict_quartets) < save_strict_quartets
        ):
            strict_quartets.append({
                "sample_index": sample_index,
                "degenerate_swap": degenerate,
                "plaintext_1": plaintext_1.hex().upper(),
                "plaintext_2": plaintext_2.hex().upper(),
                "ciphertext_1": ciphertext_1.hex().upper(),
                "ciphertext_2": ciphertext_2.hex().upper(),
                "modified_ciphertext_1": modified_ciphertext_1.hex().upper(),
                "modified_ciphertext_2": modified_ciphertext_2.hex().upper(),
                "returned_plaintext_1": returned_plaintext_1.hex().upper(),
                "returned_plaintext_2": returned_plaintext_2.hex().upper(),
                "returned_difference": returned_difference.hex().upper(),
            })

        if progress and (
            (sample_index + 1) % progress_step == 0
            or sample_index + 1 == samples
        ):
            percentage = 100.0 * (sample_index + 1) / samples
            print(
                f"  detailed samples: {sample_index + 1:,}/{samples:,} "
                f"({percentage:5.1f}%)",
                flush=True,
            )

    return DetailedExperimentResult(
        samples_requested=samples,
        attempts=samples,
        degenerate_swaps=degenerate_swaps,
        all_population=all_population,
        nondegenerate_population=nondegenerate_population,
        degenerate_population=degenerate_population,
        strict_quartets=strict_quartets,
    )


# ---------------------------------------------------------------------------
# Statistical functions
# ---------------------------------------------------------------------------


def exact_binomial_assessment(
    successes: int,
    trials: int,
    probability: float,
    confidence_level: float = 0.95,
) -> dict[str, Optional[float]]:
    if trials <= 0 or not 0.0 <= probability <= 1.0:
        return {
            "p_value": None,
            "ci_lower": None,
            "ci_upper": None,
        }
    result = stats.binomtest(
        k=successes,
        n=trials,
        p=probability,
        alternative="two-sided",
    )
    interval = result.proportion_ci(
        confidence_level=confidence_level,
        method="exact",
    )
    return {
        "p_value": float(result.pvalue),
        "ci_lower": float(interval.low),
        "ci_upper": float(interval.high),
    }


def exact_zero_upper(trials: int, confidence_level: float = 0.95) -> Optional[float]:
    if trials <= 0:
        return None
    alpha = 1.0 - confidence_level
    return 1.0 - alpha ** (1.0 / trials)


def binomial_z(successes: int, trials: int, probability: float) -> Optional[float]:
    if trials <= 0 or not 0.0 < probability < 1.0:
        return None
    variance = trials * probability * (1.0 - probability)
    if variance <= 0:
        return None
    return (successes - trials * probability) / math.sqrt(variance)


def bh_adjust(p_values: Sequence[Optional[float]]) -> list[Optional[float]]:
    indexed = [
        (index, float(value))
        for index, value in enumerate(p_values)
        if value is not None and math.isfinite(float(value))
    ]
    adjusted: list[Optional[float]] = [None] * len(p_values)
    if not indexed:
        return adjusted

    indexed.sort(key=lambda item: item[1])
    count = len(indexed)
    running = 1.0
    for reverse_rank in range(count, 0, -1):
        index, p_value = indexed[reverse_rank - 1]
        candidate = p_value * count / reverse_rank
        running = min(running, candidate)
        adjusted[index] = min(1.0, running)
    return adjusted


def bonferroni_adjust(p_value: Optional[float], tests: int) -> Optional[float]:
    if p_value is None:
        return None
    return min(1.0, float(p_value) * max(tests, 1))


def t_mean_assessment(
    values: Sequence[float],
    null_mean: float,
    confidence_level: float = 0.95,
) -> dict[str, Optional[float]]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    count = len(finite)
    if count == 0:
        return {
            "key_mean": None,
            "between_key_sd": None,
            "key_standard_error": None,
            "key_t": None,
            "key_p_value": None,
            "key_ci_lower": None,
            "key_ci_upper": None,
        }

    mean = statistics.fmean(finite)
    if count < 2:
        return {
            "key_mean": mean,
            "between_key_sd": None,
            "key_standard_error": None,
            "key_t": None,
            "key_p_value": None,
            "key_ci_lower": None,
            "key_ci_upper": None,
        }

    sd = statistics.stdev(finite)
    standard_error = sd / math.sqrt(count)
    if standard_error == 0:
        if mean == null_mean:
            t_statistic = 0.0
            p_value = 1.0
        else:
            t_statistic = math.copysign(float("inf"), mean - null_mean)
            p_value = 0.0
        margin = 0.0
    else:
        t_statistic = (mean - null_mean) / standard_error
        p_value = float(
            2.0 * stats.t.sf(abs(t_statistic), df=count - 1)
        )
        critical = float(
            stats.t.ppf(0.5 + confidence_level / 2.0, df=count - 1)
        )
        margin = critical * standard_error

    return {
        "key_mean": mean,
        "between_key_sd": sd,
        "key_standard_error": standard_error,
        "key_t": safe_float(t_statistic),
        "key_p_value": p_value,
        "key_ci_lower": mean - margin,
        "key_ci_upper": mean + margin,
    }


def cluster_bootstrap_ci(
    values: Sequence[float],
    *,
    replicates: int,
    confidence_level: float,
    seed: int,
) -> tuple[Optional[float], Optional[float]]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    count = len(finite)
    if count < 2 or replicates <= 0:
        return None, None

    rng = random.Random(seed)
    bootstrap_means = []
    for _ in range(replicates):
        sample = [finite[rng.randrange(count)] for _ in range(count)]
        bootstrap_means.append(statistics.fmean(sample))
    bootstrap_means.sort()

    alpha = 1.0 - confidence_level
    low_index = max(0, min(replicates - 1, int(math.floor((alpha / 2) * replicates))))
    high_index = max(0, min(replicates - 1, int(math.ceil((1 - alpha / 2) * replicates)) - 1))
    return bootstrap_means[low_index], bootstrap_means[high_index]


def merge_sparse_bins(
    observed: Sequence[int],
    expected: Sequence[float],
    minimum_expected: float = 5.0,
) -> tuple[list[float], list[float]]:
    if len(observed) != len(expected):
        raise ValueError("observed and expected arrays must have equal lengths")

    merged_observed: list[float] = []
    merged_expected: list[float] = []
    current_observed = 0.0
    current_expected = 0.0

    for observed_value, expected_value in zip(observed, expected):
        current_observed += float(observed_value)
        current_expected += float(expected_value)
        if current_expected >= minimum_expected:
            merged_observed.append(current_observed)
            merged_expected.append(current_expected)
            current_observed = 0.0
            current_expected = 0.0

    if current_expected > 0:
        if merged_expected:
            merged_observed[-1] += current_observed
            merged_expected[-1] += current_expected
        else:
            merged_observed.append(current_observed)
            merged_expected.append(current_expected)

    return merged_observed, merged_expected


def histogram_goodness_of_fit(
    observed: Sequence[int],
    probabilities: Sequence[float],
) -> dict[str, Optional[float]]:
    trials = sum(int(value) for value in observed)
    if trials <= 0:
        return {
            "chi_square": None,
            "degrees_of_freedom": None,
            "p_value": None,
            "merged_bins": None,
        }

    expected = [trials * probability for probability in probabilities]
    merged_observed, merged_expected = merge_sparse_bins(observed, expected)
    if len(merged_observed) < 2:
        return {
            "chi_square": None,
            "degrees_of_freedom": None,
            "p_value": None,
            "merged_bins": len(merged_observed),
        }

    statistic = sum(
        (observed_value - expected_value) ** 2 / expected_value
        for observed_value, expected_value in zip(
            merged_observed,
            merged_expected,
        )
        if expected_value > 0
    )
    degrees_of_freedom = len(merged_observed) - 1
    p_value = float(stats.chi2.sf(statistic, degrees_of_freedom))
    return {
        "chi_square": statistic,
        "degrees_of_freedom": degrees_of_freedom,
        "p_value": p_value,
        "merged_bins": len(merged_observed),
    }


def proportion_power_sample_size(
    *,
    null_probability: float,
    alternative_probability: float,
    alpha: float,
    power: float,
) -> Optional[int]:
    if not (
        0 < null_probability < 1
        and 0 < alternative_probability < 1
        and 0 < alpha < 1
        and 0 < power < 1
        and null_probability != alternative_probability
    ):
        return None

    z_alpha = float(stats.norm.ppf(1 - alpha / 2))
    z_power = float(stats.norm.ppf(power))
    numerator = (
        z_alpha * math.sqrt(null_probability * (1 - null_probability))
        + z_power * math.sqrt(
            alternative_probability * (1 - alternative_probability)
        )
    ) ** 2
    denominator = (alternative_probability - null_probability) ** 2
    return math.ceil(numerator / denominator)


# ---------------------------------------------------------------------------
# Run flattening and telemetry persistence
# ---------------------------------------------------------------------------


def population_to_flat_fields(
    population: Mapping[str, Any],
    *,
    prefix: str,
    alpha: bytes,
) -> dict[str, Any]:
    samples = int(population["samples"])
    row: dict[str, Any] = {
        f"{prefix}_samples": samples,
        f"{prefix}_mean_returned_hw": population.get("mean_returned_hw"),
        f"{prefix}_sd_returned_hw": population.get("sd_returned_hw"),
        f"{prefix}_mean_returned_active_bytes": population.get(
            "mean_returned_active_bytes"
        ),
        f"{prefix}_sd_returned_active_bytes": population.get(
            "sd_returned_active_bytes"
        ),
    }

    if samples > 0 and population.get("mean_returned_hw") is not None:
        hw_standard_error = math.sqrt(32.0 / samples)
        active_variance = 16.0 * (255.0 / 256.0) * (1.0 / 256.0)
        active_standard_error = math.sqrt(active_variance / samples)
        row[f"{prefix}_mean_hw_z_vs_ideal"] = (
            float(population["mean_returned_hw"]) - 64.0
        ) / hw_standard_error
        row[f"{prefix}_mean_active_z_vs_ideal"] = (
            float(population["mean_returned_active_bytes"])
            - 16.0 * 255.0 / 256.0
        ) / active_standard_error
    else:
        row[f"{prefix}_mean_hw_z_vs_ideal"] = None
        row[f"{prefix}_mean_active_z_vs_ideal"] = None

    successes = population.get("criterion_successes", {})
    for criterion, count in successes.items():
        name = normalize_criterion_name(criterion)
        ideal = standard_ideal_probability(name, alpha)
        count = int(count)
        row[f"{prefix}_{name}_successes"] = count
        row[f"{prefix}_{name}_probability"] = count / samples if samples else None
        row[f"{prefix}_{name}_ideal_probability"] = ideal
        row[f"{prefix}_{name}_binomial_z"] = binomial_z(count, samples, ideal)
        exact = exact_binomial_assessment(count, samples, ideal)
        row[f"{prefix}_{name}_exact_p"] = exact["p_value"]
        row[f"{prefix}_{name}_ci95_lower"] = exact["ci_lower"]
        row[f"{prefix}_{name}_ci95_upper"] = exact["ci_upper"]
        if count == 0:
            row[f"{prefix}_{name}_zero_95_upper"] = exact_zero_upper(samples)

    return row


def flatten_detailed_result(
    *,
    spec: RunSpec,
    backend: str,
    session_key: bytes,
    result: DetailedExperimentResult,
    setup_seconds: float,
    experiment_seconds: float,
    configuration_fingerprint: str,
    primary_population: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    populations = {
        "all": result.all_population.summary(),
        "nondegenerate": result.nondegenerate_population.summary(),
        "degenerate": result.degenerate_population.summary(),
    }
    primary = populations[primary_population]

    row: dict[str, Any] = {
        "run_id": spec.run_id,
        "configuration_fingerprint": configuration_fingerprint,
        "program_version": PROGRAM_VERSION,
        "phase": spec.phase,
        "control": spec.control,
        "backend": backend,
        "rounds": spec.rounds,
        "job_id": spec.job.job_id,
        "panel": spec.job.panel,
        "key_index": spec.key_index,
        "alpha_hex_text": "'" + spec.job.alpha.hex().upper(),
        "delta_hex_text": "'" + spec.job.delta.hex().upper(),
        "alpha_description": spec.job.alpha_description,
        "delta_description": spec.job.delta_description,
        "value_score": spec.job.value_score,
        "samples_requested": spec.samples,
        "attempts": result.attempts,
        "primary_population": primary_population,
        "primary_samples": int(primary["samples"]),
        "degenerate_swaps": result.degenerate_swaps,
        "degenerate_rate": result.degenerate_swaps / result.attempts
        if result.attempts else None,
        "key_setup_seconds": setup_seconds,
        "experiment_seconds": experiment_seconds,
        "session_key_sha256_prefix": hashlib.sha256(session_key).hexdigest()[:16],
    }

    for population_name, population in populations.items():
        row.update(population_to_flat_fields(
            population,
            prefix=population_name,
            alpha=spec.job.alpha,
        ))

    for key, value in population_to_flat_fields(
        primary,
        prefix="primary",
        alpha=spec.job.alpha,
    ).items():
        row[key] = value

    telemetry_record = {
        "run_id": spec.run_id,
        "configuration_fingerprint": configuration_fingerprint,
        "phase": spec.phase,
        "control": spec.control,
        "backend": backend,
        "rounds": spec.rounds,
        "job_id": spec.job.job_id,
        "panel": spec.job.panel,
        "key_index": spec.key_index,
        "alpha_hex": spec.job.alpha.hex().upper(),
        "delta_hex": spec.job.delta.hex().upper(),
        "primary_population": primary_population,
        "populations": populations,
    }
    return row, telemetry_record


def flatten_engine_result(
    *,
    spec: RunSpec,
    session_key: bytes,
    result: Any,
    engine_criteria: Sequence[Any],
    setup_seconds: float,
    experiment_seconds: float,
    configuration_fingerprint: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "run_id": spec.run_id,
        "configuration_fingerprint": configuration_fingerprint,
        "program_version": PROGRAM_VERSION,
        "phase": spec.phase,
        "control": spec.control,
        "backend": "engine",
        "rounds": spec.rounds,
        "job_id": spec.job.job_id,
        "panel": spec.job.panel,
        "key_index": spec.key_index,
        "alpha_hex_text": "'" + spec.job.alpha.hex().upper(),
        "delta_hex_text": "'" + spec.job.delta.hex().upper(),
        "alpha_description": spec.job.alpha_description,
        "delta_description": spec.job.delta_description,
        "value_score": spec.job.value_score,
        "samples_requested": spec.samples,
        "attempts": getattr(result, "samples_used", spec.samples),
        "primary_population": "nondegenerate",
        "primary_samples": int(result.samples_used),
        "degenerate_swaps": int(result.degenerate_swaps),
        "degenerate_rate": (
            int(result.degenerate_swaps)
            / (int(result.samples_used) + int(result.degenerate_swaps))
        ) if (int(result.samples_used) + int(result.degenerate_swaps)) else None,
        "key_setup_seconds": setup_seconds,
        "experiment_seconds": experiment_seconds,
        "session_key_sha256_prefix": hashlib.sha256(session_key).hexdigest()[:16],
        "primary_mean_returned_hw": safe_float(result.mean_returned_hw),
        "primary_sd_returned_hw": safe_float(result.sd_returned_hw),
        "primary_mean_hw_z_vs_ideal": safe_float(
            result.returned_hw_mean_z_vs_ideal
        ),
        "primary_mean_returned_active_bytes": safe_float(
            result.mean_returned_active_bytes
        ),
        "primary_sd_returned_active_bytes": safe_float(
            result.sd_returned_active_bytes
        ),
        "primary_mean_active_z_vs_ideal": safe_float(
            result.returned_active_mean_z_vs_ideal
        ),
    }

    criterion_lookup = {
        normalize_criterion_name(criterion.name): criterion
        for criterion in engine_criteria
    }
    for criterion_row in result.criterion_rows:
        name = normalize_criterion_name(criterion_row["criterion"])
        successes = int(criterion_row["successes"])
        trials = int(criterion_row["trials"])
        stored_ideal = float(criterion_row["ideal_probability"])
        criterion = criterion_lookup.get(name)
        if criterion is not None:
            recomputed = float(criterion.ideal_probability(spec.job.alpha))
            if not math.isclose(stored_ideal, recomputed, rel_tol=1e-12, abs_tol=0.0):
                raise ValueError(
                    f"engine ideal-probability mismatch for {spec.run_id}, "
                    f"criterion {name}: stored={stored_ideal}, recomputed={recomputed}"
                )

        row[f"primary_{name}_successes"] = successes
        row[f"primary_{name}_probability"] = successes / trials if trials else None
        row[f"primary_{name}_ideal_probability"] = stored_ideal
        row[f"primary_{name}_binomial_z"] = binomial_z(
            successes,
            trials,
            stored_ideal,
        )
        exact = exact_binomial_assessment(successes, trials, stored_ideal)
        row[f"primary_{name}_exact_p"] = exact["p_value"]
        row[f"primary_{name}_ci95_lower"] = exact["ci_lower"]
        row[f"primary_{name}_ci95_upper"] = exact["ci_upper"]
        if successes == 0:
            row[f"primary_{name}_zero_95_upper"] = exact_zero_upper(trials)

    return row


# ---------------------------------------------------------------------------
# Aggregation and assessment outputs
# ---------------------------------------------------------------------------


def parse_optional_float(row: Mapping[str, str], key: str) -> Optional[float]:
    value = row.get(key)
    if value in (None, ""):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def parse_optional_int(row: Mapping[str, str], key: str) -> Optional[int]:
    value = row.get(key)
    if value in (None, ""):
        return None
    return int(value)


def aggregate_telemetry_records(
    records: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, int, str], dict[str, Any]]:
    grouped: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    seen_run_ids: dict[str, str] = {}
    for record in records:
        run_id = str(record["run_id"])
        digest = config_fingerprint(record)
        if run_id in seen_run_ids:
            if seen_run_ids[run_id] != digest:
                raise ValueError(f"conflicting duplicate telemetry for {run_id}")
            continue
        seen_run_ids[run_id] = digest

        key = (
            str(record["phase"]),
            str(record["control"]),
            int(record["rounds"]),
            str(record["job_id"]),
        )
        primary_name = str(record["primary_population"])
        population = record["populations"][primary_name]
        target = grouped.setdefault(key, {
            "samples": 0,
            "hw_histogram": [0] * 129,
            "active_histogram": [0] * 17,
            "output_bit_ones": [0] * 128,
            "byte_nonzero": [0] * 16,
            "byte_value_counts": None,
        })
        target["samples"] += int(population["samples"])
        for field_name, length in (
            ("hw_histogram", 129),
            ("active_histogram", 17),
            ("output_bit_ones", 128),
            ("byte_nonzero", 16),
        ):
            source = population[field_name]
            if len(source) != length:
                raise ValueError(
                    f"unexpected {field_name} length in telemetry for {record['run_id']}"
                )
            target[field_name] = [
                int(a) + int(b)
                for a, b in zip(target[field_name], source)
            ]

        source_byte_counts = population.get("byte_value_counts")
        if source_byte_counts is not None:
            if len(source_byte_counts) != 16 or any(
                len(byte_counts) != 256 for byte_counts in source_byte_counts
            ):
                raise ValueError(
                    f"unexpected byte_value_counts dimensions for {record['run_id']}"
                )
            if target["byte_value_counts"] is None:
                target["byte_value_counts"] = [[0] * 256 for _ in range(16)]
            target["byte_value_counts"] = [
                [int(a) + int(b) for a, b in zip(target_row, source_row)]
                for target_row, source_row in zip(
                    target["byte_value_counts"],
                    source_byte_counts,
                )
            ]
    return grouped


def infer_criteria_from_rows(rows: Sequence[Mapping[str, str]]) -> list[str]:
    criteria: set[str] = set()
    suffix = "_successes"
    prefix = "primary_"
    for row in rows:
        for key in row:
            if key.startswith(prefix) and key.endswith(suffix):
                criteria.add(key[len(prefix):-len(suffix)])
    return sorted(criteria)


def aggregate_results(
    *,
    per_key_rows: Sequence[Mapping[str, str]],
    telemetry_records: Sequence[Mapping[str, Any]],
    bootstrap_replicates: int,
    confidence_level: float,
    seed: int,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    ensure_unique(per_key_rows, "run_id")
    criteria = infer_criteria_from_rows(per_key_rows)
    telemetry = aggregate_telemetry_records(telemetry_records)

    by_group: dict[tuple[str, str, int, str], list[Mapping[str, str]]] = defaultdict(list)
    for row in per_key_rows:
        key = (
            row["phase"],
            row["control"],
            int(row["rounds"]),
            row["job_id"],
        )
        by_group[key].append(row)

    aggregate_rows: list[dict[str, Any]] = []
    bit_rows: list[dict[str, Any]] = []
    byte_rows: list[dict[str, Any]] = []
    byte_value_rows: list[dict[str, Any]] = []

    hw_probabilities = ideal_hw_probabilities()
    active_probabilities = ideal_active_probabilities()
    byte_value_probabilities = ideal_byte_value_probabilities()

    for group_key, rows in sorted(by_group.items()):
        phase, control, rounds, job_id = group_key
        first = rows[0]
        key_count = len({int(row["key_index"]) for row in rows})
        total_trials = sum(int(row["primary_samples"]) for row in rows)
        if total_trials <= 0:
            continue

        weights = [int(row["primary_samples"]) for row in rows]
        hw_values = [float(row["primary_mean_returned_hw"]) for row in rows]
        active_values = [
            float(row["primary_mean_returned_active_bytes"])
            for row in rows
        ]
        pooled_hw = sum(value * weight for value, weight in zip(hw_values, weights)) / total_trials
        pooled_active = sum(value * weight for value, weight in zip(active_values, weights)) / total_trials

        hw_key = t_mean_assessment(hw_values, 64.0, confidence_level)
        active_key = t_mean_assessment(
            active_values,
            16.0 * 255.0 / 256.0,
            confidence_level,
        )
        bootstrap_seed = int.from_bytes(
            hashlib.sha256(
                f"{seed}|{phase}|{control}|{rounds}|{job_id}".encode("utf-8")
            ).digest()[:8],
            "big",
        )
        hw_bootstrap = cluster_bootstrap_ci(
            hw_values,
            replicates=bootstrap_replicates,
            confidence_level=confidence_level,
            seed=bootstrap_seed,
        )
        active_bootstrap = cluster_bootstrap_ci(
            active_values,
            replicates=bootstrap_replicates,
            confidence_level=confidence_level,
            seed=bootstrap_seed ^ 0xA5A5A5A5,
        )

        aggregate: dict[str, Any] = {
            "phase": phase,
            "control": control,
            "rounds": rounds,
            "job_id": job_id,
            "panel": first["panel"],
            "keys_completed": key_count,
            "trials": total_trials,
            "alpha_hex_text": first["alpha_hex_text"],
            "delta_hex_text": first["delta_hex_text"],
            "alpha_description": first["alpha_description"],
            "delta_description": first["delta_description"],
            "value_score": first.get("value_score", ""),
            "mean_returned_hw": pooled_hw,
            "mean_hw_theoretical_z": (
                pooled_hw - 64.0
            ) / math.sqrt(32.0 / total_trials),
            "mean_hw_key_t": hw_key["key_t"],
            "mean_hw_key_p": hw_key["key_p_value"],
            "mean_hw_between_key_sd": hw_key["between_key_sd"],
            "mean_hw_key_ci_lower": hw_key["key_ci_lower"],
            "mean_hw_key_ci_upper": hw_key["key_ci_upper"],
            "mean_hw_bootstrap_ci_lower": hw_bootstrap[0],
            "mean_hw_bootstrap_ci_upper": hw_bootstrap[1],
            "mean_returned_active_bytes": pooled_active,
            "mean_active_theoretical_z": (
                pooled_active - 16.0 * 255.0 / 256.0
            ) / math.sqrt(
                16.0 * (255.0 / 256.0) * (1.0 / 256.0) / total_trials
            ),
            "mean_active_key_t": active_key["key_t"],
            "mean_active_key_p": active_key["key_p_value"],
            "mean_active_between_key_sd": active_key["between_key_sd"],
            "mean_active_key_ci_lower": active_key["key_ci_lower"],
            "mean_active_key_ci_upper": active_key["key_ci_upper"],
            "mean_active_bootstrap_ci_lower": active_bootstrap[0],
            "mean_active_bootstrap_ci_upper": active_bootstrap[1],
            "degenerate_swaps": sum(int(row["degenerate_swaps"]) for row in rows),
            "attempts": sum(int(row["attempts"]) for row in rows),
        }
        aggregate["degenerate_rate"] = (
            aggregate["degenerate_swaps"] / aggregate["attempts"]
            if aggregate["attempts"] else None
        )

        # Preserve separate all/nondegenerate/degenerate summaries whenever
        # the detailed backend supplied them. The primary population remains
        # the basis for formal ranking and multiple-testing correction.
        for population_prefix in ("all", "nondegenerate", "degenerate"):
            sample_key = f"{population_prefix}_samples"
            available_rows = [
                row for row in rows
                if row.get(sample_key) not in (None, "")
            ]
            if not available_rows:
                continue
            population_trials = sum(int(row[sample_key]) for row in available_rows)
            aggregate[f"{population_prefix}_trials"] = population_trials
            if population_trials > 0:
                for metric_name in (
                    "mean_returned_hw",
                    "mean_returned_active_bytes",
                ):
                    metric_key = f"{population_prefix}_{metric_name}"
                    weighted = sum(
                        float(row[metric_key]) * int(row[sample_key])
                        for row in available_rows
                        if row.get(metric_key) not in (None, "")
                    )
                    aggregate[metric_key] = weighted / population_trials

                for criterion in criteria:
                    success_key = f"{population_prefix}_{criterion}_successes"
                    if any(row.get(success_key) not in (None, "") for row in available_rows):
                        successes = sum(
                            int(row.get(success_key) or 0)
                            for row in available_rows
                        )
                        aggregate[success_key] = successes
                        aggregate[f"{population_prefix}_{criterion}_probability"] = (
                            successes / population_trials
                        )

        for criterion in criteria:
            success_key = f"primary_{criterion}_successes"
            ideal_key = f"primary_{criterion}_ideal_probability"
            successes = sum(int(row[success_key]) for row in rows)
            ideal_values = {
                float(row[ideal_key])
                for row in rows
                if row.get(ideal_key) not in (None, "")
            }
            if len(ideal_values) != 1:
                raise ValueError(
                    f"inconsistent stored ideal probabilities for "
                    f"{phase}/{control}/r{rounds}/{job_id}/{criterion}: "
                    f"{sorted(ideal_values)}"
                )
            ideal = ideal_values.pop()
            probability = successes / total_trials
            exact = exact_binomial_assessment(
                successes,
                total_trials,
                ideal,
                confidence_level,
            )
            key_proportions = [
                int(row[success_key]) / int(row["primary_samples"])
                for row in rows
            ]
            key_assessment = t_mean_assessment(
                key_proportions,
                ideal,
                confidence_level,
            )
            criterion_bootstrap = cluster_bootstrap_ci(
                key_proportions,
                replicates=bootstrap_replicates,
                confidence_level=confidence_level,
                seed=bootstrap_seed ^ int.from_bytes(
                    hashlib.sha256(criterion.encode("utf-8")).digest()[:8],
                    "big",
                ),
            )

            aggregate[f"{criterion}_successes"] = successes
            aggregate[f"{criterion}_probability"] = probability
            aggregate[f"{criterion}_ideal_probability"] = ideal
            aggregate[f"{criterion}_binomial_z"] = binomial_z(
                successes,
                total_trials,
                ideal,
            )
            aggregate[f"{criterion}_exact_p"] = exact["p_value"]
            aggregate[f"{criterion}_ci_lower"] = exact["ci_lower"]
            aggregate[f"{criterion}_ci_upper"] = exact["ci_upper"]
            aggregate[f"{criterion}_key_t"] = key_assessment["key_t"]
            aggregate[f"{criterion}_key_p"] = key_assessment["key_p_value"]
            aggregate[f"{criterion}_between_key_sd"] = key_assessment[
                "between_key_sd"
            ]
            aggregate[f"{criterion}_key_ci_lower"] = key_assessment[
                "key_ci_lower"
            ]
            aggregate[f"{criterion}_key_ci_upper"] = key_assessment[
                "key_ci_upper"
            ]
            aggregate[f"{criterion}_bootstrap_ci_lower"] = criterion_bootstrap[0]
            aggregate[f"{criterion}_bootstrap_ci_upper"] = criterion_bootstrap[1]
            if successes == 0:
                aggregate[f"{criterion}_zero_upper"] = exact_zero_upper(
                    total_trials,
                    confidence_level,
                )

        telemetry_key = (phase, control, rounds, job_id)
        if telemetry_key in telemetry:
            item = telemetry[telemetry_key]
            hw_gof = histogram_goodness_of_fit(
                item["hw_histogram"],
                hw_probabilities,
            )
            active_gof = histogram_goodness_of_fit(
                item["active_histogram"],
                active_probabilities,
            )
            aggregate.update({
                "hw_distribution_chi_square": hw_gof["chi_square"],
                "hw_distribution_df": hw_gof["degrees_of_freedom"],
                "hw_distribution_p": hw_gof["p_value"],
                "hw_distribution_merged_bins": hw_gof["merged_bins"],
                "active_distribution_chi_square": active_gof["chi_square"],
                "active_distribution_df": active_gof["degrees_of_freedom"],
                "active_distribution_p": active_gof["p_value"],
                "active_distribution_merged_bins": active_gof["merged_bins"],
            })

            bit_p_values: list[float] = []
            bit_start = len(bit_rows)
            for bit_index, ones in enumerate(item["output_bit_ones"]):
                assessment = exact_binomial_assessment(
                    int(ones),
                    int(item["samples"]),
                    0.5,
                    confidence_level,
                )
                bit_p_values.append(float(assessment["p_value"]))
                bit_rows.append({
                    "phase": phase,
                    "control": control,
                    "rounds": rounds,
                    "job_id": job_id,
                    "bit_index": bit_index,
                    "trials": item["samples"],
                    "ones": int(ones),
                    "one_probability": int(ones) / item["samples"],
                    "ideal_probability": 0.5,
                    "exact_p": assessment["p_value"],
                    "ci_lower": assessment["ci_lower"],
                    "ci_upper": assessment["ci_upper"],
                })
            bit_q_values = bh_adjust(bit_p_values)
            for offset, q_value in enumerate(bit_q_values):
                bit_rows[bit_start + offset]["within_job_bh_q"] = q_value
            aggregate["output_bits_min_p"] = min(bit_p_values)
            aggregate["output_bits_min_within_job_q"] = min(
                value for value in bit_q_values if value is not None
            )

            byte_p_values: list[float] = []
            byte_start = len(byte_rows)
            for byte_index, nonzero in enumerate(item["byte_nonzero"]):
                assessment = exact_binomial_assessment(
                    int(nonzero),
                    int(item["samples"]),
                    255.0 / 256.0,
                    confidence_level,
                )
                byte_p_values.append(float(assessment["p_value"]))
                byte_rows.append({
                    "phase": phase,
                    "control": control,
                    "rounds": rounds,
                    "job_id": job_id,
                    "byte_index": byte_index,
                    "trials": item["samples"],
                    "nonzero": int(nonzero),
                    "nonzero_probability": int(nonzero) / item["samples"],
                    "ideal_probability": 255.0 / 256.0,
                    "exact_p": assessment["p_value"],
                    "ci_lower": assessment["ci_lower"],
                    "ci_upper": assessment["ci_upper"],
                })
            byte_q_values = bh_adjust(byte_p_values)
            for offset, q_value in enumerate(byte_q_values):
                byte_rows[byte_start + offset]["within_job_bh_q"] = q_value
            aggregate["byte_activity_min_p"] = min(byte_p_values)
            aggregate["byte_activity_min_within_job_q"] = min(
                value for value in byte_q_values if value is not None
            )

            if item.get("byte_value_counts") is not None:
                byte_value_p_values: list[float] = []
                byte_value_start = len(byte_value_rows)
                for byte_index, counts in enumerate(item["byte_value_counts"]):
                    assessment = histogram_goodness_of_fit(
                        counts,
                        byte_value_probabilities,
                    )
                    p_value = assessment["p_value"]
                    if p_value is not None:
                        byte_value_p_values.append(float(p_value))
                    byte_value_rows.append({
                        "phase": phase,
                        "control": control,
                        "rounds": rounds,
                        "job_id": job_id,
                        "byte_index": byte_index,
                        "trials": item["samples"],
                        "chi_square": assessment["chi_square"],
                        "degrees_of_freedom": assessment["degrees_of_freedom"],
                        "exact_or_asymptotic_p": p_value,
                        "merged_bins": assessment["merged_bins"],
                    })
                if byte_value_p_values:
                    byte_value_q_values = bh_adjust(byte_value_p_values)
                    q_iterator = iter(byte_value_q_values)
                    for row_index in range(byte_value_start, len(byte_value_rows)):
                        if byte_value_rows[row_index]["exact_or_asymptotic_p"] is not None:
                            byte_value_rows[row_index]["within_job_bh_q"] = next(q_iterator)
                    aggregate["byte_values_min_p"] = min(byte_value_p_values)
                    aggregate["byte_values_min_within_job_q"] = min(
                        value for value in byte_value_q_values if value is not None
                    )

        aggregate_rows.append(aggregate)

    # Global BH corrections for all bit- and byte-level tests.
    global_bit_q = bh_adjust([row.get("exact_p") for row in bit_rows])
    for row, q_value in zip(bit_rows, global_bit_q):
        row["global_bh_q"] = q_value

    global_byte_q = bh_adjust([row.get("exact_p") for row in byte_rows])
    for row, q_value in zip(byte_rows, global_byte_q):
        row["global_bh_q"] = q_value

    global_byte_value_q = bh_adjust([
        row.get("exact_or_asymptotic_p") for row in byte_value_rows
    ])
    for row, q_value in zip(byte_value_rows, global_byte_value_q):
        row["global_bh_q"] = q_value

    apply_broad_multiple_testing(aggregate_rows)
    return aggregate_rows, bit_rows, byte_rows, byte_value_rows


def broad_p_value(row: Mapping[str, Any], metric: str) -> Optional[float]:
    if metric == "mean_hw":
        return row.get("mean_hw_key_p")
    if metric == "mean_active":
        return row.get("mean_active_key_p")
    if metric == "weight_leq_48":
        value = row.get("weight_leq_48_key_p")
        return value if value is not None else row.get("weight_leq_48_exact_p")
    if metric == "active_bytes_leq_14":
        value = row.get("active_bytes_leq_14_key_p")
        return value if value is not None else row.get("active_bytes_leq_14_exact_p")
    if metric == "hw_distribution":
        return row.get("hw_distribution_p")
    if metric == "active_distribution":
        return row.get("active_distribution_p")
    if metric == "output_bits":
        return row.get("output_bits_min_within_job_q")
    if metric == "byte_activity":
        return row.get("byte_activity_min_within_job_q")
    return None


def apply_broad_multiple_testing(rows: list[dict[str, Any]]) -> None:
    by_family: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        by_family[(row["phase"], row["control"], int(row["rounds"]))].append(index)

    for family_key, indices in by_family.items():
        test_entries: list[tuple[int, str, float]] = []
        for row_index in indices:
            row = rows[row_index]
            for metric in BROAD_METRICS:
                p_value = broad_p_value(row, metric)
                if p_value is not None and math.isfinite(float(p_value)):
                    test_entries.append((row_index, metric, float(p_value)))

        p_values = [entry[2] for entry in test_entries]
        q_values = bh_adjust(p_values)
        tests = len(test_entries)
        for (row_index, metric, p_value), q_value in zip(test_entries, q_values):
            rows[row_index][f"{metric}_broad_p"] = p_value
            rows[row_index][f"{metric}_bonferroni_p"] = bonferroni_adjust(
                p_value,
                tests,
            )
            rows[row_index][f"{metric}_bh_q"] = q_value

        for row_index in indices:
            row = rows[row_index]
            adjusted_values = [
                row.get(f"{metric}_bh_q")
                for metric in BROAD_METRICS
                if row.get(f"{metric}_bh_q") is not None
            ]
            row["broad_tests_in_family"] = tests
            row["minimum_broad_bh_q"] = min(adjusted_values) if adjusted_values else None
            row["broad_flag_q_le_0_05"] = (
                min(adjusted_values) <= 0.05 if adjusted_values else False
            )


def rank_candidates(
    aggregate_rows: Sequence[Mapping[str, Any]],
    *,
    phase: str,
    control: str,
    rounds: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in aggregate_rows:
        if (
            row["phase"] != phase
            or row["control"] != control
            or int(row["rounds"]) != rounds
        ):
            continue

        exact_successes = int(row.get("exact_successes", 0) or 0)
        q_value = row.get("minimum_broad_bh_q")
        q_sort = float(q_value) if q_value is not None else 1.0
        effect_scores = []
        for key in (
            "mean_hw_theoretical_z",
            "mean_active_theoretical_z",
            "weight_leq_48_binomial_z",
            "active_bytes_leq_14_binomial_z",
        ):
            value = row.get(key)
            if value is not None:
                effect_scores.append(abs(float(value)))
        maximum_z = max(effect_scores, default=0.0)
        candidates.append({
            "job_id": row["job_id"],
            "panel": row["panel"],
            "alpha_hex_text": row["alpha_hex_text"],
            "delta_hex_text": row["delta_hex_text"],
            "alpha_description": row["alpha_description"],
            "delta_description": row["delta_description"],
            "keys_completed": row["keys_completed"],
            "trials": row["trials"],
            "exact_successes": exact_successes,
            "minimum_broad_bh_q": q_value,
            "maximum_abs_primary_z": maximum_z,
            "broad_flag_q_le_0_05": row.get("broad_flag_q_le_0_05"),
            "ranking_q_sort": q_sort,
        })

    candidates.sort(
        key=lambda row: (
            int(row["exact_successes"] > 0),
            row["exact_successes"],
            -row["ranking_q_sort"],
            row["maximum_abs_primary_z"],
        ),
        reverse=True,
    )
    for rank, row in enumerate(candidates, start=1):
        row["rank"] = rank
        row.pop("ranking_q_sort", None)
    return candidates


def create_power_plan(
    jobs: Sequence[PanelJob],
    *,
    alpha_family: float,
    comparison_count: int,
    power: float,
) -> list[dict[str, Any]]:
    if not jobs:
        return []
    alpha_per_test = alpha_family / max(comparison_count, 1)
    representative_alpha = jobs[0].alpha
    rows: list[dict[str, Any]] = []
    for criterion in ("weight_leq_48", "active_bytes_leq_14"):
        null_probability = standard_ideal_probability(
            criterion,
            representative_alpha,
        )
        for relative_multiplier in (1.10, 1.25, 1.50, 2.00):
            alternative = min(
                1.0 - 1e-15,
                null_probability * relative_multiplier,
            )
            rows.append({
                "criterion": criterion,
                "null_probability": null_probability,
                "relative_multiplier": relative_multiplier,
                "alternative_probability": alternative,
                "family_alpha": alpha_family,
                "comparison_count": comparison_count,
                "alpha_per_test": alpha_per_test,
                "target_power": power,
                "approximate_trials_required": proportion_power_sample_size(
                    null_probability=null_probability,
                    alternative_probability=alternative,
                    alpha=alpha_per_test,
                    power=power,
                ),
            })

    for upper_bound in (1e-4, 1e-6, 1e-8):
        rows.append({
            "criterion": "zero_event_upper_bound",
            "null_probability": None,
            "relative_multiplier": None,
            "alternative_probability": None,
            "family_alpha": 0.05,
            "comparison_count": 1,
            "alpha_per_test": 0.05,
            "target_power": None,
            "target_upper_bound": upper_bound,
            "approximate_trials_required": math.ceil(
                math.log(0.05) / math.log(1.0 - upper_bound)
            ),
        })
    return rows


# ---------------------------------------------------------------------------
# Manifest, resume, and phase planning
# ---------------------------------------------------------------------------


def apply_profile_defaults(args: argparse.Namespace) -> None:
    profiles = {
        "compact": {
            "value_byte_positions": "0",
            "bit_positions": ",".join(str(i) for i in range(128)),
            "bit_offsets": "0",
            "byte_positions": ",".join(str(i) for i in range(16)),
            "byte_offsets": "0",
        },
        "strong": {
            "value_byte_positions": ",".join(str(i) for i in range(16)),
            "bit_positions": ",".join(str(i) for i in range(128)),
            "bit_offsets": "0,1,7,8,15,16,31,32,63,64",
            "byte_positions": ",".join(str(i) for i in range(16)),
            "byte_offsets": "0,1,2,4,8",
        },
        "exhaustive": {
            "value_byte_positions": ",".join(str(i) for i in range(16)),
            "bit_positions": ",".join(str(i) for i in range(128)),
            "bit_offsets": ",".join(str(i) for i in range(128)),
            "byte_positions": ",".join(str(i) for i in range(16)),
            "byte_offsets": ",".join(str(i) for i in range(16)),
        },
    }
    profile = profiles[args.profile]
    for name, value in profile.items():
        if getattr(args, name) is None:
            setattr(args, name, value)


def immutable_configuration(
    *,
    args: argparse.Namespace,
    engine_path: Path,
    jobs: Sequence[PanelJob],
    base_key: bytes,
) -> dict[str, Any]:
    return {
        "program": Path(__file__).name,
        "program_version": PROGRAM_VERSION,
        "engine_path": str(engine_path),
        "engine_sha256": file_sha256(engine_path),
        "base_key_sha256": hashlib.sha256(base_key).hexdigest(),
        "kdf": args.kdf,
        "salt_hex": clean_hex(args.salt_hex),
        "profile": args.profile,
        "panel": args.panel,
        "rounds": args.rounds,
        "calibration_rounds": args.calibration_rounds,
        "criteria": args.criteria,
        "backend": args.backend,
        "primary_population": args.primary_population,
        "session_key_mode": args.session_key_mode,
        "seed": args.seed,
        "value_source": args.value_source,
        "top_bct_pairs": args.top_bct_pairs,
        "value_byte_positions": args.value_byte_positions,
        "byte_pairs": args.byte_pairs,
        "bit_positions": args.bit_positions,
        "bit_offsets": args.bit_offsets,
        "byte_positions": args.byte_positions,
        "byte_offsets": args.byte_offsets,
        "position_alpha": args.position_alpha,
        "position_delta": args.position_delta,
        "discovery_keys": args.discovery_keys,
        "discovery_samples": args.discovery_samples,
        "confirmation_keys": args.confirmation_keys,
        "confirmation_samples": args.confirmation_samples,
        "confirm_top_k": args.confirm_top_k,
        "calibration_keys": args.calibration_keys,
        "calibration_samples": args.calibration_samples,
        "calibration_jobs": args.calibration_jobs,
        "null_control": args.null_control,
        "feistel_rounds": args.feistel_rounds,
        "spn_null_control": args.spn_null_control,
        "spn_sbox": args.spn_sbox,
        "spn_structure_seed": args.spn_structure_seed,
        "control_scope": args.control_scope,
        "full_byte_histograms": args.full_byte_histograms,
        "jobs": [job.metadata() for job in jobs],
    }


def prepare_manifest(
    *,
    out_dir: Path,
    configuration: Mapping[str, Any],
    resume: bool,
) -> str:
    fingerprint = config_fingerprint(configuration)
    manifest_path = out_dir / "study_manifest.json"

    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        existing_fingerprint = existing.get("configuration_fingerprint")
        if existing_fingerprint != fingerprint:
            raise ValueError(
                "output directory contains a different experimental "
                "configuration. Use a new --out-dir, or restore the exact "
                "original arguments."
            )
        if not resume:
            raise ValueError(
                "output directory already contains a study manifest. "
                "Use --resume or choose a new --out-dir."
            )
        return fingerprint

    manifest = {
        "created_utc": utc_now_iso(),
        "configuration_fingerprint": fingerprint,
        "configuration": configuration,
    }
    write_json(manifest_path, manifest)
    return fingerprint


def completed_run_ids(path: Path, expected_fingerprint: str) -> set[str]:
    rows = read_csv_rows(path)
    ensure_unique(rows, "run_id")
    completed: set[str] = set()
    for row in rows:
        if row.get("configuration_fingerprint") != expected_fingerprint:
            raise ValueError(
                f"fingerprint mismatch in existing per-key output for {row.get('run_id')}"
            )
        completed.add(row["run_id"])
    return completed


def read_confirmation_job_ids(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"confirmation jobs file not found: {path}")
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            value = value.get("job_ids", value.get("jobs", []))
        if not isinstance(value, list):
            raise ValueError("confirmation JSON must contain a list of job IDs")
        return [str(item["job_id"] if isinstance(item, dict) else item) for item in value]

    rows = read_csv_rows(path)
    if not rows or "job_id" not in rows[0]:
        raise ValueError("confirmation CSV must contain a job_id column")
    return [row["job_id"] for row in rows]


# ---------------------------------------------------------------------------
# Experiment execution
# ---------------------------------------------------------------------------


def resolve_backend(requested: str, oracle: Any) -> str:
    if requested == "engine":
        return "engine"
    if requested == "detailed":
        if not oracle_supports_detailed_backend(oracle):
            raise RuntimeError(
                "--backend detailed was requested, but the HESPN oracle does "
                "not expose recognized encrypt/decrypt methods"
            )
        return "detailed"
    if requested == "auto":
        return "detailed" if oracle_supports_detailed_backend(oracle) else "engine"
    raise ValueError(f"unknown backend: {requested}")


def build_hespn_oracle(engine, session_key: bytes, rounds: int) -> tuple[Any, float]:
    start = time.perf_counter()
    cipher = engine.HESPNCipher(
        session_key,
        max_rounds=max(rounds, 16),
    )
    oracle = engine.HESPNOracle(cipher, rounds)
    return oracle, time.perf_counter() - start


def run_single_spec(
    *,
    engine,
    engine_criteria: Sequence[Any],
    standard_criteria: Sequence[str],
    base_key: bytes,
    spec: RunSpec,
    args: argparse.Namespace,
    fingerprint: str,
) -> tuple[dict[str, Any], Optional[dict[str, Any]], list[dict[str, Any]]]:
    session_key = derive_session_key(
        engine,
        base_key,
        phase=spec.phase,
        control=spec.control,
        rounds=spec.rounds,
        key_index=spec.key_index,
        mode=args.session_key_mode,
    )

    control_metadata: dict[str, Any] = {}
    if spec.control == "feistel_null":
        setup_start = time.perf_counter()
        oracle = FeistelPermutationOracle(session_key, rounds=args.feistel_rounds)
        setup_seconds = time.perf_counter() - setup_start
        backend = "detailed"
        control_metadata = {
            "control_design": "feistel_prp",
            "block_bits": 128,
            "effective_rounds": args.feistel_rounds,
            "round_function": "SHA256-derived 64-bit function",
        }
    elif spec.control == "spn_null":
        setup_start = time.perf_counter()
        oracle = RandomizedSPNOracle(
            session_key,
            rounds=spec.rounds,
            structure_seed=args.spn_structure_seed,
            sbox_mode=args.spn_sbox,
            aes_sbox=getattr(engine, "AES_SBOX", None),
        )
        setup_seconds = time.perf_counter() - setup_start
        backend = "detailed"
        control_metadata = oracle.metadata()
    else:
        oracle, setup_seconds = build_hespn_oracle(
            engine,
            session_key,
            spec.rounds,
        )
        backend = resolve_backend(args.backend, oracle)

    local_seed = derive_rng_seed(
        args.seed,
        phase=spec.phase,
        control=spec.control,
        rounds=spec.rounds,
        key_index=spec.key_index,
        job_id=spec.job.job_id,
    )
    rng = random.Random(local_seed)
    experiment_start = time.perf_counter()

    if backend == "detailed":
        detailed = run_detailed_boomerang_experiment(
            oracle=oracle,
            alpha=spec.job.alpha,
            delta=spec.job.delta,
            samples=spec.samples,
            criteria=standard_criteria,
            rng=rng,
            full_byte_histograms=args.full_byte_histograms,
            save_strict_quartets=args.save_quartets_per_job,
            progress=not args.no_progress,
        )
        experiment_seconds = time.perf_counter() - experiment_start
        row, telemetry = flatten_detailed_result(
            spec=spec,
            backend=backend,
            session_key=session_key,
            result=detailed,
            setup_seconds=setup_seconds,
            experiment_seconds=experiment_seconds,
            configuration_fingerprint=fingerprint,
            primary_population=args.primary_population,
        )
        for key, value in control_metadata.items():
            row[f"control_{key}"] = value
        if control_metadata:
            telemetry["control_metadata"] = control_metadata
        return row, telemetry, detailed.strict_quartets

    result, _, _, quartets = engine.run_boomerang_experiment(
        oracle=oracle,
        oracle_name=f"HESPN-{spec.run_id}",
        alpha=spec.job.alpha,
        delta=spec.job.delta,
        samples=spec.samples,
        criteria=engine_criteria,
        rng=rng,
        rounds=spec.rounds,
        include_degenerate=False,
        cipher_for_tracing=None,
        splits=(),
        middle_samples=0,
        save_quartets=args.save_quartets_per_job,
        progress=not args.no_progress,
        counter_limit=(
            args.counter_limit
            if args.counter_limit is not None
            else max(spec.samples, 10_000)
        ),
    )
    experiment_seconds = time.perf_counter() - experiment_start
    row = flatten_engine_result(
        spec=spec,
        session_key=session_key,
        result=result,
        engine_criteria=engine_criteria,
        setup_seconds=setup_seconds,
        experiment_seconds=experiment_seconds,
        configuration_fingerprint=fingerprint,
    )
    return row, None, list(quartets or [])


def execute_specs(
    *,
    engine,
    engine_criteria: Sequence[Any],
    standard_criteria: Sequence[str],
    base_key: bytes,
    specs: Sequence[RunSpec],
    args: argparse.Namespace,
    out_dir: Path,
    fingerprint: str,
    completed: set[str],
) -> None:
    per_key_path = out_dir / "per_key_results.csv"
    telemetry_path = out_dir / "telemetry.jsonl"
    pending = [spec for spec in specs if spec.run_id not in completed]
    total = len(specs)
    print(f"Runs planned:   {total:,}")
    print(f"Already done:   {total - len(pending):,}")
    print(f"Runs remaining: {len(pending):,}")

    start = time.perf_counter()
    completed_now = 0
    for spec in pending:
        elapsed = time.perf_counter() - start
        eta = (
            elapsed / completed_now * (len(pending) - completed_now)
            if completed_now else float("nan")
        )
        print()
        print("-" * 88)
        print(
            f"Run {completed_now + 1:,}/{len(pending):,} | "
            f"{spec.phase} | {spec.control} | r={spec.rounds} | "
            f"key={spec.key_index} | {spec.job.job_id}"
        )
        if completed_now:
            print(f"Estimated remaining time: {format_eta(eta)}")
        print(f"Alpha: {spec.job.alpha.hex().upper()}")
        print(f"Delta: {spec.job.delta.hex().upper()}")

        row, telemetry, quartets = run_single_spec(
            engine=engine,
            engine_criteria=engine_criteria,
            standard_criteria=standard_criteria,
            base_key=base_key,
            spec=spec,
            args=args,
            fingerprint=fingerprint,
        )
        # Telemetry is written before the per-key completion row. If an
        # interruption occurs between these writes, resume reruns the job;
        # duplicate identical telemetry records are safely deduplicated.
        if telemetry is not None:
            append_jsonl(telemetry_path, telemetry)

        if quartets:
            quartet_path = out_dir / "quartets" / f"{sha256_hex(spec.run_id.encode())[:16]}.jsonl"
            for quartet in quartets:
                append_jsonl(quartet_path, {
                    "run_id": spec.run_id,
                    **quartet,
                })

        # The CSV row is the completion commit used by --resume.
        append_row_csv(per_key_path, row)
        completed.add(spec.run_id)
        completed_now += 1
        print(
            f"Completed in {float(row['experiment_seconds']):.3f}s | "
            f"primary samples={int(row['primary_samples']):,} | "
            f"exact={int(row.get('primary_exact_successes', 0) or 0):,} | "
            f"mean HW={float(row['primary_mean_returned_hw']):.6f} | "
            f"mean active={float(row['primary_mean_returned_active_bytes']):.6f}"
        )

        if (
            completed_now % args.checkpoint_every == 0
            or completed_now == len(pending)
        ):
            write_json(out_dir / "checkpoint_status.json", {
                "updated_utc": utc_now_iso(),
                "configuration_fingerprint": fingerprint,
                "runs_completed_in_current_call": completed_now,
                "runs_remaining_in_current_call": len(pending) - completed_now,
                "last_completed_run_id": spec.run_id,
                "per_key_results": str(per_key_path),
                "telemetry": str(telemetry_path),
            })


def build_control_comparison_rows(
    aggregate_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Create a descriptive, side-by-side HESPN/Feistel/SPN comparison."""
    controls = ("hespn", "feistel_null", "spn_null")
    metrics = (
        "keys_completed",
        "trials",
        "mean_returned_hw",
        "mean_hw_theoretical_z",
        "mean_returned_active_bytes",
        "mean_active_theoretical_z",
        "exact_successes",
        "exact_probability",
        "weight_leq_48_probability",
        "weight_leq_48_binomial_z",
        "active_bytes_leq_14_probability",
        "active_bytes_leq_14_binomial_z",
        "hw_distribution_p",
        "active_distribution_p",
        "output_bits_min_within_job_q",
        "byte_activity_min_within_job_q",
        "minimum_broad_bh_q",
        "broad_flag_q_le_0_05",
        "degenerate_rate",
    )
    grouped: dict[tuple[str, int, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in aggregate_rows:
        key = (str(row["phase"]), int(row["rounds"]), str(row["job_id"]))
        grouped[key][str(row["control"])] = row

    result: list[dict[str, Any]] = []
    for (phase, rounds, job_id), by_control in sorted(grouped.items()):
        if len(by_control) < 2:
            continue
        reference = by_control.get("hespn") or next(iter(by_control.values()))
        output: dict[str, Any] = {
            "phase": phase,
            "rounds": rounds,
            "job_id": job_id,
            "panel": reference.get("panel"),
            "alpha_hex_text": reference.get("alpha_hex_text"),
            "delta_hex_text": reference.get("delta_hex_text"),
            "alpha_description": reference.get("alpha_description"),
            "delta_description": reference.get("delta_description"),
            "controls_present": ";".join(
                control for control in controls if control in by_control
            ),
        }
        for control in controls:
            row = by_control.get(control)
            output[f"{control}_present"] = row is not None
            for metric in metrics:
                output[f"{control}_{metric}"] = row.get(metric) if row else None

        hespn = by_control.get("hespn")
        spn = by_control.get("spn_null")
        feistel = by_control.get("feistel_null")
        for comparison_name, other in (
            ("spn_minus_hespn", spn),
            ("feistel_minus_hespn", feistel),
        ):
            if hespn is not None and other is not None:
                for metric in (
                    "mean_returned_hw",
                    "mean_hw_theoretical_z",
                    "mean_returned_active_bytes",
                    "mean_active_theoretical_z",
                    "exact_probability",
                    "weight_leq_48_probability",
                    "active_bytes_leq_14_probability",
                    "degenerate_rate",
                ):
                    left = safe_float(other.get(metric))
                    right = safe_float(hespn.get(metric))
                    output[f"{comparison_name}_{metric}"] = (
                        left - right
                        if left is not None and right is not None
                        else None
                    )
        result.append(output)
    return result


def rebuild_outputs(
    *,
    out_dir: Path,
    jobs: Optional[Sequence[PanelJob]],
    args: argparse.Namespace,
    provisional: bool,
) -> list[dict[str, Any]]:
    per_key_rows = read_csv_rows(out_dir / "per_key_results.csv")
    telemetry_records = read_jsonl(out_dir / "telemetry.jsonl")
    if not per_key_rows:
        return []

    aggregate_rows, bit_rows, byte_rows, byte_value_rows = aggregate_results(
        per_key_rows=per_key_rows,
        telemetry_records=telemetry_records,
        bootstrap_replicates=(
            min(args.bootstrap_replicates, 500)
            if provisional
            else args.bootstrap_replicates
        ),
        confidence_level=args.confidence_level,
        seed=args.seed,
    )
    write_rows_csv(out_dir / "aggregate_results.csv", aggregate_rows)
    write_rows_csv(out_dir / "per_bit_results.csv", bit_rows)
    write_rows_csv(out_dir / "per_byte_activity_results.csv", byte_rows)
    write_rows_csv(
        out_dir / "per_byte_value_distribution_results.csv",
        byte_value_rows,
    )
    write_rows_csv(
        out_dir / "control_comparison.csv",
        build_control_comparison_rows(aggregate_rows),
    )

    for phase, control, rounds in sorted({
        (row["phase"], row["control"], int(row["rounds"]))
        for row in aggregate_rows
    }):
        ranked = rank_candidates(
            aggregate_rows,
            phase=phase,
            control=control,
            rounds=rounds,
        )
        safe_name = f"ranked_{phase}_{control}_r{rounds:02d}.csv"
        write_rows_csv(out_dir / safe_name, ranked)

    if jobs is not None:
        comparison_count = max(len(jobs) * len(BROAD_METRICS), 1)
        power_rows = create_power_plan(
            jobs,
            alpha_family=args.alpha_family,
            comparison_count=comparison_count,
            power=args.target_power,
        )
        write_rows_csv(out_dir / "power_plan.csv", power_rows)

    return aggregate_rows


def make_phase_specs(
    *,
    phase: str,
    control: str,
    rounds: Sequence[int],
    jobs: Sequence[PanelJob],
    keys: int,
    samples: int,
) -> list[RunSpec]:
    return [
        RunSpec(
            phase=phase,
            control=control,
            rounds=round_count,
            key_index=key_index,
            samples=samples,
            job=job,
        )
        for round_count in rounds
        for key_index in range(keys)
        for job in jobs
    ]


def select_confirmation_jobs(
    *,
    jobs: Sequence[PanelJob],
    aggregate_rows: Sequence[Mapping[str, Any]],
    args: argparse.Namespace,
    out_dir: Path,
) -> list[PanelJob]:
    lookup = {job.job_id: job for job in jobs}
    if args.confirmation_jobs_file:
        requested = read_confirmation_job_ids(
            Path(args.confirmation_jobs_file).expanduser().resolve()
        )
    else:
        ranked = rank_candidates(
            aggregate_rows,
            phase="discovery",
            control="hespn",
            rounds=args.rounds,
        )
        if not ranked:
            raise ValueError(
                "no completed discovery results are available to select "
                "confirmation candidates"
            )
        requested = [row["job_id"] for row in ranked[:args.confirm_top_k]]

    missing = [job_id for job_id in requested if job_id not in lookup]
    if missing:
        raise ValueError(
            "confirmation job IDs not present in panel: " + ", ".join(missing[:10])
        )

    selected = [lookup[job_id] for job_id in requested]
    confirmation_plan = {
        "created_utc": utc_now_iso(),
        "selection_source": (
            str(Path(args.confirmation_jobs_file).expanduser().resolve())
            if args.confirmation_jobs_file
            else "discovery ranking"
        ),
        "rounds": args.rounds,
        "keys": args.confirmation_keys,
        "samples_per_key_job": args.confirmation_samples,
        "jobs": [job.metadata() for job in selected],
    }
    plan_path = out_dir / "confirmation_plan.json"
    if plan_path.exists():
        existing = json.loads(plan_path.read_text(encoding="utf-8"))
        if config_fingerprint(existing.get("jobs", [])) != config_fingerprint(
            confirmation_plan["jobs"]
        ):
            raise ValueError(
                "existing confirmation plan differs from newly selected jobs; "
                "use a new output directory"
            )
    else:
        write_json(plan_path, confirmation_plan)
        write_rows_csv(out_dir / "confirmation_plan.csv", [job.metadata() for job in selected])
    return selected


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Run a statistically strengthened HESPN boomerang discovery, "
            "calibration, and confirmation study with Feistel and randomized "
            "SPN controls."
        ),
    )
    parser.add_argument("--engine", help="path to the HESPN diagnostics engine")
    parser.add_argument(
        "--phase",
        choices=("plan", "calibration", "discovery", "confirmation", "full", "analyze"),
        default="plan",
        help=(
            "plan writes files only; full runs calibration, discovery, then "
            "confirmation; analyze rebuilds summaries from existing outputs"
        ),
    )
    parser.add_argument(
        "--profile",
        choices=("compact", "strong", "exhaustive"),
        default="compact",
    )
    parser.add_argument(
        "--panel",
        action="append",
        choices=("all", "byte-values", "bit-positions", "byte-positions"),
        default=None,
    )
    parser.add_argument("--rounds", type=int, default=16, choices=range(1, 17))
    parser.add_argument(
        "--calibration-rounds",
        default="4,6,8,10,12,14,16",
        help="comma-separated HESPN round counts for sensitivity calibration",
    )

    parser.add_argument("--discovery-keys", type=int, default=16)
    parser.add_argument("--discovery-samples", type=int, default=20_000)
    parser.add_argument("--confirmation-keys", type=int, default=64)
    parser.add_argument("--confirmation-samples", type=int, default=100_000)
    parser.add_argument("--confirm-top-k", type=int, default=10)
    parser.add_argument(
        "--confirmation-jobs-file",
        help="optional CSV/JSON file containing predeclared confirmation job IDs",
    )
    parser.add_argument("--calibration-keys", type=int, default=8)
    parser.add_argument("--calibration-samples", type=int, default=20_000)
    parser.add_argument("--calibration-jobs", type=int, default=8)
    parser.add_argument(
        "--null-control",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include a reversible Feistel pseudorandom-permutation null control",
    )
    parser.add_argument("--feistel-rounds", type=int, default=10)
    parser.add_argument(
        "--spn-null-control",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "include a structurally comparable randomized 128-bit SPN null "
            "control with the same tested round counts as HESPN"
        ),
    )
    parser.add_argument(
        "--spn-sbox",
        choices=("random", "aes"),
        default="random",
        help=(
            "use independent randomized bijective S-boxes per SPN-control "
            "round, or the engine AES S-box in every round"
        ),
    )
    parser.add_argument(
        "--spn-structure-seed",
        type=int,
        default=20260723,
        help=(
            "seed fixing the SPN-control S-boxes and invertible linear layers; "
            "round keys still vary independently by experimental key"
        ),
    )
    parser.add_argument(
        "--control-scope",
        choices=("calibration", "discovery", "both"),
        default="calibration",
        help=(
            "run enabled null controls in calibration only, discovery only, "
            "or both phases"
        ),
    )

    parser.add_argument(
        "--criteria",
        default=(
            "exact,weight1,same_weight,active_mask,"
            "weight_leq:48,active_bytes_leq:14"
        ),
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "detailed", "engine"),
        default="auto",
        help=(
            "detailed collects full telemetry; auto falls back to the engine "
            "runner if the oracle lacks encrypt/decrypt methods"
        ),
    )
    parser.add_argument(
        "--primary-population",
        choices=("all", "nondegenerate"),
        default="nondegenerate",
    )
    parser.add_argument(
        "--full-byte-histograms",
        action="store_true",
        help="store all 16x256 returned-byte histograms per run; output can be large",
    )
    parser.add_argument("--save-quartets-per-job", type=int, default=0)
    parser.add_argument("--counter-limit", type=int)
    parser.add_argument("--no-progress", action="store_true")

    parser.add_argument("--seed", type=int, default=20260724)
    parser.add_argument(
        "--session-key-mode",
        choices=("shake256", "engine"),
        default="shake256",
    )
    parser.add_argument("--bootstrap-replicates", type=int, default=5000)
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=10,
        help="rebuild aggregate assessment files after this many completed runs",
    )
    parser.add_argument("--confidence-level", type=float, default=0.95)
    parser.add_argument("--alpha-family", type=float, default=0.05)
    parser.add_argument("--target-power", type=float, default=0.80)

    parser.add_argument(
        "--value-source",
        choices=("bct", "curated", "both"),
        default="both",
    )
    parser.add_argument("--top-bct-pairs", type=int, default=16)
    parser.add_argument("--value-byte-positions")
    parser.add_argument("--byte-pairs", default="")
    parser.add_argument("--bit-positions")
    parser.add_argument("--bit-offsets")
    parser.add_argument("--byte-positions")
    parser.add_argument("--byte-offsets")
    parser.add_argument("--position-alpha", default="07")
    parser.add_argument("--position-delta", default="10")

    parser.add_argument("--master-key-hex")
    parser.add_argument(
        "--kdf",
        choices=("reference", "stub", "argon2id"),
        default="reference",
    )
    parser.add_argument("--password", default="HillEnigmaSPN2026!")
    parser.add_argument(
        "--salt-hex",
        default="0102030405060708090A0B0C0D0E0F10",
    )

    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--resume", action="store_true")
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    positive_integer_fields = (
        "discovery_keys",
        "discovery_samples",
        "confirmation_keys",
        "confirmation_samples",
        "confirm_top_k",
        "calibration_keys",
        "calibration_samples",
        "calibration_jobs",
        "feistel_rounds",
        "bootstrap_replicates",
        "checkpoint_every",
    )
    for field_name in positive_integer_fields:
        if int(getattr(args, field_name)) <= 0:
            raise ValueError(f"--{field_name.replace('_', '-')} must be positive")
    if args.top_bct_pairs < 0:
        raise ValueError("--top-bct-pairs cannot be negative")
    if args.save_quartets_per_job < 0:
        raise ValueError("--save-quartets-per-job cannot be negative")
    if args.counter_limit is not None and args.counter_limit <= 0:
        raise ValueError("--counter-limit must be positive")
    if not 0 < args.confidence_level < 1:
        raise ValueError("--confidence-level must be between zero and one")
    if not 0 < args.alpha_family < 1:
        raise ValueError("--alpha-family must be between zero and one")
    if not 0 < args.target_power < 1:
        raise ValueError("--target-power must be between zero and one")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.panel is None:
        args.panel = ["all"]
    apply_profile_defaults(args)
    validate_arguments(args)

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    engine_path = find_engine_path(args.engine)
    print(f"Loading HESPN engine: {engine_path}")
    engine = load_engine(engine_path)
    print("Running engine self-test...")
    engine.run_selftest(verbose=False)
    print("Engine self-test PASS")

    engine_criteria = engine.parse_criteria(args.criteria)
    standard_criteria = parse_standard_criteria(args.criteria)
    jobs = build_jobs(engine, args)
    calibration_rounds = parse_int_list(
        args.calibration_rounds,
        minimum=1,
        maximum=16,
    )

    base_key = engine.key_from_args(key_namespace(args))
    configuration = immutable_configuration(
        args=args,
        engine_path=engine_path,
        jobs=jobs,
        base_key=base_key,
    )
    fingerprint = prepare_manifest(
        out_dir=out_dir,
        configuration=configuration,
        resume=args.resume or args.phase == "analyze",
    )

    write_rows_csv(out_dir / "panel_plan.csv", [job.metadata() for job in jobs])
    write_json(out_dir / "panel_plan.json", {
        "created_utc": utc_now_iso(),
        "configuration_fingerprint": fingerprint,
        "job_count": len(jobs),
        "jobs": [job.metadata() for job in jobs],
    })
    write_rows_csv(
        out_dir / "power_plan.csv",
        create_power_plan(
            jobs,
            alpha_family=args.alpha_family,
            comparison_count=max(len(jobs) * len(BROAD_METRICS), 1),
            power=args.target_power,
        ),
    )
    if args.spn_null_control:
        structure_oracle = RandomizedSPNOracle(
            bytes(len(base_key)),
            rounds=16,
            structure_seed=args.spn_structure_seed,
            sbox_mode=args.spn_sbox,
            aes_sbox=getattr(engine, "AES_SBOX", None),
        )
        write_json(
            out_dir / "spn_control_structure.json",
            structure_oracle.export_structure(),
        )

    print(f"Panel jobs: {len(jobs):,}")
    print(f"Profile:    {args.profile}")
    print(f"Output:     {out_dir}")
    print(f"Fingerprint:{fingerprint[:16]}...")

    if args.phase == "plan":
        print("Plan written; no experiments were run.")
        return 0

    if args.phase == "analyze":
        aggregate = rebuild_outputs(
            out_dir=out_dir,
            jobs=jobs,
            args=args,
            provisional=False,
        )
        print(f"Rebuilt analysis for {len(aggregate):,} aggregate groups.")
        return 0

    per_key_path = out_dir / "per_key_results.csv"
    completed = completed_run_ids(per_key_path, fingerprint)

    phases_to_run: list[str]
    if args.phase == "full":
        phases_to_run = ["calibration", "discovery", "confirmation"]
    else:
        phases_to_run = [args.phase]

    for phase in phases_to_run:
        print()
        print("=" * 88)
        print(f"PHASE: {phase.upper()}")
        print("=" * 88)

        if phase == "calibration":
            calibration_jobs = select_evenly_spaced(jobs, args.calibration_jobs)
            specs = make_phase_specs(
                phase="calibration",
                control="hespn",
                rounds=calibration_rounds,
                jobs=calibration_jobs,
                keys=args.calibration_keys,
                samples=args.calibration_samples,
            )
            if args.control_scope in ("calibration", "both"):
                if args.null_control:
                    specs.extend(make_phase_specs(
                        phase="calibration",
                        control="feistel_null",
                        rounds=[args.rounds],
                        jobs=calibration_jobs,
                        keys=args.calibration_keys,
                        samples=args.calibration_samples,
                    ))
                if args.spn_null_control:
                    specs.extend(make_phase_specs(
                        phase="calibration",
                        control="spn_null",
                        rounds=calibration_rounds,
                        jobs=calibration_jobs,
                        keys=args.calibration_keys,
                        samples=args.calibration_samples,
                    ))

        elif phase == "discovery":
            specs = make_phase_specs(
                phase="discovery",
                control="hespn",
                rounds=[args.rounds],
                jobs=jobs,
                keys=args.discovery_keys,
                samples=args.discovery_samples,
            )
            if args.control_scope in ("discovery", "both"):
                if args.null_control:
                    specs.extend(make_phase_specs(
                        phase="discovery",
                        control="feistel_null",
                        rounds=[args.rounds],
                        jobs=jobs,
                        keys=args.discovery_keys,
                        samples=args.discovery_samples,
                    ))
                if args.spn_null_control:
                    specs.extend(make_phase_specs(
                        phase="discovery",
                        control="spn_null",
                        rounds=[args.rounds],
                        jobs=jobs,
                        keys=args.discovery_keys,
                        samples=args.discovery_samples,
                    ))

        elif phase == "confirmation":
            current_aggregate = rebuild_outputs(
                out_dir=out_dir,
                jobs=jobs,
                args=args,
                provisional=False,
            )
            confirmation_jobs = select_confirmation_jobs(
                jobs=jobs,
                aggregate_rows=current_aggregate,
                args=args,
                out_dir=out_dir,
            )
            specs = make_phase_specs(
                phase="confirmation",
                control="hespn",
                rounds=[args.rounds],
                jobs=confirmation_jobs,
                keys=args.confirmation_keys,
                samples=args.confirmation_samples,
            )
        else:
            raise ValueError(f"unexpected phase: {phase}")

        phase_plan_path = out_dir / f"{phase}_run_plan.csv"
        write_rows_csv(phase_plan_path, [{
            "run_id": spec.run_id,
            "phase": spec.phase,
            "control": spec.control,
            "rounds": spec.rounds,
            "key_index": spec.key_index,
            "samples": spec.samples,
            **spec.job.metadata(),
        } for spec in specs])

        print(f"Phase key/job/round runs: {len(specs):,}")
        print(f"Phase quartets: {sum(spec.samples for spec in specs):,}")
        execute_specs(
            engine=engine,
            engine_criteria=engine_criteria,
            standard_criteria=standard_criteria,
            base_key=base_key,
            specs=specs,
            args=args,
            out_dir=out_dir,
            fingerprint=fingerprint,
            completed=completed,
        )

    aggregate = rebuild_outputs(
        out_dir=out_dir,
        jobs=jobs,
        args=args,
        provisional=False,
    )
    write_json(out_dir / "run_metadata.json", {
        "program": Path(__file__).name,
        "program_version": PROGRAM_VERSION,
        "completed_utc": utc_now_iso(),
        "configuration_fingerprint": fingerprint,
        "aggregate_groups": len(aggregate),
        "arguments": vars(args),
    })

    print()
    print("=" * 88)
    print("STUDY PHASES COMPLETE")
    print("=" * 88)
    print(f"Per-key output:       {out_dir / 'per_key_results.csv'}")
    print(f"Aggregate output:     {out_dir / 'aggregate_results.csv'}")
    print(f"Per-bit output:       {out_dir / 'per_bit_results.csv'}")
    print(f"Byte-activity output: {out_dir / 'per_byte_activity_results.csv'}")
    print(
        f"Byte-value output:    "
        f"{out_dir / 'per_byte_value_distribution_results.csv'}"
    )
    print(f"Control comparison:  {out_dir / 'control_comparison.csv'}")
    if args.spn_null_control:
        print(f"SPN structure:        {out_dir / 'spn_control_structure.json'}")
    print(f"Power plan:           {out_dir / 'power_plan.csv'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Re-run with the same arguments, --out-dir, and --resume.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except (
        AssertionError,
        FileNotFoundError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
