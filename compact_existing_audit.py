#!/usr/bin/env python3
r"""Convert an existing verbose slide/reflection audit into compact outputs.

Usage from the project folder:
    py .\compact_existing_audit.py .\standard_results_local

The script preserves the original detailed JSON as
``slide_and_reflection_audit_full.json`` and replaces the default audit JSON
with a compact summary. It also writes a CSV and a short Markdown report.
No cryptanalytic search is rerun.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import Any

from slide_reflection_audit import compact_audit, compact_markdown, compact_rows


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_directory", nargs="?", default="standard_results_local")
    parser.add_argument("--examples", type=int, default=8,
                        help="Maximum examples retained from each long pair list")
    args = parser.parse_args()

    results = Path(args.results_directory).resolve()
    default_path = results / "slide_and_reflection_audit.json"
    full_path = results / "slide_and_reflection_audit_full.json"

    source = full_path if full_path.exists() else default_path
    if not source.exists():
        raise SystemExit(f"Audit file not found in: {results}")

    data = json.loads(source.read_text(encoding="utf-8"))
    if data.get("format_version") == 2 and "variants" in data:
        compact = data
        print("Audit is already compact; refreshing CSV and Markdown outputs.")
    else:
        if source == default_path and not full_path.exists():
            shutil.copy2(default_path, full_path)
            print(f"Preserved detailed audit: {full_path.name}")
        compact = compact_audit(data, example_limit=max(0, args.examples))
        write_json(default_path, compact)
        print(f"Wrote compact audit: {default_path.name}")

    write_json(results / "slide_and_reflection_summary.json", compact)
    write_csv(results / "slide_and_reflection_summary.csv", compact_rows(compact))
    (results / "SLIDE_REFLECTION_SUMMARY.md").write_text(
        compact_markdown(compact), encoding="utf-8"
    )

    print("Wrote slide_and_reflection_summary.json")
    print("Wrote slide_and_reflection_summary.csv")
    print("Wrote SLIDE_REFLECTION_SUMMARY.md")
    print("No experiment or optimizer was rerun.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
