from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.multi_cve_agent import MultiCveAgent  # noqa: E402
from core.config import load_config  # noqa: E402
from core.models import SampleRecord  # noqa: E402
from scripts.sample_builder.multi_cve import child_sample_filename, materialize_child_sample  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Split one multi-CVE sample JSON into CVE-specific child samples."
    )
    parser.add_argument("sample", type=Path, help="Path to a multi-CVE sample JSON.")
    parser.add_argument("--output-dir", type=Path, default=Path("data/samples"))
    parser.add_argument(
        "--target-cve",
        action="append",
        default=[],
        help="Only write this CVE. Can be provided multiple times.",
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sample = SampleRecord.from_path(args.sample)
    cves = sample.list_field("cve")
    if len(cves) <= 1:
        print(f"sample is not multi-CVE: {args.sample}", file=sys.stderr)
        return 1

    requested = {item.strip().upper() for item in args.target_cve if item.strip()}
    config = load_config()
    agent = MultiCveAgent(config)
    children = agent.split_sample(sample)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    written = skipped = 0
    for child in children:
        cve = str(child.get("cve") or "").upper()
        if requested and cve not in requested:
            skipped += 1
            continue
        child_sample = materialize_child_sample(sample.payload, child)
        output_path = args.output_dir / child_sample_filename(child_sample)
        if output_path.exists() and not args.overwrite:
            skipped += 1
            continue
        output_path.write_text(
            json.dumps(child_sample, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(output_path)
        written += 1

    print(f"multi-cve split complete: written={written} skipped={skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
