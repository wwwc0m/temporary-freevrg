from __future__ import annotations

import argparse
from datetime import date
import logging
from pathlib import Path
import sys

from dataset_builder import DatasetBuilder
from dataset_builder.exporters import write_outputs
from dataset_builder.reference import ReferenceMismatch, validate_reference
from dataset_builder.sources import SourceError


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CURATION = SCRIPT_DIR / "dataset_builder" / "curation_v1_4.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the FreeVRG vulnerability index dataset")
    parser.add_argument("--output-dir", type=Path, default=Path("data/dataset"))
    parser.add_argument("--snapshot-date", type=date.fromisoformat, default=date(2026, 6, 21))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/freevrg-dataset"))
    parser.add_argument("--curation-file", type=Path, default=DEFAULT_CURATION)
    parser.add_argument("--refresh", action="store_true", help="refresh cached Git and HTTP data")
    parser.add_argument("--offline", action="store_true", help="use only the local cache")
    parser.add_argument("--reference-zip", type=Path)
    parser.add_argument("--validate-reference", action="store_true")
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    if args.validate_reference and args.reference_zip is None:
        raise SystemExit("--validate-reference requires --reference-zip")

    try:
        records = DatasetBuilder(
            cache_dir=args.cache_dir,
            curation_path=args.curation_file,
            snapshot_date=args.snapshot_date,
            offline=args.offline,
            refresh=args.refresh,
            github_token_env=args.github_token_env,
        ).build()
        outputs = write_outputs(records, args.output_dir)
        for name, path in outputs.items():
            logging.info("wrote %s: %s", name.upper(), path)
        if args.validate_reference:
            validate_reference(args.output_dir, args.reference_zip)
            logging.info("reference validation passed")
        return 0
    except (SourceError, ReferenceMismatch, ValueError) as exc:
        logging.error("dataset build failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
