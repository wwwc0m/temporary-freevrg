from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys

from sample_builder.builder import DatasetSampleBuilder, SampleBuildError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Agent-ready sample JSON files from the FreeVRG dataset index."
    )
    parser.add_argument("--dataset", type=Path, default=Path("data/dataset/dataset_index.json"))
    parser.add_argument("--freebsd-src", type=Path, default=Path("vendor/freebsd-src"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/samples"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/freevrg-samples"))
    parser.add_argument("--sa-id", help="Build only one FreeBSD-SA record.")
    parser.add_argument("--limit", type=int, help="Stop after writing this many samples.")
    parser.add_argument("--offline", action="store_true", help="Do not fetch commits or advisory text.")
    parser.add_argument(
        "--fetch-missing",
        action="store_true",
        help="Fetch missing fix commits into --freebsd-src when they are not available locally.",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        stats = DatasetSampleBuilder(
            dataset_path=args.dataset,
            freebsd_src=args.freebsd_src,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            offline=args.offline,
            fetch_missing=args.fetch_missing,
            overwrite=args.overwrite,
            limit=args.limit,
            sa_id=args.sa_id,
        ).build()
    except SampleBuildError as exc:
        logging.error("sample build failed: %s", exc)
        return 1
    logging.info(
        "sample build complete: written=%d skipped=%d failed=%d",
        stats.written,
        stats.skipped,
        stats.failed,
    )
    return 0 if stats.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
