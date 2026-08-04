from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from agents.harness_agent import HarnessAgent
from core.config import load_config
from core.models import SampleRecord
from core.observability import Observability


def _write_harnesses(
    output_root: Path,
    cve: str,
    harnesses: dict[str, str],
) -> dict[str, Path]:
    vulnerable_dir = output_root / "source" / f"{cve}-vulnerable"
    fixed_dir = output_root / "source" / f"{cve}-fixed"
    vulnerable_dir.mkdir(parents=True, exist_ok=True)
    fixed_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "vulnerable": vulnerable_dir / "harness.c",
        "fixed": fixed_dir / "harness.c",
    }
    paths["vulnerable"].write_text(harnesses["vulnerable_harness"], encoding="utf-8")
    paths["fixed"].write_text(harnesses["fixed_harness"], encoding="utf-8")
    return paths


def _clang_check(paths: dict[str, Path], *, cc: str) -> None:
    object_root = paths["vulnerable"].parents[2] / "objects"
    object_root.mkdir(parents=True, exist_ok=True)
    for variant, path in paths.items():
        object_path = object_root / f"{path.parent.name}.o"
        command = [cc, "-std=c11", "-c", str(path), "-o", str(object_path)]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            message = "\n".join(
                item
                for item in (completed.stdout.strip(), completed.stderr.strip())
                if item
            )
            raise SystemExit(f"{variant} harness failed clang check:\n{message}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate vulnerable/fixed minimal C harnesses from a FreeVRG sample."
    )
    parser.add_argument("sample", type=Path, help="Path to a structured sample JSON file.")
    parser.add_argument(
        "--target",
        help="Target function name or before_code key. Defaults to the only before_code entry.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("data/harnesses"),
        help="Root containing source/<CVE>-vulnerable|fixed/harness.c.",
    )
    parser.add_argument(
        "--clang-check",
        action="store_true",
        help="Compile each generated harness with clang after writing it.",
    )
    parser.add_argument("--cc", default="clang", help="C compiler used by --clang-check.")
    args = parser.parse_args()

    config = load_config()
    sample = SampleRecord.from_path(args.sample)
    cve_values = sample.list_field("cve")
    if len(cve_values) != 1:
        raise SystemExit(
            f"Harness generation currently requires exactly one CVE, got {len(cve_values)}."
        )

    observability = Observability(config)
    try:
        harnesses = HarnessAgent(config, observability).generate_harness_pair(
            sample,
            target_symbol=args.target,
        )
        paths = _write_harnesses(args.output_root, cve_values[0], harnesses)
        if args.clang_check:
            _clang_check(paths, cc=args.cc)
    finally:
        observability.flush()

    for variant, path in paths.items():
        print(f"{variant}: {path}")


if __name__ == "__main__":
    main()
