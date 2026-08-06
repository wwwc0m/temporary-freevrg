from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.rule_agent import RuleAgent  # noqa: E402
from core.config import ensure_directories, load_config  # noqa: E402
from core.models import slugify  # noqa: E402
from core.rule_variant import DEFAULT_RULE_VARIANTS, RuleVariant, parse_rule_variant  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate multiple CodeQL rule variants from one pattern document."
    )
    parser.add_argument("pattern", type=Path, help="Path to a generated pattern markdown file.")
    parser.add_argument("--output-dir", type=Path, help="Override RULES_DIR for generated rules.")
    parser.add_argument(
        "--variant",
        action="append",
        default=[],
        help=(
            "Rule variant as '<scope>:<semantic>', for example "
            "'component:dataflow'. Can be provided multiple times."
        ),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config()
    ensure_directories(config)
    output_dir = args.output_dir or config.rules_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    variants = _variants_from_args(args.variant)
    pattern_text = args.pattern.read_text(encoding="utf-8")
    pattern_stem = slugify(args.pattern.stem)
    agent = RuleAgent(config)

    manifest: list[dict[str, object]] = []
    for variant in variants:
        output_path = output_dir / f"{pattern_stem}.{variant.slug}.ql"
        if output_path.exists() and not args.overwrite:
            manifest.append(
                {
                    "variant": variant.to_dict(),
                    "path": str(output_path),
                    "written": False,
                    "reason": "exists",
                }
            )
            continue
        rule_text = agent.generate_rule(pattern_text, variant=variant)
        output_path.write_text(rule_text, encoding="utf-8")
        manifest.append(
            {
                "variant": variant.to_dict(),
                "path": str(output_path),
                "written": True,
            }
        )
        print(output_path)

    manifest_path = output_dir / f"{pattern_stem}.rule-variants.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"manifest: {manifest_path}")
    return 0


def _variants_from_args(raw_values: list[str]) -> list[RuleVariant]:
    if not raw_values:
        return list(DEFAULT_RULE_VARIANTS)
    return [parse_rule_variant(value) for value in raw_values]


if __name__ == "__main__":
    sys.exit(main())
