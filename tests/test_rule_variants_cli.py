from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


def test_generate_rule_variants_cli_writes_rules_and_manifest(tmp_path: Path) -> None:
    pattern_path = tmp_path / "demo-pattern.md"
    pattern_path.write_text(
        "\n".join(
            [
                "# Pattern: demo-pattern",
                "",
                "## Description",
                "Network length reaches a sink without a guard.",
                "",
                "## Structured Fields",
                "source:",
                "  - packet length",
                "",
                "sink:",
                "  - memcpy",
                "",
                "sanitizer:",
                "  - length guard",
                "",
                "## Historical Instances",
                "- files_changed: sys/net/a.c",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "rules"
    env = {
        **os.environ,
        "LLM_BACKEND": "mock",
        "RULE_LLM_BACKEND": "mock",
        "LANGFUSE_ENABLED": "false",
        "RULES_DIR": str(output_dir),
    }

    result = subprocess.run(
        [
            "python",
            "scripts/generate_rule_variants.py",
            str(pattern_path),
            "--variant",
            "exact:syntactic",
            "--variant",
            "component:dataflow",
            "--overwrite",
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    exact_rule = output_dir / "demo-pattern.exact-syntactic.ql"
    component_rule = output_dir / "demo-pattern.component-dataflow.ql"
    manifest_path = output_dir / "demo-pattern.rule-variants.json"
    assert exact_rule.exists()
    assert component_rule.exists()
    assert manifest_path.exists()
    assert "@id freevrg/demo-pattern-exact-syntactic" in exact_rule.read_text(encoding="utf-8")
    assert 'target.getName() = "memcpy"' in exact_rule.read_text(encoding="utf-8")
    assert "sys/net/a.c" in exact_rule.read_text(encoding="utf-8")
    assert "sys/net/" in component_rule.read_text(encoding="utf-8")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [item["variant"]["scope_level"] for item in manifest] == ["exact", "component"]
