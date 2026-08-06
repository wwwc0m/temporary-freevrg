from __future__ import annotations

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

from agents.multi_cve_agent import MultiCveAgent
from core.models import SampleRecord
from scripts.sample_builder.multi_cve import child_sample_filename, materialize_child_sample
from tests.test_pipeline import _make_config


def _write_multi_cve_sample(tmp_path: Path) -> Path:
    sample_path = tmp_path / "multi.json"
    sample_path.write_text(
        json.dumps(
            {
                "id": "FreeBSD-SA-99:99",
                "cve": ["CVE-2099-0001", "CVE-2099-0002"],
                "subsystem": "net",
                "files_changed": ["sys/net/a.c", "sys/net/b.c"],
                "diff": (
                    "diff --git a/sys/net/a.c b/sys/net/a.c\n"
                    "+++ b/sys/net/a.c\n"
                    "+ if (len < 4) return;\n"
                    "diff --git a/sys/net/b.c b/sys/net/b.c\n"
                    "+++ b/sys/net/b.c\n"
                    "+ if (idx >= count) return;\n"
                ),
                "before_code": {
                    "sys/net/a.c::handle_request": "void handle_request(int len) { use(len); }",
                    "sys/net/b.c::parse_index": "void parse_index(int idx) { use(idx); }",
                },
                "after_code": {
                    "sys/net/a.c::handle_request": (
                        "void handle_request(int len) { if (len < 4) return; use(len); }"
                    ),
                    "sys/net/b.c::parse_index": (
                        "void parse_index(int idx) { if (idx >= count) return; use(idx); }"
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    return sample_path


def test_multi_cve_agent_fallback_creates_reviewable_child_per_cve(tmp_path: Path) -> None:
    sample = SampleRecord.from_path(_write_multi_cve_sample(tmp_path))
    agent = MultiCveAgent(_make_config(tmp_path))

    children = agent.split_sample(sample)

    assert [child["cve"] for child in children] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert all(child["evidence_mode"] == "cve_guided_composite" for child in children)
    assert all(child["confidence"] == "low" for child in children)
    assert all(
        child["target_functions"] == ["handle_request", "parse_index"] for child in children
    )


def test_multi_cve_agent_parses_fenced_model_json_and_materializes_child(tmp_path: Path) -> None:
    sample = SampleRecord.from_path(_write_multi_cve_sample(tmp_path))
    agent = MultiCveAgent(_make_config(tmp_path, pattern_llm_backend="openai-compatible"))
    model_json = """```json
{
  "children": [
    {
      "cve": "CVE-2099-0001",
      "target_functions": ["handle_request"],
      "files_changed": ["sys/net/a.c"],
      "evidence_mode": "exact_patch",
      "confidence": "high",
      "rationale": "length guard is in a.c",
      "diff_keywords": ["len < 4"]
    },
    {
      "cve": "CVE-2099-0002",
      "target_functions": ["parse_index"],
      "files_changed": ["sys/net/b.c"],
      "evidence_mode": "cve_guided_composite",
      "confidence": "medium",
      "rationale": "index guard is in b.c",
      "diff_keywords": ["idx >= count"]
    }
  ]
}
```"""

    with patch.object(agent, "invoke_model", return_value=model_json):
        children = agent.split_sample(sample)

    first = materialize_child_sample(sample.payload, children[0])
    second = materialize_child_sample(sample.payload, children[1])

    assert first["id"] == "CVE-2099-0001"
    assert first["source_sa"] == "FreeBSD-SA-99:99"
    assert first["cve"] == ["CVE-2099-0001"]
    assert list(first["before_code"]) == ["sys/net/a.c::handle_request"]
    assert first["context"]["requires_human_review"] is False
    assert child_sample_filename(first) == "freebsd-sa-99-99-cve-2099-0001.json"

    assert list(second["before_code"]) == ["sys/net/b.c::parse_index"]
    assert second["context"]["requires_human_review"] is True
    assert "sys/net/a.c" not in second["diff"]


def test_split_multi_cve_cli_runs_from_script_path(tmp_path: Path) -> None:
    sample_path = _write_multi_cve_sample(tmp_path)
    output_dir = tmp_path / "children"

    result = subprocess.run(
        [
            "python",
            "scripts/split_multi_cve_sample.py",
            str(sample_path),
            "--output-dir",
            str(output_dir),
            "--overwrite",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "freebsd-sa-99-99-cve-2099-0001.json").exists()
    assert (output_dir / "freebsd-sa-99-99-cve-2099-0002.json").exists()
