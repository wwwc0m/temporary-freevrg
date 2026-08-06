from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts.sample_builder.builder import DatasetSampleBuilder, extract_c_function


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_extract_c_function_handles_comments_and_nested_blocks() -> None:
    source = """
static int helper(void) { return 0; }

int target(int value)
{
    if (value > 0) {
        return value;
    }
    return helper();
}

int other(void) { return 1; }
"""
    extracted = extract_c_function(source, "target")
    assert extracted is not None
    assert extracted.startswith("int target")
    assert "return helper();" in extracted
    assert "int other" not in extracted


def test_dataset_sample_builder_extracts_before_after_function(tmp_path: Path) -> None:
    repo = tmp_path / "freebsd-src"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "FreeVRG Test")

    source_path = repo / "sbin" / "dhclient" / "options.c"
    write_file(
        source_path,
        """
struct option_data {
    unsigned int len;
    unsigned char *data;
};

int find_search_domain_name_len(struct option_data *option, unsigned int *offset)
{
    int pointed_len;
    pointed_len = find_search_domain_name_len(option, offset);
    return pointed_len + 1;
}
""",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "vulnerable")

    write_file(
        source_path,
        """
struct option_data {
    unsigned int len;
    unsigned char *data;
};

int find_search_domain_name_len(struct option_data *option, unsigned int *offset)
{
    int pointed_len;
    pointed_len = find_search_domain_name_len(option, offset);
    if (pointed_len < 0) {
        return -1;
    }
    return pointed_len + 1;
}
""",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "fix CVE-2020-7461")
    commit = git(repo, "rev-parse", "HEAD").strip()

    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            [
                {
                    "sa_id": "FreeBSD-SA-20:26",
                    "year": 2020,
                    "topic": "dhclient heap overflow",
                    "module": "dhclient",
                    "cve": ["CVE-2020-7461"],
                    "cwe": [],
                    "affects": "All supported versions of FreeBSD.",
                    "git_hashes": [commit[:12]],
                    "github_commit_urls": [
                        f"https://github.com/freebsd/freebsd-src/commit/{commit}"
                    ],
                    "advisory_raw_url": "",
                }
            ]
        ),
        encoding="utf-8",
    )

    stats = DatasetSampleBuilder(
        dataset_path=dataset,
        freebsd_src=repo,
        output_dir=tmp_path / "samples",
        cache_dir=tmp_path / "cache",
        offline=True,
        overwrite=True,
    ).build()

    assert stats.written == 1
    sample_path = tmp_path / "samples" / "freebsd-sa-20-26.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    key = "sbin/dhclient/options.c::find_search_domain_name_len"
    assert sample["id"] == "FreeBSD-SA-20:26"
    assert sample["cve"] == ["CVE-2020-7461"]
    assert sample["files_changed"] == ["sbin/dhclient/options.c"]
    assert key in sample["before_code"]
    assert key in sample["after_code"]
    assert "pointed_len + 1" in sample["before_code"][key]
    assert "if (pointed_len < 0)" in sample["after_code"][key]
    assert "+    if (pointed_len < 0)" in sample["diff"]
