from __future__ import annotations

import csv
from datetime import date
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.dataset_builder.builder import DatasetBuilder
from scripts.dataset_builder.classification import (
    classify_scope,
    grade_commit,
    is_document_only_commit,
)
from scripts.dataset_builder.curation import Curation
from scripts.dataset_builder.exporters import (
    CSV_FIELDS,
    MAIN_HEADERS,
    PRIORITY_HEADERS,
    build_workbook,
    csv_row,
    write_outputs,
)
from scripts.dataset_builder.models import DatasetRecord
from scripts.dataset_builder.sources import (
    UPSTREAM_PROJECTS,
    parse_advisory,
    records_from_upstream_log,
)


ROOT = Path(__file__).resolve().parents[1]
CURATION_PATH = ROOT / "scripts" / "dataset_builder" / "curation_v1_4.json"


def record(
    identifier: str = "FreeBSD-SA-24:01",
    *,
    scope: str = "lib",
    cves: list[str] | None = None,
    hashes: list[str] | None = None,
    source: str | None = None,
) -> DatasetRecord:
    item = DatasetRecord(
        sa_id=identifier,
        year=2024,
        announced="2024-01-01",
        topic="Example vulnerability",
        category="core",
        module="example",
        scope_tier=scope,
        is_priority=False,
        cve=["CVE-2024-1000"] if cves is None else cves,
        cwe=[],
        affects="All supported versions of FreeBSD.",
        git_hashes=["0123456789ab"] if hashes is None else hashes,
        svn_revisions=[],
        github_commit_urls=(
            ["https://github.com/freebsd/freebsd-src/commit/0123456789ab"]
            if hashes is None
            else [f"https://github.com/freebsd/freebsd-src/commit/{value}" for value in hashes]
        ),
        advisory_raw_url="https://example.invalid/advisory.asc",
        source=source,
        upstream_path="lib/example" if source else None,
    )
    item.recompute()
    return item


def test_parse_advisory_header_multiple_cves_hashes_and_svn() -> None:
    text = """-----BEGIN PGP SIGNED MESSAGE-----
Topic:          First header line
                ignored continuation
Category:       core
Module:         misleading-header-module
Announced:      2024-02-03; revised on 2024-02-04
Affects:        First affects line
                ignored continuation
CVE Name:       CVE-2024-1000
Problem: CVE-2024-1001 and CVE-2024-1000.
VI.  Correction details
stable/14/ 0123456789abcdef0123456789abcdef01234567
stable/13/ abcdef012345
releng/13/ r123456
stable/13/ r123456
VII. References
"""
    parsed = parse_advisory("FreeBSD-SA-24:99.real_module.asc", text)
    assert parsed is not None
    assert parsed.sa_id == "FreeBSD-SA-24:99"
    assert parsed.module == "real_module"
    assert parsed.announced == "2024-02-03; revised on 2024-02-04"
    assert parsed.affects == "First affects line"
    assert parsed.cve == ["CVE-2024-1000", "CVE-2024-1001"]
    assert parsed.git_hashes == ["0123456789ab", "abcdef012345"]
    assert parsed.svn_revisions == ["123456"]


@pytest.mark.parametrize(
    ("cves", "hashes", "quality"),
    [
        (["CVE-2024-1"], ["abc"], 3),
        (["CVE-2024-1"], [], 2),
        ([], ["abc"], 2),
        ([], [], 1),
    ],
)
def test_quality_rules(cves: list[str], hashes: list[str], quality: int) -> None:
    item = record(cves=cves, hashes=hashes)
    item.recompute()
    assert item.data_quality == quality


def test_scope_prefers_paths_and_priority_is_exact() -> None:
    assert classify_scope("openssl", ["sys/netinet/tcp_input.c"]) == "kernel"
    assert classify_scope("kernel", ["lib/libc/stdio/wbuf.c"]) == "lib"
    assert classify_scope("kernel", ["usr.sbin/rpcbind/rpcb_svc.c"]) == "tool"
    for scope, expected in (("lib", True), ("tool", True), ("kernel", False), ("other", False)):
        item = record(scope=scope)
        item.recompute()
        assert item.is_priority is expected


def test_document_only_commit_is_rejected() -> None:
    assert is_document_only_commit("Document r285330, OpenSSL update", ["release/doc/en/article.xml"])
    assert is_document_only_commit("Update notes", ["release/doc/en/article.xml", "docs/notes.md"])
    assert not is_document_only_commit(
        "Merge OpenSSL 1.0.1p", ["crypto/openssl/ssl/ssl_lib.c", "UPDATING"]
    )
    assert grade_commit(["release/doc/en/article.xml"]) == "noise_only"


def test_csv_serialization_lists_booleans_and_empty_values() -> None:
    item = record()
    item.cve = ["CVE-1", "CVE-2"]
    item.svn_revisions = ["123", "456"]
    item.diff_available = False
    row = csv_row(item)
    assert tuple(row) == CSV_FIELDS
    assert row["cve"] == "CVE-1; CVE-2"
    assert row["svn_revisions"] == "123; 456"
    assert row["is_priority"] == "Yes"
    assert row["diff_available"] == ""
    assert row["source"] == ""


def test_curation_has_reviewable_reasons_and_expected_audit_counts() -> None:
    curation = Curation(CURATION_PATH)
    assert curation.snapshot_date == date(2026, 6, 21)
    assert curation.audit_summary() == {
        "exclude_freebsd": 34,
        "exclude_upstream": 8,
        "freebsd_commit_audit": 136,
        "upstream_integration_audit": 132,
        "scope_overrides": 4,
        "notes": 4,
        "commit_grade_audit": 177,
    }


def test_curation_applies_field_level_override(tmp_path: Path) -> None:
    payload = {
        "version": "1.4",
        "snapshot_date": "2026-06-21",
        "freebsd_commit_audit": {
            "FreeBSD-SA-24:01": {
                "git_hashes": [],
                "github_commit_urls": [],
                "reason": "Audited mismatch.",
            }
        },
        "scope_overrides": {
            "FreeBSD-SA-24:01": {"value": "kernel", "reason": "Path audit."}
        },
        "notes": {"FreeBSD-SA-24:01": {"value": "reviewed", "reason": "Keep note."}},
    }
    path = tmp_path / "curation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    item = Curation(path).apply_freebsd(record(), matcher=None)
    assert item.git_hashes == []
    assert item.github_commit_urls == []
    assert item.scope_tier == "kernel"
    assert item.is_priority is False
    assert item.data_quality == 2
    assert item.note == "reviewed"


def test_upstream_cve_deduplication_and_covered_filtering() -> None:
    commits = [
        ("a" * 40, "2024-03-01T00:00:00Z", "Fix CVE-2024-1 and CVE-2024-2", ""),
        ("b" * 40, "2024-02-01T00:00:00Z", "Mention CVE-2024-1", "CVE-2024-3"),
    ]
    records = records_from_upstream_log(
        UPSTREAM_PROJECTS[0], commits, {"CVE-2024-2"}, {"CVE-2024-3"}
    )
    assert [item.cve for item in records] == [["CVE-2024-1"]]
    assert records[0].advisory_raw_url.endswith("/aaaaaaaaaaaa")


def test_builder_sort_is_stable_across_runs(tmp_path: Path) -> None:
    curation_path = tmp_path / "curation.json"
    curation_path.write_text(
        json.dumps({"version": "1.4", "snapshot_date": "2020-01-01"}), encoding="utf-8"
    )
    unsorted_records = [record("FreeBSD-SA-19:02"), record("FreeBSD-SA-19:01")]
    builder = DatasetBuilder(
        cache_dir=tmp_path / "cache",
        curation_path=curation_path,
        snapshot_date=date(2020, 1, 1),
        offline=True,
    )
    with (
        patch(
            "scripts.dataset_builder.builder.collect_freebsd_advisories",
            return_value=unsorted_records,
        ),
        patch("scripts.dataset_builder.builder.collect_upstream_records", return_value=[]),
    ):
        first = [item.sa_id for item in builder.build()]
        second = [item.sa_id for item in builder.build()]
    assert first == second == ["FreeBSD-SA-19:01", "FreeBSD-SA-19:02"]


def test_xlsx_sheets_headers_rows_stats_and_hyperlinks() -> None:
    lib = record("FreeBSD-SA-24:01", scope="lib")
    kernel = record("FreeBSD-SA-24:02", scope="kernel")
    upstream = record("UPSTREAM-OPENSSL-CVE-2024-9", scope="lib", source="upstream_commit")
    workbook = build_workbook([lib, kernel, upstream])
    assert workbook.sheetnames == [
        "SA Dataset Index",
        "Priority lib+tool",
        "Kernel Track",
        "Stats & Legend",
    ]
    main = workbook["SA Dataset Index"]
    assert tuple(cell.value for cell in main[1]) == MAIN_HEADERS
    assert (main.max_row, main.max_column) == (4, 17)
    assert main.freeze_panes == "A2"
    assert main.auto_filter.ref == "A1:Q1"
    assert main["M2"].hyperlink.target.endswith("0123456789ab")
    priority = workbook["Priority lib+tool"]
    assert tuple(cell.value for cell in priority[1]) == PRIORITY_HEADERS
    assert (priority.max_row, priority.max_column) == (3, 12)
    assert (workbook["Kernel Track"].max_row, workbook["Kernel Track"].max_column) == (2, 17)
    stats = workbook["Stats & Legend"]
    assert stats["B2"].value == 3
    assert stats["B3"].value == 2
    assert stats["B4"].value == 1


def test_output_files_are_semantically_consistent(tmp_path: Path) -> None:
    paths = write_outputs([record()], tmp_path)
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert payload[0]["is_priority"] is True
    assert "source" not in payload[0]
    with paths["csv"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["is_priority"] == "Yes"
    assert rows[0]["cwe"] == ""
    assert paths["xlsx"].is_file()
