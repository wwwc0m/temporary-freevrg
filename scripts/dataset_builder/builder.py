from __future__ import annotations

from collections import Counter
from datetime import date
import logging
import os
from pathlib import Path

from .curation import Curation
from .models import DatasetRecord
from .sources import (
    FreeBSDCommitMatcher,
    GitHubClient,
    GitRepository,
    SourceError,
    UPSTREAM_PROJECTS,
    collect_freebsd_advisories,
    collect_upstream_records,
)


LOGGER = logging.getLogger(__name__)
EXTERNAL_MODULES = {"bind", "ntp", "heimdal", "hostapd", "sqlite", "sqlite3", "unbound"}
CPU_MITIGATION_MODULES = {"speculative_execution", "lazyfpu", "l1tf", "mds", "mcepsc", "mcu"}


class DatasetBuilder:
    def __init__(
        self,
        *,
        cache_dir: Path,
        curation_path: Path,
        snapshot_date: date,
        offline: bool = False,
        refresh: bool = False,
        github_token_env: str = "GITHUB_TOKEN",
    ) -> None:
        self.cache_dir = cache_dir
        self.curation = Curation(curation_path)
        self.snapshot_date = snapshot_date
        self.offline = offline
        self.refresh = refresh
        token = os.environ.get(github_token_env)
        self.github = GitHubClient(
            cache_dir / "http",
            token=token,
            offline=offline,
            refresh=refresh,
        )
        self.matcher = FreeBSDCommitMatcher(self.github)

    def build(self) -> list[DatasetRecord]:
        freebsd_repository = GitRepository(
            self.cache_dir / "git" / "freebsd__freebsd-doc",
            "https://github.com/freebsd/freebsd-doc.git",
            "main",
            offline=self.offline,
            refresh=self.refresh,
        )
        advisories = collect_freebsd_advisories(freebsd_repository, self.snapshot_date)
        freebsd_records: list[DatasetRecord] = []
        for record in advisories:
            if self._exclude_freebsd(record):
                continue
            freebsd_records.append(self.curation.apply_freebsd(record, self.matcher))
        freebsd_records.sort(key=lambda item: item.sa_id)

        covered_cves = {cve for record in freebsd_records for cve in record.cve}
        upstream_records = collect_upstream_records(
            self.cache_dir,
            self.snapshot_date,
            covered_cves,
            self.curation.excluded_upstream_cves,
            offline=self.offline,
            refresh=self.refresh,
        )
        projects = {project.module: project for project in UPSTREAM_PROJECTS}
        upstream_records = [
            self.curation.apply_upstream(record, projects[record.module], self.matcher)
            for record in upstream_records
        ]

        records = [*freebsd_records, *upstream_records]
        self._validate(records)
        self.curation.assert_complete_for_snapshot(records, self.snapshot_date)
        self._log_stats(records)
        return records

    def _exclude_freebsd(self, record: DatasetRecord) -> bool:
        if record.sa_id in self.curation.excluded_freebsd_ids:
            return True
        if record.category.strip().lower() in {"ports", "3rd party"}:
            return True
        if record.module.lower() in EXTERNAL_MODULES:
            return True
        return record.module.lower() in CPU_MITIGATION_MODULES

    def _validate(self, records: list[DatasetRecord]) -> None:
        identifiers = [record.sa_id for record in records]
        duplicates = [item for item, count in Counter(identifiers).items() if count > 1]
        if duplicates:
            raise SourceError(f"duplicate dataset identifiers: {duplicates}")
        for record in records:
            if record.scope_tier not in {"lib", "tool", "kernel", "other"}:
                raise SourceError(f"invalid scope for {record.sa_id}: {record.scope_tier}")
            if record.commit_grade not in {
                "",
                "focused",
                "medium",
                "large_concentrated",
                "bundled_multi_module",
                "noise_only",
            }:
                raise SourceError(f"invalid commit grade for {record.sa_id}: {record.commit_grade}")
            if record.is_priority != (record.scope_tier in {"lib", "tool"}):
                raise SourceError(f"priority invariant failed for {record.sa_id}")
        if self.snapshot_date == self.curation.snapshot_date and self.curation.expected_stats:
            actual = {
                "total": len(records),
                "freebsd_sa": sum(record.source is None for record in records),
                "upstream_commit": sum(record.source == "upstream_commit" for record in records),
                "priority": sum(record.is_priority for record in records),
                "kernel": sum(record.scope_tier == "kernel" for record in records),
                "quality_3": sum(record.data_quality == 3 for record in records),
                "quality_2": sum(record.data_quality == 2 for record in records),
                "quality_1": sum(record.data_quality == 1 for record in records),
                "quality_3_priority": sum(
                    record.is_priority and record.data_quality == 3 for record in records
                ),
            }
            if actual != self.curation.expected_stats:
                raise SourceError(
                    f"v1.4 snapshot statistics differ: actual={actual} "
                    f"expected={self.curation.expected_stats}"
                )

    def _log_stats(self, records: list[DatasetRecord]) -> None:
        LOGGER.info(
            "built %d records: freebsd=%d upstream=%d priority=%d kernel=%d Q3=%d Q2=%d Q1=%d",
            len(records),
            sum(record.source is None for record in records),
            sum(record.source == "upstream_commit" for record in records),
            sum(record.is_priority for record in records),
            sum(record.scope_tier == "kernel" for record in records),
            sum(record.data_quality == 3 for record in records),
            sum(record.data_quality == 2 for record in records),
            sum(record.data_quality == 1 for record in records),
        )
