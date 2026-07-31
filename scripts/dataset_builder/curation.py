from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any

from .models import DatasetRecord
from .sources import FREEBSD_COMMIT, FreeBSDCommitMatcher, UpstreamProject


class CurationError(ValueError):
    pass


class Curation:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.payload = json.loads(path.read_text(encoding="utf-8"))
        if self.payload.get("version") != "1.4":
            raise CurationError(f"unsupported curation version in {path}")
        requirements = {
            "exclude_freebsd": (),
            "exclude_upstream": (),
            "freebsd_commit_audit": ("git_hashes", "github_commit_urls"),
            "svn_revision_overrides": ("value",),
            "upstream_source_overrides": ("fields",),
            "upstream_integration_audit": ("git_hashes",),
            "scope_overrides": ("value",),
            "notes": ("value",),
            "commit_grade_audit": ("value",),
        }
        for section, fields in requirements.items():
            for item in self.payload.get(section, {}).values():
                validate_audit_item(item, fields)

    @property
    def snapshot_date(self) -> date:
        return date.fromisoformat(self.payload["snapshot_date"])

    @property
    def excluded_freebsd_ids(self) -> set[str]:
        return set(self.payload.get("exclude_freebsd", {}))

    @property
    def excluded_upstream_cves(self) -> set[str]:
        return set(self.payload.get("exclude_upstream", {}))

    @property
    def expected_stats(self) -> dict[str, int]:
        return dict(self.payload.get("expected_stats", {}))

    def apply_freebsd(
        self, record: DatasetRecord, matcher: FreeBSDCommitMatcher | None
    ) -> DatasetRecord:
        audit = self.payload.get("freebsd_commit_audit", {}).get(record.sa_id)
        if audit is not None:
            record.git_hashes = list(audit["git_hashes"])
            record.github_commit_urls = list(audit["github_commit_urls"])
        elif not record.git_hashes and record.svn_revisions and matcher is not None:
            record.git_hashes, record.github_commit_urls = matcher.match_svn(record)

        revision_override = self.payload.get("svn_revision_overrides", {}).get(record.sa_id)
        if revision_override is not None:
            record.svn_revisions = list(revision_override["value"])
        self._apply_common(record)
        return record

    def apply_upstream(
        self,
        record: DatasetRecord,
        project: UpstreamProject,
        matcher: FreeBSDCommitMatcher | None,
    ) -> DatasetRecord:
        source_override = self.payload.get("upstream_source_overrides", {}).get(record.sa_id)
        if source_override:
            for name, value in source_override["fields"].items():
                setattr(record, name, value)

        audit = self.payload.get("upstream_integration_audit", {}).get(record.sa_id)
        if audit is not None:
            record.git_hashes = list(audit["git_hashes"])
            record.github_commit_urls = [f"{FREEBSD_COMMIT}/{item}" for item in record.git_hashes]
        elif matcher is not None:
            record.git_hashes, record.github_commit_urls = matcher.match_upstream(record, project)
        self._apply_common(record)
        return record

    def _apply_common(self, record: DatasetRecord) -> None:
        scope = self.payload.get("scope_overrides", {}).get(record.sa_id)
        if scope:
            record.scope_tier = scope["value"]
        note = self.payload.get("notes", {}).get(record.sa_id)
        if note:
            record.note = note["value"]
        grade = self.payload.get("commit_grade_audit", {}).get(record.sa_id)
        if grade:
            record.commit_grade = grade["value"]
        record.recompute()

    def assert_complete_for_snapshot(self, records: list[DatasetRecord], snapshot: date) -> None:
        if snapshot != self.snapshot_date:
            return
        known = {record.sa_id for record in records}
        for section in (
            "freebsd_commit_audit",
            "upstream_integration_audit",
            "scope_overrides",
            "notes",
            "commit_grade_audit",
        ):
            missing = set(self.payload.get(section, {})) - known
            if missing:
                raise CurationError(f"{section} contains records absent from the snapshot: {sorted(missing)}")

    def audit_summary(self) -> dict[str, int]:
        return {
            name: len(self.payload.get(name, {}))
            for name in (
                "exclude_freebsd",
                "exclude_upstream",
                "freebsd_commit_audit",
                "upstream_integration_audit",
                "scope_overrides",
                "notes",
                "commit_grade_audit",
            )
        }


def validate_audit_item(item: dict[str, Any], required_fields: tuple[str, ...]) -> None:
    for field in required_fields:
        if field not in item:
            raise CurationError(f"curation item is missing {field}: {item}")
    if not str(item.get("reason", "")).strip():
        raise CurationError(f"curation item has no reason: {item}")
