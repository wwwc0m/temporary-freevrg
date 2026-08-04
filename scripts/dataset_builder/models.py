from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


BASE_FIELDS = (
    "sa_id",
    "year",
    "announced",
    "topic",
    "category",
    "module",
    "scope_tier",
    "is_priority",
    "cve",
    "cwe",
    "affects",
    "git_hashes",
    "svn_revisions",
    "github_commit_urls",
    "advisory_raw_url",
    "diff_available",
    "data_quality",
)


@dataclass(slots=True)
class DatasetRecord:
    sa_id: str
    year: int
    announced: str
    topic: str
    category: str
    module: str
    scope_tier: str
    is_priority: bool
    cve: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    affects: str = ""
    git_hashes: list[str] = field(default_factory=list)
    svn_revisions: list[str] = field(default_factory=list)
    github_commit_urls: list[str] = field(default_factory=list)
    advisory_raw_url: str = ""
    diff_available: bool = False
    data_quality: int = 1
    commit_grade: str = ""
    source: str | None = None
    upstream_path: str | None = None
    note: str | None = None
    changed_paths: list[str] = field(default_factory=list, repr=False)
    upstream_message: str = field(default="", repr=False)

    def recompute(self) -> None:
        self.is_priority = self.scope_tier in {"lib", "tool"}
        has_cve = bool(self.cve)
        has_commit = bool(self.git_hashes)
        if has_cve and has_commit:
            self.data_quality = 3
        elif has_cve or has_commit:
            self.data_quality = 2
        else:
            self.data_quality = 1

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {name: getattr(self, name) for name in BASE_FIELDS}
        if self.source:
            result["source"] = self.source
        if self.upstream_path:
            result["upstream_path"] = self.upstream_path
        if self.note:
            result["note"] = self.note
        result["commit_grade"] = self.commit_grade
        return result
