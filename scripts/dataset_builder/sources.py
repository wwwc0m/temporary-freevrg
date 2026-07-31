from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time as time_module
from typing import Any, Iterable, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .classification import classify_scope, is_document_only_commit
from .models import DatasetRecord


LOGGER = logging.getLogger(__name__)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
HASH_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{12,40}(?![0-9a-f])", re.IGNORECASE)
REVISION_RE = re.compile(r"\br(\d{5,7})\b")
ADVISORY_RE = re.compile(r"^FreeBSD-SA-(\d{2}:\d{2})\.(.+)\.asc$")
FREEBSD_ADVISORY_DIR = "website/static/security/advisories"
FREEBSD_DOC_RAW = "https://raw.githubusercontent.com/freebsd/freebsd-doc/main"
FREEBSD_COMMIT = "https://github.com/freebsd/freebsd-src/commit"


@dataclass(frozen=True, slots=True)
class UpstreamProject:
    key: str
    owner: str
    repository: str
    branch: str
    module: str
    id_prefix: str
    freebsd_path: str
    scope: str

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repository}.git"

    @property
    def commit_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repository}/commit"


UPSTREAM_PROJECTS = (
    UpstreamProject(
        "openssl", "openssl", "openssl", "master", "openssl", "OPENSSL", "crypto/openssl", "lib"
    ),
    UpstreamProject(
        "libarchive",
        "libarchive",
        "libarchive",
        "master",
        "libarchive",
        "LIBARCHIVE",
        "lib/libarchive",
        "lib",
    ),
    UpstreamProject(
        "libexpat",
        "libexpat",
        "libexpat",
        "master",
        "expat",
        "LIBEXPAT",
        "lib/libexpat",
        "lib",
    ),
    UpstreamProject(
        "openssh",
        "openssh",
        "openssh-portable",
        "master",
        "openssh",
        "OPENSSH",
        "crypto/openssh",
        "tool",
    ),
)


class SourceError(RuntimeError):
    pass


class GitRepository:
    """A retrying, cached Git transport used as the raw-source cache."""

    def __init__(
        self,
        path: Path,
        url: str,
        branch: str,
        *,
        offline: bool,
        refresh: bool,
        timeout: int = 300,
    ) -> None:
        self.path = path
        self.url = url
        self.branch = branch
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout

    def ensure(self, shallow_since: date) -> None:
        if not (self.path / ".git").exists():
            if self.offline:
                raise SourceError(f"offline cache is missing Git repository: {self.path}")
            self.path.mkdir(parents=True, exist_ok=True)
            self._run("init", "-q")
            self._run("remote", "add", "origin", self.url)

        remote_ref = f"refs/remotes/origin/{self.branch}"
        has_ref = self._has_revision(remote_ref) or self._has_revision("FETCH_HEAD")
        if self.offline:
            if not has_ref:
                raise SourceError(f"offline Git cache has no usable ref: {self.path}")
            return
        if has_ref and not self.refresh:
            return

        refspec = f"+refs/heads/{self.branch}:{remote_ref}"
        command = (
            "fetch",
            "--force",
            "--prune",
            "--filter=blob:none",
            f"--shallow-since={shallow_since.isoformat()}",
            "origin",
            refspec,
        )
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                LOGGER.info("fetching %s (attempt %d/3)", self.url, attempt)
                self._run(*command, timeout=self.timeout)
                return
            except SourceError as exc:
                last_error = exc
                LOGGER.warning("Git fetch failed for %s: %s", self.url, exc)
                if attempt < 3:
                    time_module.sleep(2 ** (attempt - 1))
        raise SourceError(f"failed to fetch {self.url} after 3 attempts: {last_error}")

    def revision_at(self, snapshot_date: date) -> str:
        base_ref = f"refs/remotes/origin/{self.branch}"
        if not self._has_revision(base_ref):
            base_ref = "FETCH_HEAD" if self._has_revision("FETCH_HEAD") else "HEAD"
        cutoff = datetime.combine(snapshot_date, time.max, tzinfo=timezone.utc).isoformat()
        revision = self._run("rev-list", "-1", f"--before={cutoff}", base_ref).strip()
        if not revision:
            raise SourceError(f"no {self.url} revision exists on or before {snapshot_date}")
        return revision

    def materialize(self, revision: str, sparse_path: str) -> Path:
        self._run("sparse-checkout", "init", "--cone")
        self._run("sparse-checkout", "set", sparse_path)
        self._run("checkout", "-q", "--detach", "--force", revision, timeout=self.timeout)
        return self.path / sparse_path

    def iter_log(self, revision: str, since: date) -> Iterator[tuple[str, str, str, str]]:
        output = self._run(
            "log",
            revision,
            f"--since={since.isoformat()}",
            "--format=%H%x1f%aI%x1f%B%x1e",
        )
        for item in output.split("\x1e"):
            parts = item.strip("\n").split("\x1f", 2)
            if len(parts) == 3:
                lines = parts[2].splitlines()
                subject = lines[0] if lines else ""
                body = "\n".join(lines[1:])
                yield parts[0], parts[1], subject, body

    def _has_revision(self, revision: str) -> bool:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", revision],
            cwd=self.path,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0

    def _run(self, *arguments: str, timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=self.path,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise SourceError(f"Git command timed out for {self.url}: {' '.join(arguments)}") from exc
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise SourceError(f"Git command failed for {self.url}: {detail}")
        return result.stdout


class GitHubClient:
    """Small cached GitHub REST client used by heuristic commit matching."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        token: str | None,
        offline: bool,
        refresh: bool,
        timeout: int = 30,
    ) -> None:
        self.cache_dir = cache_dir
        self.token = token
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout

    def get_json(self, url: str, parameters: dict[str, str | int] | None = None) -> Any:
        if parameters:
            url = f"{url}?{urlencode(parameters)}"
        cache_path = self.cache_dir / f"{hashlib.sha256(url.encode()).hexdigest()}.json"
        if cache_path.exists() and not self.refresh:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        if self.offline:
            raise SourceError(f"offline HTTP cache miss: {url}")

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "FreeVRG-dataset-builder/1.4",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                LOGGER.debug("GET %s (attempt %d/3)", url, attempt)
                with urlopen(Request(url, headers=headers), timeout=self.timeout) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = cache_path.with_suffix(".tmp")
                temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                os.replace(temporary, cache_path)
                return payload
            except HTTPError as exc:
                last_error = exc
                reset = exc.headers.get("X-RateLimit-Reset")
                LOGGER.warning(
                    "GitHub request failed: url=%s status=%s rate_reset=%s attempt=%d/3",
                    url,
                    exc.code,
                    reset or "unknown",
                    attempt,
                )
                if exc.code not in {403, 429, 500, 502, 503, 504}:
                    break
            except (URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                LOGGER.warning("GitHub request failed: url=%s error=%s attempt=%d/3", url, exc, attempt)
            if attempt < 3:
                time_module.sleep(2 ** (attempt - 1))
        raise SourceError(f"GitHub request failed after 3 attempts: {url}: {last_error}")

    def search_commits(self, query: str) -> list[dict[str, Any]]:
        payload = self.get_json(
            "https://api.github.com/search/commits", {"q": query, "per_page": 100}
        )
        return list(payload.get("items", []))

    def commit(self, owner: str, repository: str, sha: str) -> dict[str, Any]:
        return self.get_json(f"https://api.github.com/repos/{owner}/{repository}/commits/{sha}")

    def commits_for_path(
        self, owner: str, repository: str, path: str, since: date, until: date
    ) -> list[dict[str, Any]]:
        return list(
            self.get_json(
                f"https://api.github.com/repos/{owner}/{repository}/commits",
                {
                    "path": path,
                    "since": f"{since.isoformat()}T00:00:00Z",
                    "until": f"{until.isoformat()}T23:59:59Z",
                    "per_page": 100,
                },
            )
        )


class FreeBSDCommitMatcher:
    def __init__(self, client: GitHubClient) -> None:
        self.client = client

    def match_svn(self, record: DatasetRecord) -> tuple[list[str], list[str]]:
        candidates: dict[str, tuple[int, str]] = {}
        announced = parse_announced_date(record.announced)
        for revision in record.svn_revisions:
            query = (
                f'repo:freebsd/freebsd-src "MFC r{revision}" '
                f"committer-date:{announced - timedelta(days=45)}..{announced + timedelta(days=45)}"
            )
            for item in self.client.search_commits(query):
                sha = str(item.get("sha", ""))
                if not sha:
                    continue
                detail = self.client.commit("freebsd", "freebsd-src", sha)
                paths = [file.get("filename", "") for file in detail.get("files", [])]
                message = str(detail.get("commit", {}).get("message", ""))
                if is_document_only_commit(message, paths):
                    continue
                score = score_commit_candidate(record.module, record.topic, paths, message, revision)
                if score >= 4:
                    candidates[sha] = max(candidates.get(sha, (-1, "")), (score, sha))
        ordered = [sha for _, sha in sorted(candidates.values(), reverse=True)[:1]]
        return [sha[:12] for sha in ordered], [f"{FREEBSD_COMMIT}/{sha}" for sha in ordered]

    def match_upstream(
        self, record: DatasetRecord, project: UpstreamProject
    ) -> tuple[list[str], list[str]]:
        announced = parse_announced_date(record.announced)
        candidates = self.client.commits_for_path(
            "freebsd",
            "freebsd-src",
            project.freebsd_path,
            announced - timedelta(days=30),
            announced + timedelta(days=730),
        )
        best: tuple[int, str] | None = None
        for item in candidates:
            sha = str(item.get("sha", ""))
            message = str(item.get("commit", {}).get("message", ""))
            score = score_commit_candidate(
                record.module, record.topic, [project.freebsd_path], message, record.cve[0]
            )
            if best is None or score > best[0]:
                best = (score, sha)
        if best is None or best[0] < 3:
            return [], []
        short = best[1][:12]
        return [short], [f"{FREEBSD_COMMIT}/{short}"]


def score_commit_candidate(
    module: str, topic: str, changed_paths: Iterable[str], message: str, needle: str
) -> int:
    text = f"{message}\n{topic}".lower()
    normalized_module = module.lower()
    score = 0
    if needle.lower() in text:
        score += 4
    if normalized_module and normalized_module in text:
        score += 2
    if any(normalized_module in path.lower() for path in changed_paths):
        score += 3
    if is_document_only_commit(message, changed_paths):
        score -= 10
    return score


def collect_freebsd_advisories(
    repository: GitRepository, snapshot_date: date
) -> list[DatasetRecord]:
    repository.ensure(snapshot_date - timedelta(days=2))
    revision = repository.revision_at(snapshot_date)
    advisory_dir = repository.materialize(revision, FREEBSD_ADVISORY_DIR)
    records: list[DatasetRecord] = []
    for path in sorted(advisory_dir.glob("FreeBSD-SA-*.asc")):
        parsed = parse_advisory(path.name, path.read_text(encoding="utf-8", errors="replace"))
        if parsed is None:
            continue
        if parsed.year < 2015 or parse_announced_date(parsed.announced) > snapshot_date:
            continue
        records.append(parsed)
    return records


def parse_advisory(filename: str, text: str) -> DatasetRecord | None:
    match = ADVISORY_RE.match(filename)
    if not match:
        return None
    sa_id = f"FreeBSD-SA-{match.group(1)}"
    module = match.group(2)
    announced = first_header_value(text, "Announced")
    if not announced or not re.match(r"\d{4}-\d{2}-\d{2}", announced):
        return None

    correction = correction_details(text)
    hashes = unique(item[:12].lower() for item in HASH_RE.findall(correction))
    revisions = unique(REVISION_RE.findall(correction))
    cves = unique(match.group(0).upper() for match in CVE_RE.finditer(text))
    record = DatasetRecord(
        sa_id=sa_id,
        year=int(announced[:4]),
        announced=announced,
        topic=first_header_value(text, "Topic"),
        category=first_header_value(text, "Category"),
        module=module,
        scope_tier=classify_scope(module),
        is_priority=False,
        cve=cves,
        cwe=[],
        affects=first_header_value(text, "Affects"),
        git_hashes=hashes,
        svn_revisions=revisions,
        github_commit_urls=[f"{FREEBSD_COMMIT}/{item}" for item in hashes],
        advisory_raw_url=f"{FREEBSD_DOC_RAW}/{FREEBSD_ADVISORY_DIR}/{filename}",
        diff_available=False,
    )
    record.recompute()
    return record


def collect_upstream_records(
    cache_root: Path,
    snapshot_date: date,
    covered_cves: set[str],
    excluded_cves: set[str],
    *,
    offline: bool,
    refresh: bool,
) -> list[DatasetRecord]:
    records: list[DatasetRecord] = []
    for project in UPSTREAM_PROJECTS:
        repository = GitRepository(
            cache_root / "git" / f"{project.owner}__{project.repository}",
            project.url,
            project.branch,
            offline=offline,
            refresh=refresh,
        )
        repository.ensure(date(2014, 12, 1))
        revision = repository.revision_at(snapshot_date)
        records.extend(
            records_from_upstream_log(
                project,
                repository.iter_log(revision, date(2015, 1, 1)),
                covered_cves,
                excluded_cves,
            )
        )
    return records


def records_from_upstream_log(
    project: UpstreamProject,
    commits: Iterable[tuple[str, str, str, str]],
    covered_cves: set[str],
    excluded_cves: set[str],
) -> list[DatasetRecord]:
    records: list[DatasetRecord] = []
    seen: set[str] = set()
    for sha, authored_at, subject, body in commits:
        message = f"{subject}\n{body}"
        for cve in unique(match.group(0).upper() for match in CVE_RE.finditer(message)):
            if cve in covered_cves or cve in excluded_cves or cve in seen:
                continue
            seen.add(cve)
            announced = datetime.fromisoformat(authored_at).astimezone(timezone.utc).date().isoformat()
            record = DatasetRecord(
                sa_id=f"UPSTREAM-{project.id_prefix}-{cve}",
                year=int(announced[:4]),
                announced=announced,
                topic=subject[:80],
                category="contrib",
                module=project.module,
                scope_tier=project.scope,
                is_priority=True,
                cve=[cve],
                cwe=[],
                affects="",
                git_hashes=[],
                svn_revisions=[],
                github_commit_urls=[],
                advisory_raw_url=f"{project.commit_url}/{sha[:12]}",
                diff_available=False,
                source="upstream_commit",
                upstream_path=project.freebsd_path,
            )
            record.recompute()
            records.append(record)
    return records


def first_header_value(text: str, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}:\s*(.*)$", text)
    return match.group(1).strip() if match else ""


def correction_details(text: str) -> str:
    start = re.search(r"(?im)^VI\.\s+Correction details\s*$", text)
    if not start:
        return ""
    tail = text[start.end() :]
    end = re.search(r"(?im)^VII\.\s+References\s*$", tail)
    return tail[: end.start()] if end else tail


def parse_announced_date(value: str) -> date:
    match = re.match(r"\d{4}-\d{2}-\d{2}", value)
    if not match:
        raise ValueError(f"invalid announced date: {value!r}")
    return date.fromisoformat(match.group(0))


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
