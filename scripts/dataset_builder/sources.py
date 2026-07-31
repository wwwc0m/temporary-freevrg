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
GITHUB_PAGE_SIZE = 100
GITHUB_MAX_PAGES = 20
VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?(\d+\.\d+(?:\.\d+){0,2}[a-z]?)(?![A-Za-z0-9])", re.I)


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


@dataclass(frozen=True, slots=True)
class CommitEvidence:
    full_shas: tuple[str, ...]
    changed_paths: tuple[str, ...]
    messages: tuple[str, ...] = ()
    committed_dates: tuple[date, ...] = ()
    noise_only: bool = False

    @property
    def git_hashes(self) -> list[str]:
        return [sha[:12] for sha in self.full_shas]

    @property
    def github_commit_urls(self) -> list[str]:
        return [f"{FREEBSD_COMMIT}/{sha}" for sha in self.full_shas]


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
        initialized = False
        if not (self.path / ".git").exists():
            if self.offline:
                raise SourceError(f"offline cache is missing Git repository: {self.path}")
            self.path.mkdir(parents=True, exist_ok=True)
            self._run("init", "-q")
            self._run("remote", "add", "origin", self.url)
            initialized = True

        remote_ref = f"refs/remotes/origin/{self.branch}"
        has_ref = any(
            self._has_revision(revision) for revision in (remote_ref, "FETCH_HEAD", "HEAD")
        )
        if self.offline:
            if not has_ref:
                raise SourceError(f"offline Git cache has no usable ref: {self.path}")
            return

        refspec = f"refs/heads/{self.branch}:{remote_ref}"
        command = [
            "fetch",
            "--prune",
            "--filter=blob:none",
            "--update-shallow",
            "origin",
            refspec,
        ]
        if initialized or self._is_shallow():
            command.insert(-2, f"--shallow-since={shallow_since.isoformat()}")
        if self.refresh:
            command.insert(1, "--force")
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                LOGGER.info("fetching %s (attempt %d/3)", self.url, attempt)
                self._run(*command, timeout=self.timeout)
                self._write_metadata()
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
        if not revision and self._is_shallow():
            if self.offline:
                raise SourceError(
                    f"offline Git cache at {self.path} is too shallow for {snapshot_date}; "
                    "rerun online with --refresh to deepen it"
                )
            LOGGER.info("deepening %s to resolve snapshot %s", self.url, snapshot_date)
            remote_ref = f"refs/remotes/origin/{self.branch}"
            self._run(
                "fetch",
                "--unshallow",
                "origin",
                f"refs/heads/{self.branch}:{remote_ref}",
                timeout=self.timeout,
            )
            self._write_metadata()
            base_ref = remote_ref if self._has_revision(remote_ref) else base_ref
            revision = self._run("rev-list", "-1", f"--before={cutoff}", base_ref).strip()
        if not revision:
            raise SourceError(
                f"no cached {self.url} revision exists on or before {snapshot_date}; "
                "check the requested snapshot or rerun online with --refresh"
            )
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

    def _is_shallow(self) -> bool:
        return self._run("rev-parse", "--is-shallow-repository").strip() == "true"

    def _write_metadata(self) -> None:
        base_ref = f"refs/remotes/origin/{self.branch}"
        if not self._has_revision(base_ref):
            base_ref = "FETCH_HEAD" if self._has_revision("FETCH_HEAD") else "HEAD"
        root_sha = self._run("rev-list", "--max-parents=0", base_ref).splitlines()[0]
        earliest = self._run("show", "-s", "--format=%aI", root_sha).strip()
        payload = {
            "repository_url": self.url,
            "branch": self.branch,
            "last_fetched_at": datetime.now(timezone.utc).isoformat(),
            "earliest_available_commit_date": earliest,
            "latest_remote_commit": self._run("rev-parse", base_ref).strip(),
        }
        metadata = self.path / ".freevrg-cache.json"
        temporary = metadata.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, metadata)

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
        return self._get_all_pages(
            "https://api.github.com/search/commits",
            {"q": query},
            items_key="items",
        )

    def commit(self, owner: str, repository: str, sha: str) -> dict[str, Any]:
        return self.get_json(f"https://api.github.com/repos/{owner}/{repository}/commits/{sha}")

    def commits_for_path(
        self, owner: str, repository: str, path: str, since: date, until: date
    ) -> list[dict[str, Any]]:
        return self._get_all_pages(
            f"https://api.github.com/repos/{owner}/{repository}/commits",
            {
                "path": path,
                "since": f"{since.isoformat()}T00:00:00Z",
                "until": f"{until.isoformat()}T23:59:59Z",
            },
        )

    def _get_all_pages(
        self,
        url: str,
        parameters: dict[str, str | int],
        *,
        items_key: str | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for page in range(1, GITHUB_MAX_PAGES + 1):
            page_parameters = {
                **parameters,
                "per_page": GITHUB_PAGE_SIZE,
                "page": page,
            }
            payload = self.get_json(url, page_parameters)
            raw_items = payload.get(items_key, []) if items_key else payload
            if not isinstance(raw_items, list):
                raise SourceError(f"unexpected paginated GitHub response from {url}")
            items = [item for item in raw_items if isinstance(item, dict)]
            results.extend(items)
            if len(raw_items) < GITHUB_PAGE_SIZE:
                break
        else:
            LOGGER.warning("stopped GitHub pagination at safety limit %d: %s", GITHUB_MAX_PAGES, url)
        return results


class FreeBSDCommitMatcher:
    def __init__(self, client: GitHubClient) -> None:
        self.client = client

    def inspect_existing(self, record: DatasetRecord) -> CommitEvidence | None:
        evidence: list[CommitEvidence] = []
        for sha in record.git_hashes:
            try:
                detail = self.client.commit("freebsd", "freebsd-src", sha)
            except SourceError as exc:
                LOGGER.warning("cannot inspect existing FreeBSD commit %s: %s", sha, exc)
                return None
            evidence.append(commit_evidence_from_detail(detail, sha))
        if not evidence:
            return None
        code = [item for item in evidence if not item.noise_only]
        selected = code or evidence
        return combine_commit_evidence(selected, noise_only=not code)

    def match_svn(self, record: DatasetRecord) -> CommitEvidence | None:
        candidates: dict[str, tuple[int, CommitEvidence]] = {}
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
                try:
                    detail = self.client.commit("freebsd", "freebsd-src", sha)
                except SourceError as exc:
                    LOGGER.warning("cannot inspect SVN candidate %s: %s", sha, exc)
                    continue
                evidence = commit_evidence_from_detail(detail, sha)
                if evidence.noise_only:
                    continue
                score = score_commit_candidate(
                    record.module,
                    record.topic,
                    evidence.changed_paths,
                    evidence.messages[0],
                    revision,
                )
                if score >= 4:
                    full_sha = evidence.full_shas[0]
                    current = candidates.get(full_sha)
                    if current is None or score > current[0]:
                        candidates[full_sha] = (score, evidence)
        if not candidates:
            return None
        return max(candidates.values(), key=lambda item: item[0])[1]

    def match_upstream(
        self, record: DatasetRecord, project: UpstreamProject
    ) -> CommitEvidence | None:
        announced = parse_announced_date(record.announced)
        candidates = self.client.commits_for_path(
            "freebsd",
            "freebsd-src",
            project.freebsd_path,
            announced - timedelta(days=30),
            announced + timedelta(days=730),
        )
        best: tuple[int, CommitEvidence] | None = None
        for item in candidates:
            sha = str(item.get("sha", ""))
            if not sha:
                continue
            try:
                detail = self.client.commit("freebsd", "freebsd-src", sha)
            except SourceError as exc:
                LOGGER.warning("cannot inspect upstream candidate %s: %s", sha, exc)
                continue
            evidence = commit_evidence_from_detail(detail, sha)
            if not evidence.committed_dates:
                continue
            committed = evidence.committed_dates[0]
            if not announced - timedelta(days=30) <= committed <= announced + timedelta(days=730):
                continue
            if evidence.noise_only:
                continue
            if not paths_touch_module(evidence.changed_paths, project.freebsd_path):
                continue
            message = evidence.messages[0]
            if not has_upstream_link_signal(record, message):
                continue
            score = score_commit_candidate(
                record.module,
                record.topic,
                evidence.changed_paths,
                message,
                record.cve[0] if record.cve else "",
            )
            if best is None or score > best[0]:
                best = (score, evidence)
        return best[1] if best is not None else None


def commit_evidence_from_detail(detail: dict[str, Any], requested_sha: str) -> CommitEvidence:
    sha = str(detail.get("sha") or requested_sha)
    commit = detail.get("commit") if isinstance(detail.get("commit"), dict) else {}
    message = str(commit.get("message", ""))
    paths = tuple(
        str(file.get("filename", ""))
        for file in detail.get("files", [])
        if isinstance(file, dict) and file.get("filename")
    )
    committed = parse_github_commit_date(commit)
    return CommitEvidence(
        full_shas=(sha,),
        changed_paths=paths,
        messages=(message,),
        committed_dates=(committed,) if committed else (),
        noise_only=is_document_only_commit(message, paths),
    )


def combine_commit_evidence(
    evidence: Iterable[CommitEvidence], *, noise_only: bool = False
) -> CommitEvidence:
    items = list(evidence)
    return CommitEvidence(
        full_shas=tuple(sha for item in items for sha in item.full_shas),
        changed_paths=tuple(unique(path for item in items for path in item.changed_paths)),
        messages=tuple(message for item in items for message in item.messages),
        committed_dates=tuple(value for item in items for value in item.committed_dates),
        noise_only=noise_only,
    )


def parse_github_commit_date(commit: dict[str, Any]) -> date | None:
    for key in ("committer", "author"):
        person = commit.get(key)
        if not isinstance(person, dict) or not person.get("date"):
            continue
        try:
            return datetime.fromisoformat(str(person["date"]).replace("Z", "+00:00")).date()
        except ValueError:
            continue
    return None


def paths_touch_module(changed_paths: Iterable[str], module_path: str) -> bool:
    prefix = module_path.rstrip("/")
    return any(path == prefix or path.startswith(f"{prefix}/") for path in changed_paths)


def has_upstream_link_signal(record: DatasetRecord, candidate_message: str) -> bool:
    message_upper = candidate_message.upper()
    if any(cve.upper() in message_upper for cve in record.cve):
        return True
    upstream_versions = set(VERSION_RE.findall(f"{record.upstream_message}\n{record.topic}"))
    candidate_versions = set(VERSION_RE.findall(candidate_message))
    return bool(upstream_versions & candidate_versions)


def score_commit_candidate(
    module: str, topic: str, changed_paths: Iterable[str], message: str, needle: str
) -> int:
    text = f"{message}\n{topic}".lower()
    normalized_module = module.lower()
    score = 0
    if needle and needle.lower() in text:
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
                upstream_message=message,
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
