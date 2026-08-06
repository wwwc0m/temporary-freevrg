from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


class SampleBuildError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BuildStats:
    written: int
    skipped: int
    failed: int


class DatasetSampleBuilder:
    def __init__(
        self,
        *,
        dataset_path: Path,
        freebsd_src: Path,
        output_dir: Path,
        cache_dir: Path,
        offline: bool = False,
        fetch_missing: bool = False,
        overwrite: bool = False,
        limit: int | None = None,
        sa_id: str | None = None,
    ) -> None:
        self.dataset_path = dataset_path
        self.freebsd_src = freebsd_src
        self.output_dir = output_dir
        self.cache_dir = cache_dir
        self.offline = offline
        self.fetch_missing = fetch_missing
        self.overwrite = overwrite
        self.limit = limit
        self.sa_id = sa_id

    def build(self) -> BuildStats:
        records = self._load_records()
        written = skipped = failed = 0
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for record in records:
            if self.sa_id and record.get("sa_id") != self.sa_id:
                continue
            if not self._is_supported_record(record):
                skipped += 1
                continue
            output_path = self.output_dir / f"{self._sample_file_stem(record)}.json"
            if output_path.exists() and not self.overwrite:
                skipped += 1
                continue
            try:
                sample = self.build_one(record)
            except SampleBuildError:
                failed += 1
                continue
            output_path.write_text(
                json.dumps(sample, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            written += 1
            if self.limit is not None and written >= self.limit:
                break
        return BuildStats(written=written, skipped=skipped, failed=failed)

    def build_one(self, record: dict[str, Any]) -> dict[str, Any]:
        commit = self._select_commit(record)
        self._ensure_commit(commit)
        diff = self._git("show", "--format=", "--find-renames", "--unified=80", commit)
        changed_paths = self._changed_source_paths(diff)
        if not changed_paths:
            raise SampleBuildError(f"no changed C source paths for {record.get('sa_id')}")

        function_names = self._function_names_from_diff(diff)
        before_code: dict[str, str] = {}
        after_code: dict[str, str] = {}
        for path in changed_paths:
            before_text = self._show_text(f"{commit}^:{path}")
            after_text = self._show_text(f"{commit}:{path}")
            path_function_names = function_names or self._changed_function_names(
                before_text,
                after_text,
            )
            for function_name in path_function_names:
                before_function = extract_c_function(before_text, function_name)
                after_function = extract_c_function(after_text, function_name)
                if before_function and after_function:
                    key = f"{path}::{function_name}"
                    before_code[key] = before_function
                    after_code[key] = after_function

        if not before_code:
            raise SampleBuildError(
                f"could not extract changed functions for {record.get('sa_id')} at {commit}"
            )

        cve_values = [str(item) for item in record.get("cve", []) if str(item).strip()]
        return {
            "id": record.get("sa_id", ""),
            "cve": cve_values,
            "subsystem": record.get("module", ""),
            "cwe": record.get("cwe", []),
            "affected_versions": [record["affects"]] if record.get("affects") else [],
            "fix_commits": [commit],
            "advisory_source": "freebsd_sa_dataset",
            "advisory_text": self._advisory_text(record),
            "files_changed": changed_paths,
            "diff": diff,
            "extractable": True,
            "before_code": before_code,
            "after_code": after_code,
            "context": {
                "dataset_record": record,
                "target_functions": sorted({key.rsplit("::", 1)[1] for key in before_code}),
            },
        }

    def _load_records(self) -> list[dict[str, Any]]:
        payload = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise SampleBuildError("dataset JSON must be a list")
        return [item for item in payload if isinstance(item, dict)]

    def _is_supported_record(self, record: dict[str, Any]) -> bool:
        return (
            len(record.get("cve") or []) == 1
            and bool(record.get("git_hashes") or record.get("github_commit_urls"))
            and record.get("source") in {None, ""}
        )

    def _select_commit(self, record: dict[str, Any]) -> str:
        for url in record.get("github_commit_urls") or []:
            match = re.search(r"/commit/([0-9a-fA-F]{12,40})", str(url))
            if match:
                return match.group(1)
        hashes = record.get("git_hashes") or []
        if hashes:
            return str(hashes[0])
        raise SampleBuildError(f"record has no commit: {record.get('sa_id')}")

    def _ensure_commit(self, commit: str) -> None:
        if self._git_ok("cat-file", "-e", f"{commit}^{{commit}}"):
            return
        if self.offline or not self.fetch_missing:
            raise SampleBuildError(
                f"missing commit {commit}; rerun with --fetch-missing or use a fuller src repo"
            )
        self._git("fetch", "origin", commit, timeout=300)
        if not self._git_ok("cat-file", "-e", f"{commit}^{{commit}}"):
            raise SampleBuildError(f"fetched commit is still unavailable: {commit}")

    def _show_text(self, revision_path: str) -> str:
        try:
            return self._git("show", revision_path)
        except SampleBuildError:
            return ""

    def _changed_source_paths(self, diff: str) -> list[str]:
        paths: list[str] = []
        current: str | None = None
        for line in diff.splitlines():
            if line.startswith("diff --git "):
                parts = line.split()
                current = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else None
            elif current and line.startswith("+++ b/"):
                path = line.removeprefix("+++ b/")
                if path.endswith((".c", ".h")) and path not in paths:
                    paths.append(path)
                current = None
        return paths

    def _function_names_from_diff(self, diff: str) -> list[str]:
        names: list[str] = []
        for line in diff.splitlines():
            if not line.startswith("@@"):
                continue
            suffix = line.rsplit("@@", 1)[-1].strip()
            for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", suffix):
                if name not in {"if", "for", "while", "switch", "return"} and name not in names:
                    names.append(name)
        return names

    def _changed_function_names(self, before_text: str, after_text: str) -> list[str]:
        before_names = _function_names_from_source(before_text)
        after_names = set(_function_names_from_source(after_text))
        names: list[str] = []
        for name in before_names:
            if name not in after_names:
                continue
            before_function = extract_c_function(before_text, name)
            after_function = extract_c_function(after_text, name)
            if before_function and after_function and before_function != after_function:
                names.append(name)
        return names

    def _advisory_text(self, record: dict[str, Any]) -> str:
        url = str(record.get("advisory_raw_url") or "")
        if not url:
            return ""
        cache_path = self.cache_dir / "advisories" / f"{_safe_file_name(url)}.txt"
        if cache_path.exists():
            return cache_path.read_text(encoding="utf-8")
        if self.offline:
            return ""
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with urlopen(Request(url, headers={"User-Agent": "FreeVRG-sample-builder/0.1"}), timeout=30) as response:
                text = response.read().decode("utf-8", errors="replace")
        except (OSError, URLError):
            return ""
        cache_path.write_text(text, encoding="utf-8")
        return text

    def _sample_file_stem(self, record: dict[str, Any]) -> str:
        return str(record.get("sa_id") or "sample").replace(":", "-").lower()

    def _git_ok(self, *arguments: str) -> bool:
        return (
            subprocess.run(
                ["git", *arguments],
                cwd=self.freebsd_src,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )

    def _git(self, *arguments: str, timeout: int = 60) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=self.freebsd_src,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise SampleBuildError(f"git {' '.join(arguments)} failed: {detail}")
        return completed.stdout


def extract_c_function(source: str, function_name: str) -> str | None:
    for match in re.finditer(rf"\b{re.escape(function_name)}\s*\(", source):
        open_brace = _find_function_open_brace(source, match.end())
        if open_brace is None:
            continue
        start = _find_function_start(source, match.start())
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        return source[start : end + 1].strip()
    return None


def _function_names_from_source(source: str) -> list[str]:
    names: list[str] = []
    pattern = re.compile(
        r"(?m)^[A-Za-z_][A-Za-z0-9_ \t\*]*\n?"
        r"[A-Za-z_][A-Za-z0-9_ \t\*]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{"
    )
    for match in pattern.finditer(source):
        name = match.group(1)
        if name not in names:
            names.append(name)
    return names


def _find_function_open_brace(source: str, start: int) -> int | None:
    depth = 1
    index = start
    while index < len(source):
        char = source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "{" and depth == 0:
            return index
        elif char == ";" and depth == 0:
            return None
        index += 1
    return None


def _find_function_start(source: str, name_start: int) -> int:
    line_start = source.rfind("\n", 0, name_start) + 1
    previous_blank = source.rfind("\n\n", 0, line_start)
    if previous_blank >= 0:
        return previous_blank + 2
    return line_start


def _find_matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    index = open_brace
    state = "code"
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "*":
                state = "block-comment"
                index += 2
                continue
            if char == "/" and nxt == "/":
                state = "line-comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state == "block-comment" and char == "*" and nxt == "/":
            state = "code"
            index += 2
            continue
        elif state == "line-comment" and char == "\n":
            state = "code"
        elif state == "string":
            if char == "\\":
                index += 2
                continue
            if char == '"':
                state = "code"
        elif state == "char":
            if char == "\\":
                index += 2
                continue
            if char == "'":
                state = "code"
        index += 1
    return None


def _safe_file_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "advisory"
