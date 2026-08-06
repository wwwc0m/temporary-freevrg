from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from core.models import slugify


def materialize_child_sample(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    cve = str(child["cve"]).strip().upper()
    target_functions = _string_list(child.get("target_functions"))
    files_changed = _string_list(child.get("files_changed"))
    evidence_mode = str(child.get("evidence_mode") or "ambiguous")
    confidence = str(child.get("confidence") or "low")

    before_code = _filter_code_map(parent.get("before_code"), target_functions, files_changed)
    after_code = _filter_code_map(parent.get("after_code"), target_functions, files_changed)

    payload = {
        "id": cve,
        "source_sa": parent.get("source_sa") or parent.get("id", ""),
        "cve": [cve],
        "subsystem": parent.get("subsystem", ""),
        "cwe": deepcopy(parent.get("cwe", [])),
        "affected_versions": deepcopy(parent.get("affected_versions", [])),
        "fix_commits": deepcopy(parent.get("fix_commits", [])),
        "advisory_source": parent.get("advisory_source", ""),
        "advisory_text": parent.get("advisory_text", ""),
        "files_changed": files_changed or deepcopy(parent.get("files_changed", [])),
        "diff": _filter_diff(str(parent.get("diff") or ""), files_changed),
        "extractable": bool(before_code and after_code),
        "before_code": before_code,
        "after_code": after_code,
        "context": deepcopy(parent.get("context", {})),
    }
    payload["context"].update(
        {
            "source_sa": payload["source_sa"],
            "target_functions": target_functions,
            "multi_cve_split": {
                "evidence_mode": evidence_mode,
                "confidence": confidence,
                "rationale": str(child.get("rationale") or ""),
                "diff_keywords": _string_list(child.get("diff_keywords")),
            },
            "requires_human_review": _requires_human_review(evidence_mode, confidence),
        }
    )
    return payload


def child_sample_filename(child_sample: dict[str, Any]) -> str:
    source_sa = str(child_sample.get("source_sa") or "").strip()
    cve = str((child_sample.get("cve") or [child_sample.get("id", "sample")])[0])
    if source_sa:
        return f"{slugify(source_sa)}-{slugify(cve)}.json"
    return f"{slugify(cve)}.json"


def _filter_code_map(
    raw_value: Any,
    target_functions: list[str],
    files_changed: list[str],
) -> dict[str, str]:
    if not isinstance(raw_value, dict):
        return {}
    selected: dict[str, str] = {}
    target_set = set(target_functions)
    file_set = set(files_changed)
    for key, value in raw_value.items():
        key_text = str(key)
        function_name = key_text.rsplit("::", 1)[-1]
        file_name = key_text.split("::", 1)[0]
        if target_set and function_name not in target_set and key_text not in target_set:
            continue
        if file_set and file_name not in file_set:
            continue
        selected[key_text] = str(value)
    if selected:
        return selected
    return {str(key): str(value) for key, value in raw_value.items()}


def _filter_diff(diff: str, files_changed: list[str]) -> str:
    if not diff or not files_changed:
        return diff
    chunks = re.split(r"(?=^diff --git )", diff, flags=re.MULTILINE)
    selected = [
        chunk
        for chunk in chunks
        if any(f" b/{path}" in chunk or f"+++ b/{path}" in chunk for path in files_changed)
    ]
    return "".join(selected).strip() or diff


def _requires_human_review(evidence_mode: str, confidence: str) -> bool:
    return evidence_mode not in {"exact_patch", "child_commit_exact"} or confidence != "high"


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []
