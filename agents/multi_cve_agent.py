from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from agents.base import BaseAgent
from core.config import AppConfig
from core.models import SampleRecord, compact_text
from core.observability import Observability


class MultiCveAgent(BaseAgent):
    """Split a multi-CVE advisory sample into CVE-specific child specs."""

    def __init__(self, config: AppConfig, observability: Observability | None = None) -> None:
        super().__init__(config, Path("prompts/multi_cve_agent.md"), "multi-cve", observability)

    def split_sample(self, sample: SampleRecord) -> list[dict[str, Any]]:
        cve_values = sample.list_field("cve")
        if len(cve_values) <= 1:
            return []

        with self.observation(
            name="split-multi-cve",
            as_type="span",
            input_payload={"sample_id": sample.sample_id, "cve": cve_values},
            metadata={
                "agent": "multi-cve",
                "backend": self.profile.backend,
                "model": self.profile.model,
            },
        ) as observation:
            model_output = self.invoke_model(user_prompt=self._build_user_prompt(sample))
            if model_output:
                children = self._parse_children(model_output, cve_values)
                observation.update(
                    output={"children": children},
                    metadata={"agent": "multi-cve", "execution_mode": "llm"},
                )
                return children

            children = self._fallback_children(sample, cve_values)
            observation.update(
                output={"children": children},
                metadata={"agent": "multi-cve", "execution_mode": "local-fallback"},
            )
            return children

    def _build_user_prompt(self, sample: SampleRecord) -> str:
        payload = sample.payload
        before_keys = sorted((payload.get("before_code") or {}).keys())
        after_keys = sorted((payload.get("after_code") or {}).keys())
        return "\n".join(
            [
                "Split this multi-CVE FreeBSD sample into CVE-specific child specs.",
                "Return JSON only.",
                "",
                f"sample_id: {sample.sample_id}",
                f"cve: {compact_text(sample.list_field('cve'))}",
                f"subsystem: {sample.text_field('subsystem', default='unknown')}",
                f"files_changed: {compact_text(sample.list_field('files_changed'))}",
                f"before_code_keys: {compact_text(before_keys)}",
                f"after_code_keys: {compact_text(after_keys)}",
                "context:",
                compact_text(payload.get("context")),
                "advisory_text:",
                self._truncate(sample.text_field("advisory_text", default="N/A"), limit=12000),
                "diff:",
                self._truncate(sample.text_field("diff", default="N/A"), limit=20000),
            ]
        )

    def _parse_children(self, raw_output: str, allowed_cves: list[str]) -> list[dict[str, Any]]:
        payload = _loads_json_object(raw_output)
        raw_children = payload.get("children")
        if not isinstance(raw_children, list):
            raise ValueError("MultiCveAgent response must contain a children list")

        children: list[dict[str, Any]] = []
        seen: set[str] = set()
        allowed = set(allowed_cves)
        for raw_child in raw_children:
            if not isinstance(raw_child, dict):
                continue
            cve = str(raw_child.get("cve") or "").strip().upper()
            if cve not in allowed or cve in seen:
                continue
            seen.add(cve)
            children.append(_normalize_child(raw_child, cve))
        missing = [cve for cve in allowed_cves if cve not in seen]
        children.extend(
            {
                "cve": cve,
                "target_functions": [],
                "files_changed": [],
                "evidence_mode": "ambiguous",
                "confidence": "low",
                "rationale": "model response omitted this CVE",
                "diff_keywords": [],
            }
            for cve in missing
        )
        return children

    def _fallback_children(self, sample: SampleRecord, cve_values: list[str]) -> list[dict[str, Any]]:
        function_names = sorted(
            {
                key.rsplit("::", 1)[1]
                for key in (sample.payload.get("before_code") or {})
                if "::" in key
            }
        )
        return [
            {
                "cve": cve,
                "target_functions": function_names,
                "files_changed": sample.list_field("files_changed"),
                "evidence_mode": "cve_guided_composite",
                "confidence": "low",
                "rationale": "local fallback preserves the composite diff and requires review",
                "diff_keywords": [],
            }
            for cve in cve_values
        ]

    def _truncate(self, text: str, *, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "\n[truncated]"


def _loads_json_object(raw_output: str) -> dict[str, Any]:
    text = raw_output.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end >= start:
            text = text[start : end + 1]
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("MultiCveAgent response must be a JSON object")
    return payload


def _normalize_child(raw_child: dict[str, Any], cve: str) -> dict[str, Any]:
    evidence_mode = str(raw_child.get("evidence_mode") or "ambiguous").strip()
    if evidence_mode not in {
        "exact_patch",
        "child_commit_exact",
        "cve_guided_composite",
        "ambiguous",
    }:
        evidence_mode = "ambiguous"

    confidence = str(raw_child.get("confidence") or "low").strip().lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"

    return {
        "cve": cve,
        "target_functions": _string_list(raw_child.get("target_functions")),
        "files_changed": _string_list(raw_child.get("files_changed")),
        "evidence_mode": evidence_mode,
        "confidence": confidence,
        "rationale": str(raw_child.get("rationale") or "").strip(),
        "diff_keywords": _string_list(raw_child.get("diff_keywords")),
    }


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []
