from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from agents.base import BaseAgent
from core.config import AppConfig
from core.models import SampleRecord
from core.observability import Observability


class HarnessAgent(BaseAgent):
    """Generate vulnerable/fixed C harnesses for CodeQL mechanism validation."""

    _FENCED_BLOCK = re.compile(
        r"```[ \t]*(?P<language>[A-Za-z0-9_-]*)[ \t]*\r?\n(?P<body>.*?)```",
        flags=re.DOTALL,
    )

    def __init__(self, config: AppConfig, observability: Observability | None = None) -> None:
        super().__init__(config, Path("prompts/harness_agent.md"), "harness", observability)

    def generate_harness_pair(
        self,
        sample: SampleRecord,
        *,
        target_symbol: str | None = None,
        feedback: str | None = None,
    ) -> dict[str, str]:
        before_key, before_code, after_code = self._select_code_pair(
            sample,
            target_symbol=target_symbol,
        )
        with self.observation(
            name="generate-harness",
            as_type="span",
            input_payload={
                "sample_id": sample.sample_id,
                "target": before_key,
                "feedback": feedback or "",
            },
            metadata={
                "agent": "harness",
                "backend": self.profile.backend,
                "model": self.profile.model,
            },
        ) as observation:
            model_output = self.invoke_model(
                user_prompt=self._build_user_prompt(
                    sample,
                    target=before_key,
                    before_code=before_code,
                    after_code=after_code,
                    feedback=feedback,
                )
            )
            if model_output:
                harnesses = self._normalize_model_output(model_output)
                observation.update(
                    output={"target": before_key, **harnesses},
                    metadata={"agent": "harness", "execution_mode": "llm"},
                )
                return harnesses

            harnesses = {
                "vulnerable_harness": self._build_local_harness(before_code),
                "fixed_harness": self._build_local_harness(after_code),
            }
            observation.update(
                output={"target": before_key, **harnesses},
                metadata={"agent": "harness", "execution_mode": "local-fallback"},
            )
            return harnesses

    def _select_code_pair(
        self,
        sample: SampleRecord,
        *,
        target_symbol: str | None,
    ) -> tuple[str, str, str]:
        before_map = self._code_map(sample.payload.get("before_code"))
        after_map = self._code_map(sample.payload.get("after_code"))
        if not before_map or not after_map:
            raise ValueError("Harness generation requires before_code and after_code maps.")

        if target_symbol:
            matching_keys = [
                key for key in before_map if key == target_symbol or key.endswith(f"::{target_symbol}")
            ]
            if not matching_keys:
                raise ValueError(f"Target symbol not found in before_code: {target_symbol}")
            key = matching_keys[0]
        elif len(before_map) == 1:
            key = next(iter(before_map))
        else:
            changed_files = sample.list_field("files_changed")
            key = next(
                (
                    candidate
                    for candidate in before_map
                    if any(candidate.startswith(path) for path in changed_files)
                ),
                next(iter(before_map)),
            )

        if key not in after_map:
            raise ValueError(f"Matching after_code entry not found for target: {key}")
        return key, before_map[key], after_map[key]

    def _code_map(self, value: Any) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {
            str(key): str(item)
            for key, item in value.items()
            if str(key).strip() and str(item).strip()
        }

    def _build_user_prompt(
        self,
        sample: SampleRecord,
        *,
        target: str,
        before_code: str,
        after_code: str,
        feedback: str | None,
    ) -> str:
        return "\n".join(
            [
                "Generate vulnerable/fixed minimal C11 harnesses for this FreeBSD CVE.",
                f"sample_id: {sample.sample_id}",
                f"cve: {', '.join(sample.list_field('cve')) or 'N/A'}",
                f"subsystem: {sample.text_field('subsystem', default='unknown')}",
                f"target: {target}",
                "",
                "advisory_text:",
                sample.text_field("advisory_text", default="N/A"),
                "",
                "fix_diff:",
                sample.text_field("diff", default="N/A"),
                "",
                "vulnerable_function:",
                "```c",
                before_code,
                "```",
                "",
                "fixed_function:",
                "```c",
                after_code,
                "```",
                "",
                "validation_feedback:",
                feedback or "none",
            ]
        )

    def _normalize_model_output(self, model_output: str) -> dict[str, str]:
        text = model_output.strip()
        json_candidates = [text]
        json_candidates.extend(
            match.group("body").strip()
            for match in self._FENCED_BLOCK.finditer(text)
            if match.group("language").strip().lower() in {"json", ""}
        )
        for candidate in json_candidates:
            try:
                payload = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            vulnerable = payload.get("vulnerable_harness") or payload.get("vulnerable")
            fixed = payload.get("fixed_harness") or payload.get("fixed")
            if isinstance(vulnerable, str) and isinstance(fixed, str):
                return {
                    "vulnerable_harness": self._ensure_trailing_newline(vulnerable),
                    "fixed_harness": self._ensure_trailing_newline(fixed),
                }
        raise ValueError(
            "HarnessAgent model output must be JSON with vulnerable_harness and fixed_harness."
        )

    def _build_local_harness(self, function_code: str) -> str:
        stripped = self._strip_leading_comment(function_code.strip())
        prelude = self._infer_prelude(stripped)
        return self._ensure_trailing_newline(prelude + "\n\n" + stripped)

    def _strip_leading_comment(self, code: str) -> str:
        text = code.lstrip()
        while text.startswith("/*"):
            end = text.find("*/")
            if end < 0:
                return code
            text = text[end + 2 :].lstrip()
        return text

    def _infer_prelude(self, code: str) -> str:
        lines = [
            "#include <stddef.h>",
            "#include <assert.h>",
            "",
            "#ifndef PRIVATE",
            "#define PRIVATE static",
            "#endif",
            "",
            "typedef int int32;",
            "typedef unsigned int u_int;",
            "typedef unsigned char u_char;",
            "typedef unsigned char uint8_t;",
            "typedef unsigned int uint32_t;",
        ]

        if "struct option_data" in code and "struct option_data {" not in code:
            lines.extend(
                [
                    "",
                    "struct option_data {",
                    "    size_t len;",
                    "    unsigned char *data;",
                    "};",
                ]
            )
        if "warning(" in code:
            lines.extend(
                [
                    "",
                    "static volatile int freevrg_warning_sink;",
                    "",
                    "static void warning(const char *message)",
                    "{",
                    "    freevrg_warning_sink += message != 0;",
                    "}",
                ]
            )
        if "pktbuf" in code:
            lines.extend(
                [
                    "",
                    "static unsigned char pktbuf[2048];",
                ]
            )
        if "struct bootp" in code and "struct bootp {" not in code:
            lines.extend(
                [
                    "",
                    "struct bootp {",
                    "    unsigned char bp_htype;",
                    "    char bp_file[128];",
                    "};",
                ]
            )
        if "struct host" in code and "struct host {" not in code:
            lines.extend(["", "struct host { int freevrg_stub; };"])
        if "hwinfocnt" in code:
            lines.extend(["", "static unsigned int hwinfocnt = 4;"])
        if "hwlookuptab" in code:
            lines.extend(["", "static int hwlookuptab[8];"])
        if "MD5Update(" in code:
            lines.extend(
                [
                    "",
                    "static volatile int freevrg_md5_sink;",
                    "",
                    "static void MD5Update(void *ctx, const void *data, int len)",
                    "{",
                    "    freevrg_md5_sink += (ctx != 0) + (data != 0) + len;",
                    "}",
                ]
            )
        if "memcmp(" in code:
            lines.extend(
                [
                    "",
                    "static int memcmp(const void *left, const void *right, size_t n)",
                    "{",
                    "    return (left != right) + (int)n;",
                    "}",
                ]
            )
        if "strlen(" in code:
            lines.extend(
                [
                    "",
                    "static size_t strlen(const char *value)",
                    "{",
                    "    size_t n = 0;",
                    "    while (value[n] != 0) {",
                    "        n++;",
                    "    }",
                    "    return n;",
                    "}",
                ]
            )
        return "\n".join(dict.fromkeys(lines))

    def _ensure_trailing_newline(self, text: str) -> str:
        return text.rstrip() + "\n"
