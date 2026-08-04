from __future__ import annotations

from pathlib import Path

from agents.base import BaseAgent
from core.config import AppConfig
from core.models import SampleRecord, compact_text, slugify
from core.observability import Observability


class PatternAgent(BaseAgent):
    """Generate reusable vulnerability patterns from structured samples."""

    def __init__(self, config: AppConfig, observability: Observability | None = None) -> None:
        super().__init__(config, Path("prompts/pattern_agent.md"), "pattern", observability)

    def generate_pattern(self, sample: SampleRecord) -> str:
        with self.observation(
            name="generate-pattern",
            as_type="span",
            input_payload={"sample_id": sample.sample_id, "source_path": sample.source_path},
            metadata={
                "agent": "pattern",
                "backend": self.profile.backend,
                "model": self.profile.model,
            },
        ) as observation:
            model_output = self.invoke_model(user_prompt=self._build_user_prompt(sample))
            if model_output:
                output = model_output.strip() + "\n"
                observation.update(
                    output=output,
                    metadata={"agent": "pattern", "execution_mode": "llm"},
                )
                return output

            advisory_text = sample.text_field(
                "advisory_text",
                default="Historical vulnerability sample imported into the pipeline.",
            )
            first_sentence = advisory_text.split(". ")[0].strip()
            description = first_sentence if first_sentence else advisory_text

            files_changed = sample.list_field("files_changed")
            cve_values = sample.list_field("cve")
            cwe_values = sample.list_field("cwe")
            pattern_name = slugify(sample.pattern_name())

            source_candidates = self._infer_source_candidates(sample)
            sink_candidates = self._infer_sink_candidates(sample)
            sanitizer_candidates = self._infer_sanitizer_candidates(sample)

            lines = [
                f"# Pattern: {pattern_name}",
                "",
                "## Description",
                description,
                "",
                "## Structured Fields",
                "source:",
                *[f"  - {item}" for item in source_candidates],
                "",
                "sink:",
                *[f"  - {item}" for item in sink_candidates],
                "",
                "sanitizer:",
                *[f"  - {item}" for item in sanitizer_candidates],
                "",
                f"severity_hint: {'high' if cwe_values else 'medium'}",
                "",
                "## Historical Instances",
                f"- sample_id: {sample.sample_id}",
                f"- cve: {compact_text(cve_values)}",
                f"- subsystem: {sample.text_field('subsystem', default='unknown')}",
                f"- files_changed: {compact_text(files_changed)}",
                "",
                "## Agent Context",
                self.system_prompt,
                "",
                "## Normalized Sample Context",
                "```text",
                sample.to_prompt_context(),
                "```",
            ]
            output = "\n".join(lines).strip() + "\n"
            observation.update(
                output=output,
                metadata={"agent": "pattern", "execution_mode": "local-fallback"},
            )
            return output

    def _build_user_prompt(self, sample: SampleRecord) -> str:
        return "\n".join(
            [
                "Please generate a reusable vulnerability pattern document in Markdown.",
                "The output should include these sections exactly:",
                "- # Pattern: <slug-like-name>",
                "- ## Description",
                "- ## Structured Fields",
                "- severity_hint: <low|medium|high|critical>",
                "- ## Historical Instances",
                "",
                "Within ## Structured Fields, include:",
                "source:",
                "  - ...",
                "sink:",
                "  - ...",
                "sanitizer:",
                "  - ...",
                "",
                "Sample context:",
                sample.to_prompt_context(),
            ]
        )

    def _infer_source_candidates(self, sample: SampleRecord) -> list[str]:
        context = sample.to_prompt_context().lower()
        candidates = []
        if any(token in context for token in ("user", "guest", "network", "packet", "socket")):
            candidates.append("attacker-controlled input crossing a trust boundary")
        if "length" in context or "size" in context:
            candidates.append("length or size field derived from untrusted input")
        if not candidates:
            candidates.append("input extracted from vulnerable historical sample context")
        return candidates

    def _infer_sink_candidates(self, sample: SampleRecord) -> list[str]:
        context = sample.to_prompt_context().lower()
        candidates = []
        for token in ("copyin", "copyout", "memcpy", "strcpy", "malloc", "free", "array"):
            if token in context:
                candidates.append(token)
        if not candidates:
            candidates.append("dangerous operation mentioned in advisory or patch diff")
        return candidates

    def _infer_sanitizer_candidates(self, sample: SampleRecord) -> list[str]:
        context = sample.to_prompt_context().lower()
        candidates = []
        if any(token in context for token in ("check", "validate", "bounds", "limit", "range")):
            candidates.append("explicit bounds or semantic validation before the sink")
        if any(token in context for token in ("null", "nonnull")):
            candidates.append("nullability guard before dereference or parsing")
        if not candidates:
            candidates.append("fix-introduced guard inferred from patch context")
        return candidates
