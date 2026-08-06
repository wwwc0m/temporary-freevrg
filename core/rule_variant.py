from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


ScopeLevel = Literal["exact", "component", "freebsd", "upstream"]
SemanticLevel = Literal["syntactic", "structural", "dataflow", "semantic"]


@dataclass(frozen=True, slots=True)
class RuleVariant:
    scope_level: ScopeLevel
    semantic_level: SemanticLevel

    @property
    def slug(self) -> str:
        return f"{self.scope_level}-{self.semantic_level}"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def prompt_context(self) -> str:
        return "\n".join(
            [
                f"target_scope: {self.scope_level}",
                f"semantic_strength: {self.semantic_level}",
                f"scope_policy: {SCOPE_POLICIES[self.scope_level]}",
                f"semantic_policy: {SEMANTIC_POLICIES[self.semantic_level]}",
            ]
        )


DEFAULT_RULE_VARIANTS: tuple[RuleVariant, ...] = (
    RuleVariant("exact", "syntactic"),
    RuleVariant("component", "dataflow"),
    RuleVariant("freebsd", "semantic"),
)


SCOPE_POLICIES: dict[ScopeLevel, str] = {
    "exact": (
        "Constrain to historical file/function/API evidence. Use for regression and harness "
        "validation, not broad discovery."
    ),
    "component": (
        "Constrain to the same FreeBSD component or path family, but avoid binding solely to "
        "one historical function name."
    ),
    "freebsd": (
        "Scan across FreeBSD src. Avoid component path requirements; rely on source, sink, and "
        "guard semantics."
    ),
    "upstream": (
        "Target upstream component repositories. Avoid FreeBSD-specific paths, wrappers, typedefs, "
        "and private macros unless the pattern explicitly comes from that upstream API."
    ),
}


SEMANTIC_POLICIES: dict[SemanticLevel, str] = {
    "syntactic": (
        "Use direct AST/API matching. Prefer precision and explainable anchors over recall."
    ),
    "structural": (
        "Match structural relationships such as enclosing function, variable identity, field "
        "identity, and nearby guard placement."
    ),
    "dataflow": (
        "Model value propagation from source to sink and model sanitizers/barriers. Use dataflow "
        "only when AST identity is insufficient."
    ),
    "semantic": (
        "Describe the vulnerability mechanism abstractly: attacker-controlled value, dangerous "
        "operation, and missing semantic guard. Minimize names and paths unless required."
    ),
}


def parse_rule_variant(value: str) -> RuleVariant:
    normalized = value.strip().lower().replace("_", "-")
    if ":" in normalized:
        scope, semantic = normalized.split(":", 1)
    elif "/" in normalized:
        scope, semantic = normalized.split("/", 1)
    elif "-" in normalized:
        parts = normalized.split("-")
        scope, semantic = parts[0], "-".join(parts[1:])
    else:
        raise ValueError("rule variant must be '<scope>:<semantic>'")

    if scope not in SCOPE_POLICIES:
        raise ValueError(f"unsupported rule scope: {scope}")
    if semantic not in SEMANTIC_POLICIES:
        raise ValueError(f"unsupported rule semantic level: {semantic}")
    return RuleVariant(scope, semantic)  # type: ignore[arg-type]
