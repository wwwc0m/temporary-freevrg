from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class LLMProfile:
    backend: str
    api_key: str
    base_url: str
    timeout_seconds: int
    model: str
    temperature: float


@dataclass(slots=True)
class AppConfig:
    langfuse_enabled: bool
    langfuse_public_key: str
    langfuse_secret_key: str
    langfuse_base_url: str
    langfuse_timeout_seconds: int
    llm_backend: str
    llm_api_key: str
    llm_base_url: str
    llm_timeout_seconds: int
    pattern_llm_backend: str
    pattern_llm_api_key: str
    pattern_llm_base_url: str
    pattern_llm_timeout_seconds: int
    rule_llm_backend: str
    rule_llm_api_key: str
    rule_llm_base_url: str
    rule_llm_timeout_seconds: int
    pattern_model: str
    rule_model: str
    pattern_temperature: float
    rule_temperature: float
    max_repair_rounds: int
    codeql_path: str
    samples_dir: Path
    patterns_dir: Path
    rules_dir: Path
    results_dir: Path
    codeql_additional_packs: tuple[Path, ...] = ()
    validation_databases_dir: Path | None = None
    validation_expected_vulnerable_results: int = 1
    validation_expected_fixed_results: int = 0

    def profile_for(self, agent_name: str) -> LLMProfile:
        normalized = agent_name.strip().lower()
        if normalized in {"pattern", "multi-cve"}:
            prefix = "PATTERN"
            model = self.pattern_model
            temperature = self.pattern_temperature
        elif normalized == "rule":
            prefix = "RULE"
            model = self.rule_model
            temperature = self.rule_temperature
        elif normalized == "harness":
            prefix = "RULE"
            model = self.rule_model
            temperature = self.rule_temperature
        else:
            raise ValueError(f"Unsupported agent profile: {agent_name}")
        return LLMProfile(
            backend=getattr(self, f"{prefix.lower()}_llm_backend"),
            api_key=getattr(self, f"{prefix.lower()}_llm_api_key"),
            base_url=getattr(self, f"{prefix.lower()}_llm_base_url"),
            timeout_seconds=getattr(self, f"{prefix.lower()}_llm_timeout_seconds"),
            model=model,
            temperature=temperature,
        )


def read_dotenv(env_path: str = ".env") -> dict[str, str]:
    path = Path(env_path)
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        cleaned = value.strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
            cleaned = cleaned[1:-1]
        values[key.strip()] = cleaned
    return values


def apply_runtime_environment(env_values: dict[str, str]) -> None:
    passthrough_keys = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    )
    for key in passthrough_keys:
        value = env_values.get(key)
        if value and key not in os.environ:
            os.environ[key] = value


def load_config(env_path: str = ".env") -> AppConfig:
    env_values = read_dotenv(env_path)
    apply_runtime_environment(env_values)

    def get(name: str, default: str) -> str:
        environment_value = os.getenv(name)
        if environment_value is not None and environment_value.strip():
            return environment_value
        dotenv_value = env_values.get(name)
        if dotenv_value is not None and dotenv_value.strip():
            return dotenv_value
        return default

    def get_bool(name: str, default: bool) -> bool:
        raw_value = get(name, "true" if default else "false").strip().lower()
        return raw_value in {"1", "true", "yes", "on"}

    def get_paths(name: str) -> tuple[Path, ...]:
        raw_value = get(name, "")
        return tuple(
            Path(item.strip())
            for item in raw_value.split(os.pathsep)
            if item.strip()
        )

    def get_optional_path(name: str) -> Path | None:
        raw_value = get(name, "").strip()
        return Path(raw_value) if raw_value else None

    return AppConfig(
        langfuse_enabled=get_bool("LANGFUSE_ENABLED", True),
        langfuse_public_key=get("LANGFUSE_PUBLIC_KEY", ""),
        langfuse_secret_key=get("LANGFUSE_SECRET_KEY", ""),
        langfuse_base_url=get(
            "LANGFUSE_BASE_URL",
            get("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        ),
        langfuse_timeout_seconds=int(get("LANGFUSE_TIMEOUT_SECONDS", "5")),
        llm_backend=get("LLM_BACKEND", "mock"),
        llm_api_key=get("LLM_API_KEY", ""),
        llm_base_url=get("LLM_BASE_URL", ""),
        llm_timeout_seconds=int(get("LLM_TIMEOUT_SECONDS", "100")),
        pattern_llm_backend=get("PATTERN_LLM_BACKEND", get("LLM_BACKEND", "mock")),
        pattern_llm_api_key=get("PATTERN_LLM_API_KEY", get("LLM_API_KEY", "")),
        pattern_llm_base_url=get("PATTERN_LLM_BASE_URL", get("LLM_BASE_URL", "")),
        pattern_llm_timeout_seconds=int(
            get("PATTERN_LLM_TIMEOUT_SECONDS", get("LLM_TIMEOUT_SECONDS", "100"))
        ),
        rule_llm_backend=get("RULE_LLM_BACKEND", get("LLM_BACKEND", "mock")),
        rule_llm_api_key=get("RULE_LLM_API_KEY", get("LLM_API_KEY", "")),
        rule_llm_base_url=get("RULE_LLM_BASE_URL", get("LLM_BASE_URL", "")),
        rule_llm_timeout_seconds=int(
            get("RULE_LLM_TIMEOUT_SECONDS", get("LLM_TIMEOUT_SECONDS", "100"))
        ),
        pattern_model=get("PATTERN_MODEL", "gpt-4.1"),
        rule_model=get("RULE_MODEL", "gpt-4.1"),
        pattern_temperature=float(get("PATTERN_TEMPERATURE", "0.2")),
        rule_temperature=float(get("RULE_TEMPERATURE", "0.1")),
        max_repair_rounds=int(get("MAX_REPAIR_ROUNDS", "2")),
        codeql_path=get("CODEQL_PATH", "codeql"),
        samples_dir=Path(get("SAMPLES_DIR", "data/samples")),
        patterns_dir=Path(get("PATTERNS_DIR", "data/patterns")),
        rules_dir=Path(get("RULES_DIR", "data/rules")),
        results_dir=Path(get("RESULTS_DIR", "data/results")),
        codeql_additional_packs=get_paths("CODEQL_ADDITIONAL_PACKS"),
        validation_databases_dir=get_optional_path("VALIDATION_DATABASES_DIR"),
        validation_expected_vulnerable_results=int(
            get("VALIDATION_EXPECTED_VULNERABLE_RESULTS", "1")
        ),
        validation_expected_fixed_results=int(
            get("VALIDATION_EXPECTED_FIXED_RESULTS", "0")
        ),
    )


def ensure_directories(config: AppConfig) -> None:
    for directory in (
        config.samples_dir,
        config.patterns_dir,
        config.rules_dir,
        config.results_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
