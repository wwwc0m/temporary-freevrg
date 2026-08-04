from __future__ import annotations

from contextlib import contextmanager
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.harness_agent import HarnessAgent
from agents.rule_agent import RuleAgent
from core.config import AppConfig, load_config
from core.orchestrator import Orchestrator
from core.models import SampleRecord, ValidationResult
from core.validator import Validator


def _valid_ast_query() -> str:
    return """import cpp

/**
 * @name Test AST query
 * @kind problem
 * @id freevrg/test-ast
 */
from Function function
select function, "Test AST result."
"""


def _valid_modular_query() -> str:
    return """import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import FreeVRGTestFlow::PathGraph

/**
 * @name Test modular dataflow query
 * @kind path-problem
 * @id freevrg/test-modular-dataflow
 */
module FreeVRGTestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof StringLiteral }
  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof VariableAccess }
}

module FreeVRGTestFlow = TaintTracking::Global<FreeVRGTestConfig>;

from FreeVRGTestFlow::PathNode source, FreeVRGTestFlow::PathNode sink
where FreeVRGTestFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Test path."
"""


def _make_config(root: Path, **overrides: object) -> AppConfig:
    values = {
        "langfuse_enabled": False,
        "langfuse_public_key": "",
        "langfuse_secret_key": "",
        "langfuse_base_url": "https://cloud.langfuse.com",
        "langfuse_timeout_seconds": 5,
        "llm_backend": "mock",
        "llm_api_key": "",
        "llm_base_url": "",
        "llm_timeout_seconds": 60,
        "pattern_llm_backend": "mock",
        "pattern_llm_api_key": "",
        "pattern_llm_base_url": "",
        "pattern_llm_timeout_seconds": 60,
        "rule_llm_backend": "mock",
        "rule_llm_api_key": "",
        "rule_llm_base_url": "",
        "rule_llm_timeout_seconds": 60,
        "pattern_model": "test-pattern",
        "rule_model": "test-rule",
        "pattern_temperature": 0.0,
        "rule_temperature": 0.0,
        "max_repair_rounds": 1,
        "codeql_path": "missing-codeql-executable",
        "samples_dir": root / "samples",
        "patterns_dir": root / "patterns",
        "rules_dir": root / "rules",
        "results_dir": root / "results",
    }
    values.update(overrides)
    return AppConfig(**values)


def _write_sample(root: Path, sample_id: str) -> Path:
    sample_path = root / "sample.json"
    sample_path.write_text(
        json.dumps(
            {
                "id": sample_id,
                "cve": ["CVE-2020-7461"],
                "subsystem": "net",
                "advisory_text": "Observation ordering test sample.",
            }
        ),
        encoding="utf-8",
    )
    return sample_path


def _write_sarif(path: Path, result_count: int) -> None:
    results = []
    for index in range(result_count):
        results.append(
            {
                "ruleId": "freevrg/test",
                "message": {"text": "Test result."},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "harness.c"},
                            "region": {"startLine": 28 + index},
                        }
                    }
                ],
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": results}]}),
        encoding="utf-8",
    )


class _RecordingObservation:
    def update(self, **_: object) -> None:
        return None


class _RecordingObservability:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    @contextmanager
    def observation(self, *, name: str, **_: object):
        self.events.append(f"enter:{name}")
        try:
            yield _RecordingObservation()
        finally:
            self.events.append(f"exit:{name}")

    def flush(self) -> None:
        self.events.append("flush")


class _FailingGraph:
    def invoke(self, _: object) -> None:
        raise RuntimeError("graph failed")


class PipelineTests(unittest.TestCase):
    def test_orchestrator_generates_pattern_rule_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-TEST",
                        "cve": ["CVE-2020-7461"],
                        "cwe": ["CWE-125"],
                        "subsystem": "net",
                        "files_changed": ["sys/net/foo.c"],
                        "advisory_text": "Network packet length is used without minimum validation.",
                        "diff": "if (pkt_len < 4) return EINVAL;",
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="missing-codeql-executable",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )

            outputs = Orchestrator(config).run_for_sample(sample_path)

            pattern_path = Path(outputs["pattern"])
            rule_path = Path(outputs["rule"])
            result_path = Path(outputs["result"])

            self.assertTrue(pattern_path.exists())
            self.assertTrue(rule_path.exists())
            self.assertTrue(result_path.exists())
            self.assertIn("# Pattern:", pattern_path.read_text(encoding="utf-8"))
            self.assertIn("@id freevrg/", rule_path.read_text(encoding="utf-8"))

            result_data = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertIsNone(result_data["compile_ok"])
            self.assertTrue(result_data["structure_ok"])
            self.assertEqual(result_data["validation_mode"], "static-only")
            self.assertEqual(result_data["failure_type"], "tool-unavailable")

    def test_validator_static_fallback_marks_missing_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "broken.ql"
            rule_path.write_text("import cpp\nfrom Function f\nselect f\n", encoding="utf-8")
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="codeql",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )

            result = Validator(config).validate_rule(rule_path)

            self.assertIsNone(result.compile_ok)
            self.assertFalse(result.structure_ok)
            self.assertEqual(result.failure_type, "structure-error")
            self.assertTrue(result.should_repair)

    def test_load_config_reads_llm_backend_from_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "LLM_BACKEND=openai-compatible",
                        "LANGFUSE_ENABLED=true",
                        "LANGFUSE_PUBLIC_KEY=pk-lf-test",
                        "LANGFUSE_SECRET_KEY=sk-lf-test",
                        "LANGFUSE_BASE_URL=\"https://langfuse.example.com\"",
                        "LANGFUSE_TIMEOUT_SECONDS=7",
                        "LLM_API_KEY=test-key",
                        "LLM_BASE_URL=https://example.invalid/v1",
                        "LLM_TIMEOUT_SECONDS=42",
                        "PATTERN_LLM_BASE_URL=https://pattern.invalid/v1",
                        "RULE_LLM_API_KEY=rule-key",
                        "RULE_LLM_TIMEOUT_SECONDS=33",
                        f"CODEQL_ADDITIONAL_PACKS={root / 'packs-a'}{os.pathsep}{root / 'packs-b'}",
                        f"VALIDATION_DATABASES_DIR={root / 'validation-databases'}",
                        "VALIDATION_EXPECTED_VULNERABLE_RESULTS=2",
                        "VALIDATION_EXPECTED_FIXED_RESULTS=1",
                        "PATTERN_MODEL=model-a",
                        "RULE_MODEL=model-b",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_config(str(env_path))

            self.assertTrue(config.langfuse_enabled)
            self.assertEqual(config.langfuse_public_key, "pk-lf-test")
            self.assertEqual(config.langfuse_secret_key, "sk-lf-test")
            self.assertEqual(config.langfuse_base_url, "https://langfuse.example.com")
            self.assertEqual(config.langfuse_timeout_seconds, 7)
            self.assertEqual(config.llm_backend, "openai-compatible")
            self.assertEqual(config.llm_api_key, "test-key")
            self.assertEqual(config.llm_base_url, "https://example.invalid/v1")
            self.assertEqual(config.llm_timeout_seconds, 42)
            self.assertEqual(config.pattern_llm_base_url, "https://pattern.invalid/v1")
            self.assertEqual(config.pattern_llm_api_key, "test-key")
            self.assertEqual(config.rule_llm_api_key, "rule-key")
            self.assertEqual(config.rule_llm_timeout_seconds, 33)
            self.assertEqual(
                config.codeql_additional_packs,
                (root / "packs-a", root / "packs-b"),
            )
            self.assertEqual(
                config.validation_databases_dir,
                root / "validation-databases",
            )
            self.assertEqual(config.validation_expected_vulnerable_results, 2)
            self.assertEqual(config.validation_expected_fixed_results, 1)
            self.assertEqual(config.pattern_model, "model-a")
            self.assertEqual(config.rule_model, "model-b")

    def test_load_config_applies_proxy_environment_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            env_path = root / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "HTTP_PROXY=http://127.0.0.1:7897",
                        "HTTPS_PROXY=http://127.0.0.1:7897",
                        "ALL_PROXY=http://127.0.0.1:7897",
                        "NO_PROXY=127.0.0.1,localhost",
                    ]
                ),
                encoding="utf-8",
            )

            original = {key: os.environ.get(key) for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}
            try:
                for key in original:
                    os.environ.pop(key, None)

                load_config(str(env_path))

                self.assertEqual(os.environ.get("HTTP_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("HTTPS_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("ALL_PROXY"), "http://127.0.0.1:7897")
                self.assertEqual(os.environ.get("NO_PROXY"), "127.0.0.1,localhost")
            finally:
                for key, value in original.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_load_config_treats_blank_agent_overrides_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_path = Path(tmp_dir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "LLM_BACKEND=openai-compatible",
                        "LLM_API_KEY=shared-key",
                        "LLM_BASE_URL=https://shared.invalid/v1",
                        "LLM_TIMEOUT_SECONDS=60",
                        "PATTERN_LLM_BACKEND=",
                        "PATTERN_LLM_API_KEY=",
                        "PATTERN_LLM_BASE_URL=   ",
                        "PATTERN_LLM_TIMEOUT_SECONDS=",
                        "RULE_LLM_BACKEND=",
                        "RULE_LLM_API_KEY=",
                        "RULE_LLM_BASE_URL=",
                        "RULE_LLM_TIMEOUT_SECONDS=   ",
                    ]
                ),
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"LLM_BACKEND": " "}, clear=True):
                config = load_config(str(env_path))

            self.assertEqual(config.pattern_llm_backend, "openai-compatible")
            self.assertEqual(config.pattern_llm_api_key, "shared-key")
            self.assertEqual(config.pattern_llm_base_url, "https://shared.invalid/v1")
            self.assertEqual(config.pattern_llm_timeout_seconds, 60)
            self.assertEqual(config.rule_llm_backend, "openai-compatible")
            self.assertEqual(config.rule_llm_api_key, "shared-key")
            self.assertEqual(config.rule_llm_base_url, "https://shared.invalid/v1")
            self.assertEqual(config.rule_llm_timeout_seconds, 60)

    def test_load_config_defaults_llm_timeouts_to_100_seconds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_path = Path(tmp_dir) / ".env"
            env_path.write_text("", encoding="utf-8")

            with patch.dict(os.environ, {}, clear=True):
                config = load_config(str(env_path))

            self.assertEqual(config.llm_timeout_seconds, 100)
            self.assertEqual(config.pattern_llm_timeout_seconds, 100)
            self.assertEqual(config.rule_llm_timeout_seconds, 100)

    def test_rule_agent_normalizes_fenced_model_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            agent = RuleAgent(_make_config(root))
            fenced_output = """Here is the requested query.
```ql
import cpp

/**
 * @name Connectivity smoke query
 * @kind problem
 * @id freevrg/connectivity-smoke
 */
from Function function
select function, "Connectivity smoke result."
```
"""

            with patch.object(agent, "invoke_model", return_value=fenced_output):
                output = agent.generate_rule("# Pattern: connectivity-smoke")

            self.assertTrue(output.startswith("import cpp\n"))
            self.assertNotIn("```", output)
            self.assertNotIn("Here is the requested query", output)
            self.assertTrue(output.endswith("\n"))

    def test_rule_agent_rejects_incomplete_model_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            agent = RuleAgent(_make_config(root))

            with (
                patch.object(
                    agent,
                    "invoke_model",
                    return_value="```ql\nimport cpp\nselect 1\n```",
                ),
                self.assertRaisesRegex(ValueError, "@name metadata"),
            ):
                agent.generate_rule("# Pattern: incomplete-smoke")

    def test_rule_agent_accepts_modular_dataflow_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            agent = RuleAgent(_make_config(Path(tmp_dir)))

            with patch.object(agent, "invoke_model", return_value=_valid_modular_query()):
                output = agent.generate_rule("# Pattern: modular-smoke")

            self.assertIn("new.TaintTracking", output)
            self.assertIn("import FreeVRGTestFlow::PathGraph", output)

    def test_harness_agent_generates_local_pair_from_sample_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-HARNESS",
                        "cve": ["CVE-2020-7461"],
                        "subsystem": "dhclient",
                        "diff": "+if (pointed_len < 0) return (-1);",
                        "before_code": {
                            "sbin/dhclient/options.c::find_search_domain_name_len": (
                                "int find_search_domain_name_len(struct option_data *option, "
                                "size_t *offset)\n"
                                "{\n"
                                "    int pointed_len;\n"
                                "    pointed_len = find_search_domain_name_len(option, offset);\n"
                                "    return pointed_len + 1;\n"
                                "}\n"
                            )
                        },
                        "after_code": {
                            "sbin/dhclient/options.c::find_search_domain_name_len": (
                                "int find_search_domain_name_len(struct option_data *option, "
                                "size_t *offset)\n"
                                "{\n"
                                "    int pointed_len;\n"
                                "    pointed_len = find_search_domain_name_len(option, offset);\n"
                                "    if (pointed_len < 0) {\n"
                                "        return -1;\n"
                                "    }\n"
                                "    return pointed_len + 1;\n"
                                "}\n"
                            )
                        },
                    }
                ),
                encoding="utf-8",
            )
            sample = SampleRecord.from_path(sample_path)
            agent = HarnessAgent(_make_config(root))

            harnesses = agent.generate_harness_pair(sample)

            self.assertIn("struct option_data", harnesses["vulnerable_harness"])
            self.assertIn("pointed_len + 1", harnesses["vulnerable_harness"])
            self.assertIn("if (pointed_len < 0)", harnesses["fixed_harness"])
            self.assertTrue(harnesses["vulnerable_harness"].endswith("\n"))
            self.assertTrue(harnesses["fixed_harness"].endswith("\n"))

    def test_harness_agent_accepts_json_model_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-HARNESS-LLM",
                        "cve": ["CVE-2020-7461"],
                        "before_code": {"file.c::target": "int target(void) { return 1; }"},
                        "after_code": {"file.c::target": "int target(void) { return 0; }"},
                    }
                ),
                encoding="utf-8",
            )
            agent = HarnessAgent(_make_config(root))
            model_output = json.dumps(
                {
                    "vulnerable_harness": "#include <stddef.h>\nint target(void) { return 1; }",
                    "fixed_harness": "#include <stddef.h>\nint target(void) { return 0; }",
                }
            )

            with patch.object(agent, "invoke_model", return_value=f"```json\n{model_output}\n```"):
                harnesses = agent.generate_harness_pair(SampleRecord.from_path(sample_path))

            self.assertIn("return 1", harnesses["vulnerable_harness"])
            self.assertIn("return 0", harnesses["fixed_harness"])

    def test_rule_agent_rejects_incompatible_codeql_profiles(self) -> None:
        invalid_outputs = {
            "legacy TaintTracking import": _valid_modular_query().replace(
                ".dataflow.new.TaintTracking",
                ".dataflow.TaintTracking",
            ),
            "DataFlow::PathGraph": _valid_modular_query().replace(
                "FreeVRGTestFlow::PathGraph",
                "DataFlow::PathGraph",
            ),
            "PathGraph import must match": _valid_modular_query().replace(
                "import FreeVRGTestFlow::PathGraph",
                "import OtherFlow::PathGraph",
            ),
            "freevrg/ prefix": _valid_ast_query().replace(
                "@id freevrg/test-ast",
                "@id cpp/test-ast",
            ),
            "controlflow.Guards": _valid_ast_query().replace(
                "import cpp",
                "import cpp\nimport semmle.code.cpp.controlflow.Guards",
            ),
            "RelationalOperation.getOperator": _valid_ast_query().replace(
                "from Function function",
                "predicate invalid(ComparisonOperation comp) {\n"
                "  comp.getType() instanceof GeOp\n"
                "}\n\nfrom Function function",
            ),
            "does not call controls": _valid_ast_query().replace(
                "from Function function",
                "predicate invalid(ComparisonOperation comp, BasicBlock block) {\n"
                "  comp.controls(block, true)\n"
                "}\n\nfrom Function function",
            ),
            "integral type checks must normalize typedefs": _valid_ast_query().replace(
                "from Function function",
                "predicate isIntegral(Variable value) {\n"
                "  value.getType() instanceof IntegralType\n"
                "}\n\nfrom Function function",
            ),
            "guarded AST queries must use VariableAccess.getTarget": _valid_ast_query().replace(
                "from Function function",
                "predicate hasRelevantGuard(Expr value, Element useSite) {\n"
                "  exists(RelationalOperation comparison | comparison = comparison)\n"
                "}\n\nfrom ArrayExpr function, RelationalOperation comparison",
            ),
            "security.FlowSources must not be mixed": _valid_modular_query().replace(
                "import cpp",
                "import cpp\nimport semmle.code.cpp.security.FlowSources",
            ),
            "Assertion requires the commons.Assertions import": _valid_ast_query().replace(
                "from Function function",
                "predicate isAsserted(Assertion assertion) { assertion = assertion }\n\n"
                "from Function function",
            ),
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            agent = RuleAgent(_make_config(Path(tmp_dir)))
            for expected_error, model_output in invalid_outputs.items():
                with self.subTest(expected_error=expected_error):
                    with (
                        patch.object(agent, "invoke_model", return_value=model_output),
                        self.assertRaisesRegex(ValueError, expected_error),
                    ):
                        agent.generate_rule("# Pattern: incompatible-smoke")

    def test_validator_does_not_treat_codeql_directory_as_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            codeql_dir = root / "codeql"
            codeql_dir.mkdir()
            rule_path = root / "valid.ql"
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")
            config = _make_config(root, codeql_path=str(codeql_dir))

            with (
                patch("core.validator.shutil.which", return_value=None) as which_mock,
                patch("core.validator.subprocess.run") as run_mock,
            ):
                result = Validator(config).validate_rule(rule_path)

            self.assertIsNone(result.compile_ok)
            self.assertTrue(result.structure_ok)
            self.assertEqual(result.validation_mode, "static-only")
            self.assertEqual(result.failure_type, "tool-unavailable")
            self.assertFalse(result.should_repair)
            which_mock.assert_called_once_with(str(codeql_dir))
            run_mock.assert_not_called()

    def test_validator_keeps_unresolved_module_as_compile_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "invalid-module.ql"
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")
            pack_a = root / "packs-a"
            pack_b = root / "packs-b"
            config = _make_config(
                root,
                codeql_additional_packs=(pack_a, pack_b),
            )
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="ERROR: could not resolve module DataFlow::PathGraph",
            )

            with (
                patch.object(Validator, "_resolve_codeql_executable", return_value="codeql"),
                patch("core.validator.subprocess.run", return_value=completed) as run_mock,
            ):
                result = Validator(config).validate_rule(rule_path)

            self.assertTrue(result.structure_ok)
            self.assertFalse(result.compile_ok)
            self.assertEqual(result.validation_mode, "codeql-compile")
            self.assertEqual(result.failure_type, "compile-error")
            self.assertTrue(result.should_repair)
            command = run_mock.call_args.args[0]
            self.assertIn("--check-only", command)
            self.assertEqual(
                command[command.index("--additional-packs") + 1],
                os.pathsep.join((str(pack_a), str(pack_b))),
            )

    def test_validator_classifies_pack_resolution_as_environment_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "missing-pack.ql"
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="ERROR: Referenced pack 'codeql/cpp-all' was not found locally",
            )

            with (
                patch.object(Validator, "_resolve_codeql_executable", return_value="codeql"),
                patch("core.validator.subprocess.run", return_value=completed),
            ):
                result = Validator(_make_config(root)).validate_rule(rule_path)

            self.assertTrue(result.structure_ok)
            self.assertIsNone(result.compile_ok)
            self.assertEqual(result.failure_type, "tool-environment")
            self.assertFalse(result.should_repair)

    def test_validator_classifies_process_launch_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "launch-failure.ql"
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")

            with (
                patch.object(Validator, "_resolve_codeql_executable", return_value="codeql"),
                patch("core.validator.subprocess.run", side_effect=OSError("access denied")),
            ):
                result = Validator(_make_config(root)).validate_rule(rule_path)

            self.assertIsNone(result.compile_ok)
            self.assertEqual(result.failure_type, "tool-execution")
            self.assertFalse(result.should_repair)

    def test_validator_runs_compile_and_vulnerable_fixed_quality_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rules_dir = root / "rules"
            rules_dir.mkdir()
            rule_path = rules_dir / "generated.ql"
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")
            sample_path = _write_sample(root, "FreeBSD-SA-MECHANISM")
            sample = SampleRecord.from_path(sample_path)
            database_root = root / "databases"
            for variant in ("vulnerable", "fixed"):
                database = database_root / f"CVE-2020-7461-{variant}"
                database.mkdir(parents=True)
                (database / "codeql-database.yml").write_text("primaryLanguage: cpp\n")
            config = _make_config(
                root,
                codeql_additional_packs=(root / "packs",),
                validation_databases_dir=database_root,
            )
            commands: list[list[str]] = []

            def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                if command[1:3] == ["query", "compile"]:
                    return subprocess.CompletedProcess(command, 0, "", "")
                output = Path(
                    next(item.split("=", 1)[1] for item in command if item.startswith("--output="))
                )
                result_count = 1 if "-vulnerable" in command[3] else 0
                _write_sarif(output, result_count)
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                patch.object(Validator, "_resolve_codeql_executable", return_value="codeql"),
                patch("core.validator.subprocess.run", side_effect=fake_run),
            ):
                result = Validator(config).validate_rule(rule_path, sample=sample)

            self.assertTrue((rules_dir / "qlpack.yml").is_file())
            self.assertEqual(len(commands), 3)
            self.assertIn("--check-only", commands[0])
            self.assertTrue(all("--rerun" in command for command in commands[1:]))
            self.assertTrue(result.compile_ok)
            self.assertTrue(result.recall_ok)
            self.assertTrue(result.false_positive_ok)
            self.assertEqual(result.vulnerable_result_count, 1)
            self.assertEqual(result.fixed_result_count, 0)
            self.assertEqual(result.vulnerable_locations, ["harness.c:28"])
            self.assertEqual(result.fixed_locations, [])
            self.assertEqual(result.validation_mode, "codeql-mechanism")
            self.assertEqual(result.failure_type, "none")
            self.assertFalse(result.should_repair)

    def test_validator_quality_mismatch_requests_repair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rule_path = root / "rules" / "generated.ql"
            rule_path.parent.mkdir()
            rule_path.write_text(_valid_ast_query(), encoding="utf-8")
            sample = SampleRecord.from_path(_write_sample(root, "FreeBSD-SA-MISMATCH"))
            database_root = root / "databases"
            for variant in ("vulnerable", "fixed"):
                database = database_root / f"CVE-2020-7461-{variant}"
                database.mkdir(parents=True)
                (database / "codeql-database.yml").write_text("primaryLanguage: cpp\n")
            config = _make_config(root, validation_databases_dir=database_root)

            def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                if command[1:3] == ["query", "compile"]:
                    return subprocess.CompletedProcess(command, 0, "", "")
                output = Path(
                    next(item.split("=", 1)[1] for item in command if item.startswith("--output="))
                )
                result_count = 0 if "-vulnerable" in command[3] else 1
                _write_sarif(output, result_count)
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                patch.object(Validator, "_resolve_codeql_executable", return_value="codeql"),
                patch("core.validator.subprocess.run", side_effect=fake_run),
            ):
                result = Validator(config).validate_rule(rule_path, sample=sample)

            self.assertTrue(result.compile_ok)
            self.assertFalse(result.recall_ok)
            self.assertFalse(result.false_positive_ok)
            self.assertEqual(result.vulnerable_result_count, 0)
            self.assertEqual(result.fixed_result_count, 1)
            self.assertEqual(result.failure_type, "mechanism-error")
            self.assertTrue(result.should_repair)

    def test_orchestrator_closes_root_observation_before_flush(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = _write_sample(root, "FreeBSD-SA-OBSERVABILITY")
            orchestrator = Orchestrator(_make_config(root))
            events: list[str] = []
            orchestrator.observability = _RecordingObservability(events)

            outputs = orchestrator.run_for_sample(sample_path)

            self.assertTrue(Path(outputs["result"]).exists())
            self.assertEqual(events[-2:], ["exit:run-sample-pipeline", "flush"])

    def test_orchestrator_closes_root_observation_before_flush_on_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = _write_sample(root, "FreeBSD-SA-OBSERVABILITY-ERROR")
            orchestrator = Orchestrator(_make_config(root))
            orchestrator.graph = _FailingGraph()
            events: list[str] = []
            orchestrator.observability = _RecordingObservability(events)

            with self.assertRaisesRegex(RuntimeError, "graph failed"):
                orchestrator.run_for_sample(sample_path)

            self.assertEqual(
                events,
                ["enter:run-sample-pipeline", "exit:run-sample-pipeline", "flush"],
            )

    def test_orchestrator_repair_path_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_path = root / "sample.json"
            sample_path.write_text(
                json.dumps(
                    {
                        "id": "FreeBSD-SA-REPAIR",
                        "cve": ["CVE-2020-7461"],
                        "subsystem": "net",
                        "advisory_text": "Repair path coverage sample.",
                    }
                ),
                encoding="utf-8",
            )
            config = AppConfig(
                langfuse_enabled=False,
                langfuse_public_key="",
                langfuse_secret_key="",
                langfuse_base_url="https://cloud.langfuse.com",
                langfuse_timeout_seconds=5,
                llm_backend="mock",
                llm_api_key="",
                llm_base_url="",
                llm_timeout_seconds=60,
                pattern_llm_backend="mock",
                pattern_llm_api_key="",
                pattern_llm_base_url="",
                pattern_llm_timeout_seconds=60,
                rule_llm_backend="mock",
                rule_llm_api_key="",
                rule_llm_base_url="",
                rule_llm_timeout_seconds=60,
                pattern_model="test-pattern",
                rule_model="test-rule",
                pattern_temperature=0.0,
                rule_temperature=0.0,
                max_repair_rounds=1,
                codeql_path="codeql",
                samples_dir=root / "samples",
                patterns_dir=root / "patterns",
                rules_dir=root / "rules",
                results_dir=root / "results",
            )
            orchestrator = Orchestrator(config)
            calls = {"count": 0}

            def fake_validate_rule(
                rule_path: Path,
                *,
                sample: SampleRecord | None = None,
            ) -> ValidationResult:
                self.assertIsNotNone(sample)
                calls["count"] += 1
                if calls["count"] == 1:
                    return ValidationResult(
                        rule_name=rule_path.stem,
                        compile_ok=False,
                        recall_ok=None,
                        false_positive_ok=None,
                        validation_mode="codeql-compile",
                        should_repair=True,
                        notes=["first pass fails"],
                        failure_type="compile-error",
                    )
                return ValidationResult(
                    rule_name=rule_path.stem,
                    compile_ok=True,
                    recall_ok=None,
                    false_positive_ok=None,
                    validation_mode="codeql-compile",
                    should_repair=False,
                    notes=["second pass succeeds"],
                )

            orchestrator.validator.validate_rule = fake_validate_rule
            outputs = orchestrator.run_for_sample(sample_path)

            self.assertEqual(calls["count"], 2)
            self.assertTrue(Path(outputs["rule"]).exists())
            self.assertTrue(Path(outputs["result"]).exists())


if __name__ == "__main__":
    unittest.main()
