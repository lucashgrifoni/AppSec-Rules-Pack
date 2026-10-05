"""Tests for per-rule compliant/violating examples and --require-examples."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.validator import validate_rules_file, validate_rules_payload

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
MINIMAL_VALID_PATH = Path("tests/fixtures/pass/minimal-valid.yaml")

runner = CliRunner()


def test_baseline_enabled_rules_define_complete_examples() -> None:
    payload = load_yaml_file(BASELINE_PATH)

    for rule in payload["rules"]:
        if rule.get("status") != "enabled":
            continue
        examples = rule.get("examples")
        assert examples, f"{rule['id']} is missing examples"
        for kind in ("compliant", "violating"):
            example = examples[kind]
            assert example["language"]
            assert example["snippet"].strip()
            assert len(example["explanation"]) >= 10


def test_baseline_passes_with_require_examples() -> None:
    result = validate_rules_file(BASELINE_PATH, require_examples=True)

    assert result.ok
    assert result.rule_count == 20
    assert result.warning_count == 0


def test_require_examples_warns_when_enabled_rule_lacks_examples() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    del payload["rules"][0]["examples"]

    default_result = validate_rules_payload(payload)
    assert default_result.warning_count == 0

    required_result = validate_rules_payload(payload, require_examples=True)
    assert required_result.ok  # missing examples is a warning, not an error
    assert required_result.warning_count == 1
    assert any(
        issue.level == "warning" and issue.path == ("rules", 0, "examples")
        for issue in required_result.issues
    )


def test_require_examples_ignores_disabled_rules() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    del payload["rules"][0]["examples"]
    payload["rules"][0]["status"] = "disabled"

    result = validate_rules_payload(payload, require_examples=True)

    assert result.warning_count == 0


def test_examples_missing_violating_is_rejected() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    del payload["rules"][0]["examples"]["violating"]

    result = validate_rules_payload(payload)

    assert not result.ok
    assert any("missing required field 'violating'" in issue.message for issue in result.issues)


def test_example_with_unknown_field_is_rejected() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    payload["rules"][0]["examples"]["compliant"]["severity"] = "high"

    result = validate_rules_payload(payload)

    assert not result.ok
    assert any(
        "unexpected field 'severity' is not allowed" in issue.message for issue in result.issues
    )


def test_example_with_invalid_language_is_rejected() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    payload["rules"][0]["examples"]["compliant"]["language"] = "cobol"

    result = validate_rules_payload(payload)

    assert not result.ok


def test_sensitive_value_inside_example_is_not_flagged() -> None:
    payload = deepcopy(load_yaml_file(BASELINE_PATH))
    payload["rules"][0]["examples"]["violating"]["snippet"] = "token=aaaaaaaaaaaaaaaaaaaaaaaa"

    result = validate_rules_payload(payload)

    assert result.ok
    assert not any("possible sensitive value" in issue.message for issue in result.issues)


def test_cli_require_examples_warns_on_rule_without_examples() -> None:
    result = runner.invoke(app, ["validate", str(MINIMAL_VALID_PATH), "--require-examples"])

    assert result.exit_code == 0
    assert (
        "WARNING rules.0.examples: enabled rule should include compliant and violating examples"
        in result.output
    )
    assert "0 errors, 1 warning" in result.output


def test_cli_require_examples_with_fail_on_warnings_exits_nonzero() -> None:
    result = runner.invoke(
        app,
        ["validate", str(MINIMAL_VALID_PATH), "--require-examples", "--fail-on-warnings"],
    )

    assert result.exit_code == 1
    assert "Validation failed: 1 file, 1 rule, 0 errors, 1 warning." in result.output
