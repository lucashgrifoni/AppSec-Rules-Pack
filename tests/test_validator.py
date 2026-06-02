"""Unit tests for AppSec rules pack validation."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.validator import (
    validate_rules_file,
    validate_rules_files,
    validate_rules_payload,
)

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
PASS_FIXTURE_PATH = Path("tests/fixtures/pass/minimal-valid.yaml")
FAIL_FIXTURE_PATH = Path("tests/fixtures/fail/missing-required-field.yaml")
PASS_FIXTURES_DIR = Path("tests/fixtures/pass")
FAIL_FIXTURES_DIR = Path("tests/fixtures/fail")
CROSS_FILE_DUP_DIR = Path("tests/fixtures/cross-file-dup")
WARN_FIXTURE_PATH = Path("tests/fixtures/warn/exception-window-warning.yaml")
EXCEPTION_WINDOW_WARNING = (
    "exception window is 120 days; default review limit is 90 days"
)
NEGATIVE_FIXTURE_CASES = (
    (
        Path("tests/fixtures/fail/additional-property.yaml"),
        ("rules", 0),
        "unexpected field 'unexpected_field' is not allowed",
    ),
    (
        Path("tests/fixtures/fail/duplicate-id.yaml"),
        ("rules", 1, "id"),
        "duplicate rule id 'APPSEC-DUP-001'; first seen at rules.0",
    ),
    (
        Path("tests/fixtures/fail/invalid-enum.yaml"),
        ("rules", 0, "severity"),
        "value must be one of: critical, high, medium, low",
    ),
    (
        Path("tests/fixtures/fail/invalid-type.yaml"),
        ("rules", 0, "exceptions", "max_days"),
        "invalid type; expected integer",
    ),
    (
        FAIL_FIXTURE_PATH,
        ("rules", 0),
        "missing required field 'title'",
    ),
)

runner = CliRunner()


def test_baseline_rules_pack_is_valid() -> None:
    result = validate_rules_file(BASELINE_PATH)

    assert result.ok
    assert result.rule_count == 19
    assert result.warning_count == 0


def test_pass_fixture_is_valid() -> None:
    result = validate_rules_file(PASS_FIXTURE_PATH)

    assert result.ok
    assert result.rule_count == 1
    assert result.warning_count == 0


def test_fail_fixture_reports_missing_required_field() -> None:
    result = validate_rules_file(FAIL_FIXTURE_PATH)

    assert not result.ok
    assert result.rule_count == 1
    assert any(
        issue.path == ("rules", 0) and issue.message == "missing required field 'title'"
        for issue in result.issues
    )


@pytest.mark.parametrize(("fixture_path", "issue_path", "message"), NEGATIVE_FIXTURE_CASES)
def test_negative_fixtures_report_expected_errors(
    fixture_path: Path,
    issue_path: tuple[str | int, ...],
    message: str,
) -> None:
    result = validate_rules_file(fixture_path)

    assert not result.ok
    assert any(issue.path == issue_path and issue.message == message for issue in result.issues)


def test_duplicate_rule_ids_are_rejected() -> None:
    payload = load_yaml_file(BASELINE_PATH)
    duplicate_payload = deepcopy(payload)
    duplicate_payload["rules"][1]["id"] = duplicate_payload["rules"][0]["id"]

    result = validate_rules_payload(duplicate_payload)

    assert not result.ok
    assert any("duplicate rule id" in issue.message for issue in result.issues)


def test_exception_window_emits_warning() -> None:
    result = validate_rules_file(WARN_FIXTURE_PATH)

    assert result.ok
    assert result.warning_count == 1
    assert any(
        issue.path == ("rules", 0, "exceptions", "max_days")
        and issue.message == EXCEPTION_WINDOW_WARNING
        for issue in result.issues
    )


def test_cross_file_duplicate_rule_ids_are_rejected() -> None:
    results = dict(validate_rules_files(tuple(CROSS_FILE_DUP_DIR.glob("*.yaml"))))

    first_result = results[CROSS_FILE_DUP_DIR / "first-pack.yaml"]
    second_result = results[CROSS_FILE_DUP_DIR / "second-pack.yaml"]

    assert first_result.ok
    assert not second_result.ok
    assert any(
        issue.path == ("rules", 0, "id")
        and "duplicate rule id 'APPSEC-CROSS-001'" in issue.message
        and "first seen in first-pack.yaml at rules.0" in issue.message
        for issue in second_result.issues
    )


def test_sensitive_values_are_rejected() -> None:
    payload = load_yaml_file(BASELINE_PATH)
    sensitive_payload = deepcopy(payload)
    sensitive_payload["rules"][0]["description"] = "token=aaaaaaaaaaaaaaaaaaaaaaaa"

    result = validate_rules_payload(sensitive_payload)

    assert not result.ok
    assert any("possible sensitive value" in issue.message for issue in result.issues)


def test_cli_validate_accepts_single_file() -> None:
    result = runner.invoke(app, ["validate", str(PASS_FIXTURE_PATH)])

    assert result.exit_code == 0
    assert "Validation passed: 1 file, 1 rules, 0 errors, 0 warnings." in result.output


def test_cli_validate_single_file_reports_file_name_and_clear_error() -> None:
    result = runner.invoke(app, ["validate", str(FAIL_FIXTURE_PATH)])

    assert result.exit_code == 1
    assert "missing-required-field.yaml: ERROR rules.0: missing required field 'title'" in (
        result.output
    )


def test_cli_validate_accepts_directory() -> None:
    result = runner.invoke(app, ["validate", str(PASS_FIXTURES_DIR)])

    assert result.exit_code == 0
    assert "Validation passed: 1 file, 1 rules, 0 errors, 0 warnings." in result.output


def test_cli_validate_warn_fixture_passes_without_fail_on_warnings() -> None:
    result = runner.invoke(app, ["validate", str(WARN_FIXTURE_PATH)])

    assert result.exit_code == 0
    assert (
        "exception-window-warning.yaml: WARNING rules.0.exceptions.max_days: "
        f"{EXCEPTION_WINDOW_WARNING}"
    ) in result.output
    assert "Validation passed: 1 file, 1 rules, 0 errors, 1 warnings." in result.output


def test_cli_validate_warn_fixture_fails_with_fail_on_warnings() -> None:
    result = runner.invoke(
        app,
        ["validate", str(WARN_FIXTURE_PATH), "--fail-on-warnings"],
    )

    assert result.exit_code == 1
    assert "Validation failed: 1 file, 1 rules, 0 errors, 1 warnings." in result.output


def test_cli_validate_cross_file_directory_reports_duplicate_across_files() -> None:
    result = runner.invoke(app, ["validate", str(CROSS_FILE_DUP_DIR)])

    assert result.exit_code == 1
    assert (
        "second-pack.yaml: ERROR rules.0.id: duplicate rule id 'APPSEC-CROSS-001'; "
        "first seen in first-pack.yaml at rules.0"
    ) in result.output
    assert "Validation failed: 2 files, 2 rules, 1 errors, 0 warnings." in result.output


def test_cli_validate_directory_reports_file_and_clear_error() -> None:
    result = runner.invoke(app, ["validate", str(FAIL_FIXTURES_DIR)])

    assert result.exit_code == 1
    assert (
        "additional-property.yaml: ERROR rules.0: "
        "unexpected field 'unexpected_field' is not allowed"
    ) in result.output
    assert (
        "duplicate-id.yaml: ERROR rules.1.id: "
        "duplicate rule id 'APPSEC-DUP-001'; first seen at rules.0"
    ) in result.output
    assert (
        "invalid-enum.yaml: ERROR rules.0.severity: "
        "value must be one of: critical, high, medium, low"
    ) in result.output
    assert (
        "invalid-type.yaml: ERROR rules.0.exceptions.max_days: "
        "invalid type; expected integer"
    ) in result.output
    assert "missing-required-field.yaml: ERROR rules.0: missing required field 'title'" in (
        result.output
    )
    assert "Validation failed: 5 files, 6 rules, 5 errors, 0 warnings." in result.output
