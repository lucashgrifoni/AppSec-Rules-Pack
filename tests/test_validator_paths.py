"""Coverage-focused tests for validator error and edge-case paths."""

from __future__ import annotations

import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.validator import (
    validate_rules_file,
    validate_rules_payload,
)

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
WARN_FIXTURE_PATH = Path("tests/fixtures/warn/exception-window-warning.yaml")
runner = CliRunner()


def _baseline_payload() -> dict[str, Any]:
    return deepcopy(load_yaml_file(BASELINE_PATH))


def test_validate_rules_file_reports_unreadable_file(tmp_path: Path) -> None:
    result = validate_rules_file(tmp_path / "missing.yaml")

    assert not result.ok
    assert result.rule_count == 0
    assert any("could not read YAML file" in issue.message for issue in result.issues)


def test_validate_rules_file_reports_malformed_yaml(tmp_path: Path) -> None:
    target = tmp_path / "broken.yaml"
    target.write_text("pack: [unterminated\n", encoding="utf-8")

    result = validate_rules_file(target)

    assert not result.ok
    assert result.rule_count == 0
    assert any("could not parse YAML file" in issue.message for issue in result.issues)
    assert any("line" in issue.message for issue in result.issues)


def test_non_dict_payload_is_rejected_without_crash() -> None:
    result = validate_rules_payload(["not", "a", "mapping"])

    assert not result.ok
    assert result.rule_count == 0


def test_empty_payload_reports_missing_required_fields() -> None:
    result = validate_rules_payload({})

    assert not result.ok
    assert any("missing required field" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "AKIAIOSFODNN7EXAMPLE",
        "api_key: 'abcdefghijklmnop1234'",
    ],
)
def test_sensitive_value_patterns_are_detected(secret: str) -> None:
    payload = _baseline_payload()
    payload["rules"][0]["description"] = (
        f"Verify object authorization on the server side. {secret}"
    )

    result = validate_rules_payload(payload)

    assert not result.ok
    assert any("possible sensitive value" in issue.message for issue in result.issues)


def test_pattern_violation_message() -> None:
    payload = _baseline_payload()
    payload["pack"]["version"] = "1.0"

    result = validate_rules_payload(payload)

    assert any("does not match required pattern" in issue.message for issue in result.issues)


def test_min_length_violation_message() -> None:
    payload = _baseline_payload()
    payload["pack"]["owner"] = "a"

    result = validate_rules_payload(payload)

    assert any("value is too short" in issue.message for issue in result.issues)


def test_max_length_violation_message() -> None:
    payload = _baseline_payload()
    payload["pack"]["description"] = "x" * 300

    result = validate_rules_payload(payload)

    assert any("value is too long" in issue.message for issue in result.issues)


def test_min_items_violation_message() -> None:
    payload = _baseline_payload()
    payload["rules"] = []

    result = validate_rules_payload(payload)

    assert any("array is too short" in issue.message for issue in result.issues)


def test_unique_items_violation_message() -> None:
    payload = _baseline_payload()
    payload["rules"][0]["targets"] = ["api", "api"]

    result = validate_rules_payload(payload)

    assert any("array items must be unique" in issue.message for issue in result.issues)


def test_minimum_violation_message() -> None:
    payload = _baseline_payload()
    payload["rules"][0]["exceptions"]["max_days"] = -1

    result = validate_rules_payload(payload)

    assert any("below minimum" in issue.message for issue in result.issues)


def test_maximum_violation_message() -> None:
    payload = _baseline_payload()
    payload["rules"][0]["exceptions"]["max_days"] = 400

    result = validate_rules_payload(payload)

    assert any("above maximum" in issue.message for issue in result.issues)


def test_multiple_missing_required_fields_message() -> None:
    payload = _baseline_payload()
    del payload["rules"][0]["title"]
    del payload["rules"][0]["description"]

    result = validate_rules_payload(payload)

    assert any("missing required fields:" in issue.message for issue in result.issues)


def test_disallowed_exception_with_window_is_rejected() -> None:
    result = validate_rules_file(
        Path("tests/fixtures/exception-consistency/disallowed-with-window.yaml")
    )

    assert not result.ok
    assert any(
        issue.path == ("rules", 0, "exceptions", "max_days")
        and "not allowed but defines a non-zero max_days" in issue.message
        for issue in result.issues
    )
    assert any(
        issue.path == ("rules", 0, "exceptions", "required_fields")
        and "not allowed but declares required_fields" in issue.message
        for issue in result.issues
    )


def test_allowed_exception_missing_core_fields_warns() -> None:
    payload = _baseline_payload()
    payload["rules"][0]["exceptions"] = {
        "allowed": True,
        "max_days": 30,
        "required_fields": ["owner"],
    }

    result = validate_rules_payload(payload)

    assert result.ok  # warnings only
    assert any(
        issue.level == "warning"
        and "allowed exception should require" in issue.message
        and "justification" in issue.message
        and "expires_at" in issue.message
        for issue in result.issues
    )


def test_allowed_exception_zero_day_window_warns() -> None:
    payload = _baseline_payload()
    payload["rules"][0]["exceptions"] = {
        "allowed": True,
        "max_days": 0,
        "required_fields": ["owner", "justification", "expires_at"],
    }

    result = validate_rules_payload(payload)

    assert result.ok
    assert any(
        issue.level == "warning" and "zero-day window" in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("cwe", "CWE79"),
        ("owasp_api_top_10_2023", "API99:2023"),
        ("owasp_asvs", "5.3"),
        ("nist_ssdf", "XX.1"),
    ],
)
def test_malformed_mapping_id_warns(field: str, bad_value: str) -> None:
    payload = _baseline_payload()
    payload["rules"][0]["mappings"][field] = [bad_value]

    result = validate_rules_payload(payload)

    assert result.ok  # mapping format issues are warnings, not errors
    assert any(
        issue.level == "warning"
        and issue.path[:2] == ("rules", 0)
        and "is malformed" in issue.message
        for issue in result.issues
    )


def test_schema_is_loaded_once_and_cached() -> None:
    from appsec_rules_pack.validator import _load_schema

    first = _load_schema()
    second = _load_schema()

    assert first is second  # cached, not re-read from disk
    assert first["title"] == "AppSec Rules Pack"


def test_well_formed_mappings_do_not_warn() -> None:
    result = validate_rules_file(BASELINE_PATH)

    assert result.ok
    assert not any("is malformed" in issue.message for issue in result.issues)


def test_cli_version_flag_reports_package_version() -> None:
    from appsec_rules_pack import __version__

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_reports_empty_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output


def test_cli_json_output_passing_baseline() -> None:
    import json

    result = runner.invoke(app, ["validate", "rules/appsec-baseline.yaml", "--format", "json"])

    assert result.exit_code == 0
    report = json.loads(result.output)
    assert report["summary"] == {
        "files": 1,
        "rules": 10,
        "errors": 0,
        "warnings": 0,
        "ok": True,
    }
    assert report["files"][0]["path"] == "appsec-baseline.yaml"
    assert report["files"][0]["issues"] == []


def test_cli_json_output_failing_fixture() -> None:
    import json

    result = runner.invoke(
        app,
        ["validate", "tests/fixtures/fail/invalid-enum.yaml", "-f", "json"],
    )

    assert result.exit_code == 1
    report = json.loads(result.output)
    assert report["summary"]["ok"] is False
    assert report["summary"]["errors"] >= 1
    issues = report["files"][0]["issues"]
    assert any(
        issue["level"] == "error" and issue["path"] == "rules.0.severity" for issue in issues
    )


def test_cli_json_output_empty_directory(tmp_path: Path) -> None:
    import json

    result = runner.invoke(app, ["validate", str(tmp_path), "--format", "json"])

    assert result.exit_code == 1
    report = json.loads(result.output)
    assert report["summary"]["errors"] == 1
    assert "no YAML rule files found" in report["error"]


def test_cli_json_output_fail_on_warnings() -> None:
    import json

    result = runner.invoke(
        app,
        ["validate", str(WARN_FIXTURE_PATH), "--format", "json", "--fail-on-warnings"],
    )

    assert result.exit_code == 1
    report = json.loads(result.output)
    assert report["summary"]["ok"] is False
    assert report["summary"]["warnings"] == 1


def test_module_entry_point_runs_help() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(repo_root / "src")}
    result = subprocess.run(
        [sys.executable, "-m", "appsec_rules_pack", "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=repo_root,
        env=env,
    )

    assert result.returncode == 0
    assert "validate" in result.stdout
