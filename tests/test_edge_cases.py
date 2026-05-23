"""Negative and edge-case tests for safe failure behavior."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.validator import validate_rules_file

runner = CliRunner()

VALID_PACK = """\
pack:
  id: edge-pack
  name: Edge Case Pack
  version: 0.1.0
  mode: advisory
  owner: appsec
  description: Minimal valid pack used by edge-case tests.
rules:
  - id: APPSEC-EDGE-001
    title: Minimal valid rule
    description: A minimal but schema-valid rule used to exercise edge cases.
    severity: low
    category: configuration
    status: enabled
    enforcement: advisory
    targets:
      - general
    mappings:
      owasp_asvs:
        - V14.1
      owasp_api_top_10_2023:
        - API8:2023
      cwe:
        - CWE-16
      nist_ssdf:
        - PW.9
    evidence:
      required:
        - Evidence item.
      signals:
        - Signal item.
    match:
      type: review
      includes:
        - Included surface.
      excludes:
        - Excluded surface.
    remediation:
      guidance: Apply the documented secure configuration guidance for this rule.
      validation:
        - Validation step.
    exceptions:
      allowed: true
      max_days: 30
      required_fields:
        - owner
        - justification
        - expires_at
"""


def test_empty_file_fails_without_crashing(tmp_path: Path) -> None:
    target = tmp_path / "empty.yaml"
    target.write_text("\n", encoding="utf-8")

    result = validate_rules_file(target)

    assert not result.ok
    assert result.rule_count == 0
    assert any("expected object" in issue.message for issue in result.issues)


def test_non_mapping_rule_entry_fails_safely(tmp_path: Path) -> None:
    target = tmp_path / "badrule.yaml"
    target.write_text(
        "pack:\n"
        "  id: x\n"
        "  name: Test Pack\n"
        "  version: 0.1.0\n"
        "  mode: advisory\n"
        "  owner: ab\n"
        "  description: short description here\n"
        "rules:\n"
        "  - just-a-string\n",
        encoding="utf-8",
    )

    result = validate_rules_file(target)

    assert not result.ok
    assert any(issue.path == ("rules", 0) for issue in result.issues)


def test_yml_extension_is_recognized(tmp_path: Path) -> None:
    target = tmp_path / "pack.yml"
    target.write_text(VALID_PACK, encoding="utf-8")

    result = runner.invoke(app, ["validate", str(tmp_path)])

    assert result.exit_code == 0
    assert "1 file" in result.output


def test_uppercase_extension_is_recognized(tmp_path: Path) -> None:
    target = tmp_path / "PACK.YAML"
    target.write_text(VALID_PACK, encoding="utf-8")

    result = runner.invoke(app, ["validate", str(tmp_path)])

    assert result.exit_code == 0
    assert "1 file" in result.output


def test_directory_with_valid_and_empty_file_fails(tmp_path: Path) -> None:
    (tmp_path / "valid.yaml").write_text(VALID_PACK, encoding="utf-8")
    (tmp_path / "empty.yaml").write_text("\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", str(tmp_path)])

    assert result.exit_code == 1
    assert "2 files" in result.output
    assert "empty.yaml" in result.output
