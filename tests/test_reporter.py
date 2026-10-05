"""Tests for the mapping-coverage reporter and the `report coverage` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.reporter import COVERAGE_SCHEMA, build_coverage_from_files

BASELINE_PATH = Path("rules/appsec-baseline.yaml")

runner = CliRunner()


def test_report_coverage_warns_when_pack_yields_no_rules(tmp_path: Path) -> None:
    """A malformed pack used to produce a clean-looking 0/0 report with no signal.

    `report coverage` derives from mapping metadata without schema validation, so a
    pack whose `rules` key is not a list still reports successfully. It now says so on
    stderr. The exit code stays 0 on purpose: judging pack structure is `validate`'s job,
    and changing it would break callers that treat a non-zero exit as a mapping failure.
    """

    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("pack:\n  id: demo\nrules: not-a-list\n", encoding="utf-8")

    result = runner.invoke(app, ["report", "coverage", str(malformed)])

    assert result.exit_code == 0
    assert "no rules found" in result.output
    assert "Mapping coverage for 0 rules" in result.output


def test_build_coverage_summary() -> None:
    coverage = build_coverage_from_files([BASELINE_PATH])

    assert coverage["schema"] == COVERAGE_SCHEMA
    assert coverage["rules"] == 20

    fw = coverage["frameworks"]
    # Required mappings are present on every rule.
    for required in ("owasp_asvs", "cwe", "nist_ssdf"):
        assert fw[required]["covered"] == 20
        assert fw[required]["missing"] == []

    # The optional mappings are partial by design: APPSEC-PWSTORE-001 has no API Top 10
    # category, and APPSEC-FILE-001 has no Top 10:2025 category.
    for optional, missing in (
        ("owasp_api_top_10_2023", ["APPSEC-PWSTORE-001"]),
        ("owasp_top_10_2025", ["APPSEC-FILE-001"]),
    ):
        assert fw[optional]["covered"] == 19
        assert fw[optional]["missing"] == missing

    assert coverage["categories"]  # non-empty category distribution


def test_cli_report_coverage_text() -> None:
    result = runner.invoke(app, ["report", "coverage", str(BASELINE_PATH)])

    assert result.exit_code == 0
    assert "Mapping coverage for 20 rules:" in result.output
    assert "owasp_asvs" in result.output


def test_cli_report_coverage_json() -> None:
    result = runner.invoke(app, ["report", "coverage", str(BASELINE_PATH), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema"] == COVERAGE_SCHEMA
    assert payload["rules"] == 20


def test_cli_report_coverage_to_file(tmp_path: Path) -> None:
    out = tmp_path / "coverage.json"

    result = runner.invoke(
        app, ["report", "coverage", str(BASELINE_PATH), "--format", "json", "--output", str(out)]
    )

    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["rules"] == 20


def test_cli_report_coverage_no_rule_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "coverage", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output
