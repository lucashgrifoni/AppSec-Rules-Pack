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
    assert coverage["rules"] == 24

    fw = coverage["frameworks"]
    # Required mappings are present on every rule.
    for required in ("cwe", "nist_ssdf"):
        assert fw[required]["covered"] == 24
        assert fw[required]["missing"] == []

    # The optional mappings are partial by design (docs/mapping-rationale.md): ASVS 5.0.0
    # has no requirement for LLM prompts, and the general Top 10 lists are not stretched
    # over rules that have no category there.
    llm_rules = ["APPSEC-LLM-001", "APPSEC-LLM-002"]
    for optional, missing in (
        ("owasp_asvs", ["APPSEC-LLM-001"]),
        ("owasp_api_top_10_2023", ["APPSEC-PWSTORE-001", *llm_rules, "APPSEC-LOG-002"]),
        ("owasp_top_10_2025", ["APPSEC-FILE-001", *llm_rules]),
    ):
        assert fw[optional]["missing"] == missing
        assert fw[optional]["covered"] == 24 - len(missing)
    assert fw["owasp_llm_top_10_2025"]["covered"] == 2

    assert coverage["categories"]  # non-empty category distribution


def test_cli_report_coverage_text() -> None:
    result = runner.invoke(app, ["report", "coverage", str(BASELINE_PATH)])

    assert result.exit_code == 0
    assert "Mapping coverage for 24 rules:" in result.output
    assert "owasp_asvs" in result.output


def test_cli_report_coverage_json() -> None:
    result = runner.invoke(app, ["report", "coverage", str(BASELINE_PATH), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema"] == COVERAGE_SCHEMA
    assert payload["rules"] == 24


def test_cli_report_coverage_to_file(tmp_path: Path) -> None:
    out = tmp_path / "coverage.json"

    result = runner.invoke(
        app, ["report", "coverage", str(BASELINE_PATH), "--format", "json", "--output", str(out)]
    )

    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["rules"] == 24


def test_cli_report_coverage_no_rule_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "coverage", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output
