"""Tests for the SARIF rule-catalog export (declares rules, no results)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.sarif_export import SARIF_VERSION, build_sarif_from_files

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
SARIF_PATH = Path("exports/sarif/appsec-baseline.sarif.json")

runner = CliRunner()


def test_sarif_declares_rules_with_no_results() -> None:
    sarif = build_sarif_from_files([BASELINE_PATH])
    payload = load_yaml_file(BASELINE_PATH)
    enabled = [rule for rule in payload["rules"] if rule.get("status") == "enabled"]

    assert sarif["version"] == SARIF_VERSION
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == len(enabled)
    # The pack does not scan, so there are no findings by design.
    assert run["results"] == []

    first = run["tool"]["driver"]["rules"][0]
    assert first["defaultConfiguration"]["level"] in {"error", "warning", "note"}
    assert "security" in first["properties"]["tags"]


def test_committed_sarif_matches_current_pack() -> None:
    committed = json.loads(SARIF_PATH.read_text(encoding="utf-8"))
    derived = build_sarif_from_files([BASELINE_PATH])

    assert committed == derived


def test_cli_export_sarif_to_stdout() -> None:
    result = runner.invoke(app, ["export", "sarif", str(BASELINE_PATH)])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["version"] == SARIF_VERSION
    assert payload["runs"][0]["results"] == []


def test_cli_export_sarif_no_rule_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["export", "sarif", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output
