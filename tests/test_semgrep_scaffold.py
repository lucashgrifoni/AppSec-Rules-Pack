"""Tests for the reference (non-runnable) Semgrep scaffold export."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.semgrep_scaffold import (
    PATTERN_PLACEHOLDER,
    build_semgrep_scaffold_from_files,
)

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
SCAFFOLD_PATH = Path("exports/semgrep/appsec-baseline.semgrep.yaml")

runner = CliRunner()


def test_scaffold_emits_enabled_rules_with_placeholder() -> None:
    scaffold = build_semgrep_scaffold_from_files([BASELINE_PATH])
    payload = load_yaml_file(BASELINE_PATH)
    enabled = [rule for rule in payload["rules"] if rule.get("status") == "enabled"]

    assert len(scaffold["rules"]) == len(enabled)
    for rule in scaffold["rules"]:
        # Every emitted rule is a non-runnable scaffold, never a real detection.
        assert rule["pattern-regex"] == PATTERN_PLACEHOLDER
        assert rule["severity"] in {"ERROR", "WARNING", "INFO"}
        assert rule["languages"] == ["generic"]


def test_committed_scaffold_matches_current_pack() -> None:
    # Drift guard: the checked-in scaffold must equal a fresh derivation (ignoring the
    # header comment, which the CLI prepends and YAML parsing strips).
    committed = yaml.safe_load(SCAFFOLD_PATH.read_text(encoding="utf-8"))
    derived = build_semgrep_scaffold_from_files([BASELINE_PATH])

    assert committed == derived


def test_cli_export_semgrep_carries_non_runnable_header() -> None:
    result = runner.invoke(app, ["export", "semgrep", str(BASELINE_PATH)])

    assert result.exit_code == 0
    assert "NOT a runnable ruleset" in result.output
    assert PATTERN_PLACEHOLDER in result.output


def test_cli_export_semgrep_no_rule_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["export", "semgrep", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output
