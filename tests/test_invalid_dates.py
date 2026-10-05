"""An unquoted date that is not a real day is a YAML error, not a crash.

YAML reads `2026-02-30` as a date, and PyYAML raises a plain ValueError for it, which
escaped the loader: `validate`, the exports, and `review` all printed a traceback. Found
by the property harness (issue #32); present since the first release.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.validator import validate_rules_file

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("value", "column"),
    [("2026-02-30", 10), ("2026-13-01", 10), ("2026-01-01 25:00:00", 10)],
)
def test_impossible_date_is_a_located_yaml_error(tmp_path: Path, value: str, column: int) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text(f"pack:\n  since: {value}\nrules: []\n", encoding="utf-8")

    [issue] = validate_rules_file(path).issues

    assert issue.code == "yaml-invalid"
    assert issue.message.startswith(f"could not parse YAML file at line 2, column {column}: ")
    assert "not a valid date" in issue.message


def test_a_real_date_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text("pack:\n  since: 2026-02-28\nrules: []\n", encoding="utf-8")

    codes = {issue.code for issue in validate_rules_file(path).issues}

    assert "yaml-invalid" not in codes


def test_export_reports_an_impossible_date_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text("pack:\n  since: 2026-02-30\nrules: []\n", encoding="utf-8")

    result = runner.invoke(app, ["export", "index", str(path)])

    assert result.exit_code == 1
    assert "could not parse YAML" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_review_reports_an_impossible_date_in_the_record(tmp_path: Path) -> None:
    record = (ROOT / "examples/review/payments-api-review.yaml").read_text(encoding="utf-8")
    path = tmp_path / "record.yaml"
    path.write_text(record.replace("date: 2026-10-01", "date: 2026-02-30"), encoding="utf-8")

    result = runner.invoke(
        app,
        ["review", str(ROOT / "rules/appsec-baseline.yaml"), str(path), "--format", "json"],
    )

    report = json.loads(result.stdout)
    assert result.exit_code == 1
    assert [issue["code"] for issue in report["issues"]] == ["yaml-invalid"]
