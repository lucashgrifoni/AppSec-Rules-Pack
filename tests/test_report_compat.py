"""Saved v1 reports are a field/type floor; additive fields remain compatible."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/compat/reports"
runner = CliRunner()


def current_report(kind: str, tmp_path: Path) -> dict:
    if kind == "validation":
        args = ["validate", str(ROOT / "tests/fixtures/fail/invalid-enum.yaml")]
    else:
        record = yaml.safe_load(
            (ROOT / "examples/review/payments-api-review.yaml").read_text(encoding="utf-8")
        )
        del record["results"][0]["evidence"]
        path = tmp_path / "review.yaml"
        path.write_text(yaml.safe_dump(record), encoding="utf-8")
        args = [
            "review",
            str(ROOT / "rules/appsec-baseline.yaml"),
            str(path),
            "--as-of",
            "2026-10-05",
        ]
    result = runner.invoke(app, [*args, "--format", "json"])
    assert result.exit_code == 1, result.output
    return json.loads(result.stdout)


def assert_floor(current: Any, fixture: Any, path: str = "$") -> None:
    assert type(current) is type(fixture), f"{path}: changed JSON type"
    if isinstance(fixture, dict):
        for key, value in fixture.items():
            assert key in current, f"{path}.{key}: missing field"
            assert_floor(current[key], value, f"{path}.{key}")
    elif isinstance(fixture, list):
        for template in fixture:
            for candidate in current:
                try:
                    assert_floor(candidate, template, f"{path}[]")
                except AssertionError:
                    continue
                break
            else:
                raise AssertionError(f"{path}[]: missing fixture element shape")


@pytest.mark.parametrize("kind", ["validation", "review"])
def test_current_report_preserves_fixture_floor(kind: str, tmp_path: Path) -> None:
    fixture = json.loads((FIXTURES / f"{kind}-v1.json").read_text(encoding="utf-8"))
    current = current_report(kind, tmp_path)
    schema = json.loads(
        (ROOT / f"src/appsec_rules_pack/schemas/{kind}-report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(current, schema)
    assert current["schema"] == fixture["schema"]
    assert_floor(current, fixture)


@pytest.mark.parametrize("kind", ["validation", "review"])
def test_additive_report_fields_are_allowed(kind: str) -> None:
    fixture = json.loads((FIXTURES / f"{kind}-v1.json").read_text(encoding="utf-8"))
    current = deepcopy(fixture)
    current["new_optional_field"] = {"value": True}
    current["summary"]["new_optional_count"] = 0
    assert_floor(current, fixture)


@pytest.mark.parametrize("kind", ["validation", "review"])
@pytest.mark.parametrize("change", ["removed", "wrong-type", "boolean-as-integer"])
def test_report_floor_rejects_breaking_changes(kind: str, change: str) -> None:
    fixture = json.loads((FIXTURES / f"{kind}-v1.json").read_text(encoding="utf-8"))
    current = deepcopy(fixture)
    if change == "removed":
        del current["summary"]["errors"]
    elif change == "wrong-type":
        current["summary"]["errors"] = "0"
    else:
        current["summary"]["errors"] = False
    with pytest.raises(AssertionError):
        assert_floor(current, fixture)


def test_nested_issue_field_removal_is_detected() -> None:
    fixture = json.loads((FIXTURES / "validation-v1.json").read_text(encoding="utf-8"))
    current = deepcopy(fixture)
    del current["files"][0]["issues"][0]["code"]
    with pytest.raises(AssertionError, match="missing fixture element shape"):
        assert_floor(current, fixture)
