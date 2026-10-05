"""YAML keys that are not strings get an issue, not a crash.

YAML allows `0: x`, `true: x`, or `null: x` as mapping keys. The `x-` extension keys added
in v0.5 put `patternProperties` on the pack, the rules, and `mappings`, and jsonschema
applies their regex to every key, so a non-string key raised TypeError out of `validate`
and `review` instead of being reported. Found by the property harness (issue #32).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.review import review_payloads
from appsec_rules_pack.validator import validate_rules_payload

ROOT = Path(__file__).resolve().parents[1]
STARTER = yaml.safe_load(
    (ROOT / "src/appsec_rules_pack/templates/minimal-pack.yaml").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    ("where", "key"),
    [("pack", 0), ("rule", True), ("mappings", None), ("root", 1.5)],
)
def test_non_string_key_is_an_unexpected_field(where: str, key: object) -> None:
    pack = copy.deepcopy(STARTER)
    target = {
        "pack": pack["pack"],
        "rule": pack["rules"][0],
        "mappings": pack["rules"][0]["mappings"],
        "root": pack,
    }[where]
    target[key] = "x"

    result = validate_rules_payload(pack)

    assert [issue.code for issue in result.issues] == ["schema-unexpected-field"]
    assert repr(str(key)) in result.issues[0].message


def test_cli_reports_a_non_string_key_as_json(tmp_path: Path) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text("pack:\n  0: null\nrules: []\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["validate", str(path), "--format", "json"])

    report = json.loads(result.stdout)
    assert result.exit_code == 1
    codes = [issue["code"] for issue in report["files"][0]["issues"]]
    assert "schema-unexpected-field" in codes


def test_review_record_with_a_non_string_key_is_an_issue() -> None:
    baseline = yaml.safe_load((ROOT / "rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
    record = yaml.safe_load(
        (ROOT / "examples/review/payments-api-review.yaml").read_text(encoding="utf-8")
    )
    record["results"][0][0] = "x"

    result = review_payloads(baseline, record, as_of=dt.date(2026, 10, 5))

    assert [issue.code for issue in result.issues] == ["schema-unexpected-field"]
    assert result.issues[0].rule_id == "APPSEC-AUTHZ-001"
