"""The public contract: rule schema, validation report, issue codes, and compatibility.

VERSIONING.md defines what other tools may rely on. These tests pin each part of it, so
a change that breaks the contract fails here instead of in a consumer's pipeline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.validator import validate_rules_file, validate_rules_payload

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
REPORT_SCHEMA = json.loads(
    (ROOT / "src/appsec_rules_pack/schemas/validation-report.schema.json").read_text(
        encoding="utf-8"
    )
)
MINIMAL = FIXTURES / "pass" / "minimal-valid.yaml"


def _minimal_payload() -> dict:
    return yaml.safe_load(MINIMAL.read_text(encoding="utf-8"))


def _json_report(*args: str) -> tuple[int, dict]:
    result = runner.invoke(app, ["validate", *args, "--format", "json"])
    return result.exit_code, json.loads(result.stdout)


# --- validation report --------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        FIXTURES / "pass" / "minimal-valid.yaml",
        FIXTURES / "fail" / "invalid-enum.yaml",
        FIXTURES / "warn" / "exception-window-warning.yaml",
        FIXTURES / "cross-file-dup",
        ROOT / "rules",
    ],
    ids=["pass", "fail", "warn", "cross-file", "baseline"],
)
def test_every_report_matches_the_published_schema(target: Path) -> None:
    exit_code, report = _json_report(str(target))

    jsonschema.validate(report, REPORT_SCHEMA)
    assert report["schema"] == "appsec-rules-validation/v1"
    assert (exit_code == 0) == report["summary"]["ok"]


def test_report_for_an_empty_directory_has_an_explicit_verdict(tmp_path: Path) -> None:
    exit_code, report = _json_report(str(tmp_path))

    jsonschema.validate(report, REPORT_SCHEMA)
    assert exit_code == 1
    assert report["summary"]["ok"] is False
    assert report["error"].startswith("no YAML rule files found in ")


def test_issues_carry_a_code_and_the_owning_rule_id() -> None:
    fixture = FIXTURES / "fail" / "invalid-enum.yaml"
    rule_id = yaml.safe_load(fixture.read_text(encoding="utf-8"))["rules"][0]["id"]

    _, report = _json_report(str(fixture))

    [issue] = report["files"][0]["issues"]
    assert issue["code"] == "schema-enum"
    assert issue["rule_id"] == rule_id


def test_pack_level_issues_have_no_rule_id() -> None:
    payload = _minimal_payload()
    payload["pack"]["mode"] = "strict"

    result = validate_rules_payload(payload)

    [issue] = result.issues
    assert issue.code == "schema-enum"
    assert issue.rule_id is None


def test_report_paths_use_forward_slashes(tmp_path: Path) -> None:
    nested = tmp_path / "team" / "service"
    nested.mkdir(parents=True)
    (nested / "pack.yaml").write_text(MINIMAL.read_text(encoding="utf-8"), encoding="utf-8")

    _, report = _json_report(str(tmp_path))

    assert report["files"][0]["path"] == "team/service/pack.yaml"


def test_every_issue_code_is_documented() -> None:
    source = (ROOT / "src/appsec_rules_pack/validator.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'code="([a-z0-9-]+)"', source))
    emitted |= set(re.findall(r'": "(schema-[a-z0-9-]+)"', source))
    emitted.add("schema-invalid")
    versioning = (ROOT / "VERSIONING.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `([a-z0-9-]+)` \|", versioning, re.M))

    assert emitted, "no codes found in validator.py"
    assert emitted <= documented, sorted(emitted - documented)


# --- rule schema --------------------------------------------------------------------


def test_custom_rule_id_prefix_is_valid() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["id"] = "ACME-AUTH-002"

    assert validate_rules_payload(payload).ok


@pytest.mark.parametrize("bad_id", ["acme-auth-002", "ACME-AUTH-2", "-AUTH-002", "ACME_AUTH_002"])
def test_malformed_rule_ids_are_still_rejected(bad_id: str) -> None:
    payload = _minimal_payload()
    payload["rules"][0]["id"] = bad_id

    result = validate_rules_payload(payload)

    assert [issue.code for issue in result.issues] == ["schema-pattern"]


def test_api_top_10_mapping_is_optional() -> None:
    payload = _minimal_payload()
    del payload["rules"][0]["mappings"]["owasp_api_top_10_2023"]

    assert validate_rules_payload(payload).ok


def test_extension_fields_are_accepted_everywhere_they_are_documented() -> None:
    payload = _minimal_payload()
    payload["pack"]["x-team"] = "payments"
    payload["rules"][0]["x-ticket"] = {"system": "jira", "key": "SEC-12"}
    payload["rules"][0]["mappings"]["x-pci-dss"] = ["6.2.4"]

    assert validate_rules_payload(payload).issues == ()


def test_unknown_fields_are_rejected_without_listing_extensions() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["x-ticket"] = "SEC-12"
    payload["rules"][0]["owner"] = "appsec"

    [issue] = validate_rules_payload(payload).issues

    assert issue.code == "schema-unexpected-field"
    assert issue.message == "unexpected field 'owner' is not allowed"


def test_mapping_extension_must_be_a_list_of_strings() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["mappings"]["x-pci-dss"] = "6.2.4"

    assert not validate_rules_payload(payload).ok


# --- schema_version -----------------------------------------------------------------


@pytest.mark.parametrize("version", ["0.2", "0.5"])
def test_supported_schema_versions_are_accepted(version: str) -> None:
    payload = _minimal_payload()
    payload["pack"]["schema_version"] = version

    assert validate_rules_payload(payload).ok


def test_newer_schema_version_is_refused() -> None:
    payload = _minimal_payload()
    payload["pack"]["schema_version"] = "1.0"

    [issue] = validate_rules_payload(payload).issues

    assert issue.code == "schema-version-unsupported"
    assert issue.path == ("pack", "schema_version")
    assert "supports up to 0.5" in issue.message


def test_malformed_schema_version_is_a_pattern_error() -> None:
    payload = _minimal_payload()
    payload["pack"]["schema_version"] = "v0.5"

    assert [issue.code for issue in validate_rules_payload(payload).issues] == ["schema-pattern"]


# --- backward compatibility ---------------------------------------------------------


@pytest.mark.parametrize("release", ["v0.2.0", "v0.4.0"])
def test_released_baselines_still_validate(release: str) -> None:
    result = validate_rules_file(
        FIXTURES / "compat" / f"appsec-baseline-{release}.yaml", require_examples=True
    )

    assert result.ok
    assert result.warning_count == 0
