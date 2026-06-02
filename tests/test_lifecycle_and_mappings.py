"""Tests for rule lifecycle (deprecation) and the optional Top 10:2025 mapping."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.validator import validate_rules_payload

BASELINE_PATH = Path("rules/appsec-baseline.yaml")


def _baseline() -> dict:
    return deepcopy(load_yaml_file(BASELINE_PATH))


def test_top_10_2025_mapping_present_and_clean() -> None:
    payload = _baseline()

    # The optional field is populated on at least the access-control rule.
    assert any("owasp_top_10_2025" in rule["mappings"] for rule in payload["rules"])

    result = validate_rules_payload(payload)
    assert result.ok
    assert result.warning_count == 0


def test_malformed_top_10_2025_id_warns() -> None:
    payload = _baseline()
    payload["rules"][0]["mappings"]["owasp_top_10_2025"] = ["A1:2025"]  # missing leading zero

    result = validate_rules_payload(payload)

    assert result.ok  # mapping-format issues are warnings, not errors
    assert any(
        issue.level == "warning" and "A1:2025" in issue.message for issue in result.issues
    )


def test_deprecated_rule_with_metadata_is_clean() -> None:
    payload = _baseline()
    rule = payload["rules"][0]
    rule["status"] = "deprecated"
    rule["deprecation"] = {
        "reason": "Superseded by a more specific successor rule.",
        "since": "2026-06-02",
    }

    result = validate_rules_payload(payload)

    assert result.ok
    assert not any(issue.path == ("rules", 0, "deprecation") for issue in result.issues)


def test_deprecated_without_metadata_warns() -> None:
    payload = _baseline()
    payload["rules"][0]["status"] = "deprecated"

    result = validate_rules_payload(payload)

    assert result.ok
    assert any(
        issue.level == "warning" and issue.path == ("rules", 0, "deprecation")
        for issue in result.issues
    )


def test_deprecation_metadata_without_deprecated_status_warns() -> None:
    payload = _baseline()
    payload["rules"][0]["deprecation"] = {"reason": "Pending retirement next release."}

    result = validate_rules_payload(payload)

    assert result.ok
    assert any(
        issue.level == "warning" and issue.path == ("rules", 0, "status")
        for issue in result.issues
    )
