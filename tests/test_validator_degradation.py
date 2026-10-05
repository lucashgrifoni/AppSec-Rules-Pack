"""How the semantic checks behave on payloads the schema already rejected.

Schema validation and the semantic checks run over the same payload, so every
semantic check sees malformed input whenever a pack is invalid. Each one skips what
it cannot read instead of raising, which is what lets a single `validate` run report
*all* the schema errors at once rather than dying on the first malformed rule.

These tests pin that down. Without them, adding a semantic check that indexes into a
rule without a type guard would crash the whole run on any invalid pack, and nothing
would catch it: every existing fixture is either valid or invalid in a way that still
keeps `rules` a list of dicts.
"""

from __future__ import annotations

from typing import Any

from appsec_rules_pack.validator import validate_rules_payload

VALID_PACK_META = {
    "id": "degraded-pack",
    "name": "Degraded Pack",
    "version": "0.1.0",
    "mode": "advisory",
    "owner": "appsec",
    "description": "Pack used to exercise degraded semantic-check paths.",
}


def _payload(rules: Any) -> dict[str, Any]:
    return {"pack": dict(VALID_PACK_META), "rules": rules}


def test_non_dict_rule_entries_do_not_crash_the_semantic_checks() -> None:
    result = validate_rules_payload(_payload(["not-a-dict", 42, None]))

    # Every entry is reported by the schema rather than the run aborting on the first.
    type_errors = [issue for issue in result.issues if issue.path[:1] == ("rules",)]
    assert len(type_errors) == 3
    assert all(issue.level == "error" for issue in type_errors)


def test_rules_that_are_not_a_list_are_reported_without_crashing() -> None:
    result = validate_rules_payload(_payload("not-a-list"))

    assert result.rule_count == 0
    assert any(issue.level == "error" for issue in result.issues)


def test_duplicate_detection_ignores_rules_without_a_string_id() -> None:
    result = validate_rules_payload(_payload([{"id": 1}, {"id": 1}, {"no": "id"}]))

    # A non-string id cannot collide: reporting a duplicate here would be a false
    # positive on top of the schema error the pack already gets.
    assert not any("duplicate" in issue.message.lower() for issue in result.issues)


def test_exception_checks_skip_rules_whose_exceptions_block_is_not_a_mapping() -> None:
    result = validate_rules_payload(_payload([{"id": "APPSEC-D-001", "exceptions": "nope"}]))

    assert not any("exception" in issue.message.lower() for issue in result.issues)


def test_mapping_format_checks_skip_rules_whose_mappings_are_not_a_mapping() -> None:
    result = validate_rules_payload(_payload([{"id": "APPSEC-D-002", "mappings": ["CWE 79"]}]))

    assert "mapping-id-malformed" not in {issue.code for issue in result.issues}


def test_require_examples_skips_non_dict_rules() -> None:
    result = validate_rules_payload(_payload(["not-a-dict"]), require_examples=True)

    assert not any("example" in issue.message.lower() for issue in result.issues)


def test_a_payload_that_is_not_a_mapping_is_reported_not_raised() -> None:
    result = validate_rules_payload("not-a-mapping")

    assert result.rule_count == 0
    assert any(issue.level == "error" for issue in result.issues)
