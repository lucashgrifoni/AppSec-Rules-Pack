"""Every semantic check keeps going after an item it skips.

Each check loops over rules (and some over values inside a rule) and skips items it
cannot judge. The older tests put the flagged rule first, so a skip that ended the loop
instead of moving to the next item went unnoticed: mutation testing showed `continue`
replaced by `break` surviving in 13 places, and in the secret scan. Here the flagged
rule always comes after every kind of item the check skips.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from appsec_rules_pack.sarif_export import build_sarif
from appsec_rules_pack.semgrep_scaffold import build_semgrep_scaffold
from appsec_rules_pack.validator import (
    validate_rules_file,
    validate_rules_files,
    validate_rules_payload,
)

ROOT = Path(__file__).resolve().parents[1]
STARTER = yaml.safe_load(
    (ROOT / "src/appsec_rules_pack/templates/minimal-pack.yaml").read_text(encoding="utf-8")
)


def _rule(rule_id: str = "TEST-LOOP-001", **changes: Any) -> dict:
    rule = copy.deepcopy(STARTER["rules"][0])
    rule["id"] = rule_id
    for key, value in changes.items():
        if value is None:
            rule.pop(key, None)
        else:
            rule[key] = value
    return rule


def _flagged(rules: list[Any], code: str, *, require_examples: bool = False) -> list[str | int]:
    payload = {"pack": copy.deepcopy(STARTER["pack"]), "rules": rules}
    result = validate_rules_payload(payload, require_examples=require_examples)
    return [issue.path[1] for issue in result.issues if issue.code == code]


NOT_A_RULE = "not a rule"


def _exceptions(allowed: bool, max_days: int, fields: list[str]) -> dict:
    return {"allowed": allowed, "max_days": max_days, "required_fields": fields}


FULL_FIELDS = ["owner", "justification", "expires_at"]

# (code, items the check skips, the rule it must still flag)
EXCEPTION_CASES = [
    ("exception-window-too-long", _exceptions(True, 91, FULL_FIELDS)),
    ("exception-disallowed-window", _exceptions(False, 1, [])),
    ("exception-disallowed-fields", _exceptions(False, 0, ["owner"])),
    ("exception-missing-fields", _exceptions(True, 30, ["owner"])),
    ("exception-zero-window", _exceptions(True, 0, FULL_FIELDS)),
]


@pytest.mark.parametrize(
    ("code", "exceptions"), EXCEPTION_CASES, ids=[c for c, _ in EXCEPTION_CASES]
)
def test_exception_checks_reach_rules_after_skipped_ones(code: str, exceptions: dict) -> None:
    rules = [
        NOT_A_RULE,
        _rule("TEST-LOOP-001", exceptions=None),
        _rule("TEST-LOOP-002", exceptions="not a mapping"),
        _rule("TEST-LOOP-003"),
        _rule("TEST-LOOP-004", exceptions=exceptions),
    ]

    assert _flagged(rules, code) == [4]


@pytest.mark.parametrize(
    ("allowed", "max_days", "code", "flagged"),
    [
        (True, 90, "exception-window-too-long", False),
        (True, 91, "exception-window-too-long", True),
        (False, 0, "exception-disallowed-window", False),
        (False, 1, "exception-disallowed-window", True),
        (True, 0, "exception-zero-window", True),
        (True, 1, "exception-zero-window", False),
    ],
)
def test_exception_window_boundaries(
    allowed: bool, max_days: int, code: str, flagged: bool
) -> None:
    fields = FULL_FIELDS if allowed else []
    rules = [_rule(exceptions=_exceptions(allowed, max_days, fields))]

    assert _flagged(rules, code) == ([0] if flagged else [])


def test_duplicate_ids_are_found_after_rules_without_a_string_id() -> None:
    rules = [
        NOT_A_RULE,
        _rule(id=None),
        _rule(id=7),
        _rule("TEST-LOOP-001"),
        _rule("TEST-LOOP-001"),
    ]

    assert _flagged(rules, "duplicate-rule-id") == [4]


def test_mapping_checks_reach_later_rules_and_later_frameworks() -> None:
    # The flagged rule omits both optional frameworks, which sit before cwe and nist_ssdf
    # in the check order, so a skipped framework must not end the scan of the rule.
    mappings = {"owasp_asvs": ["V16.5.1"], "cwe": ["CWE 209"], "nist_ssdf": ["PW7"]}
    rules = [
        NOT_A_RULE,
        _rule("TEST-LOOP-001", mappings=None),
        _rule("TEST-LOOP-002", mappings=["CWE-209"]),
        _rule("TEST-LOOP-003", mappings={**mappings, "cwe": "CWE-209", "nist_ssdf": ["PW.7"]}),
        _rule("TEST-LOOP-004", mappings=mappings),
    ]

    payload = {"pack": copy.deepcopy(STARTER["pack"]), "rules": rules}
    issues = [
        issue.path[1:4]
        for issue in validate_rules_payload(payload).issues
        if issue.code == "mapping-id-malformed"
    ]

    assert issues == [(4, "mappings", "cwe"), (4, "mappings", "nist_ssdf")]


def test_mapping_checks_reach_later_values_in_a_list() -> None:
    mappings = {"owasp_asvs": ["V16.5.1"], "cwe": ["CWE-209", 209, "CWE 20"], "nist_ssdf": ["PW.7"]}

    payload = {"pack": copy.deepcopy(STARTER["pack"]), "rules": [_rule(mappings=mappings)]}
    paths = [
        issue.path
        for issue in validate_rules_payload(payload).issues
        if issue.code == "mapping-id-malformed"
    ]

    assert paths == [("rules", 0, "mappings", "cwe", 2)]


@pytest.mark.parametrize(
    ("code", "flagged_rule"),
    [
        ("deprecation-missing", {"status": "deprecated", "deprecation": None}),
        ("deprecation-status-mismatch", {"deprecation": {"reason": "Replaced by a newer rule."}}),
    ],
)
def test_deprecation_checks_reach_rules_after_skipped_ones(code: str, flagged_rule: dict) -> None:
    rules = [NOT_A_RULE, _rule("TEST-LOOP-001"), _rule("TEST-LOOP-002", **flagged_rule)]

    assert _flagged(rules, code) == [2]


def test_missing_examples_are_found_after_rules_the_check_skips() -> None:
    rules = [
        NOT_A_RULE,
        _rule("TEST-LOOP-001", status="disabled", examples=None),
        _rule("TEST-LOOP-002"),
        _rule("TEST-LOOP-003", examples=None),
    ]

    assert _flagged(rules, "examples-missing", require_examples=True) == [3]


def test_secret_scan_continues_after_an_examples_block() -> None:
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    rules = [_rule("TEST-LOOP-001"), _rule("TEST-LOOP-002", description=f"Rotate {fake_key} now.")]

    assert _flagged(rules, "sensitive-value") == [1]


def test_require_examples_is_off_by_default_for_several_files(tmp_path: Path) -> None:
    pack = {"pack": copy.deepcopy(STARTER["pack"]), "rules": [_rule(examples=None)]}
    paths = []
    for name in ("a.yaml", "b.yaml"):
        pack["rules"][0]["id"] = f"TEST-{name[0].upper()}-001"
        path = tmp_path / name
        path.write_text(yaml.safe_dump(pack), encoding="utf-8")
        paths.append(path)

    results = validate_rules_files(paths)

    assert [result.issues for _, result in results] == [(), ()]
    assert validate_rules_file(paths[0]).issues == ()


# --- exporters ----------------------------------------------------------------------


def _mixed_status_pack() -> dict:
    return {
        "pack": copy.deepcopy(STARTER["pack"]),
        "rules": [
            _rule("TEST-DISABLED-001", status="disabled"),
            _rule("TEST-DRAFT-001", status="draft"),
            _rule("TEST-ENABLED-001"),
            _rule(
                "TEST-DEPRECATED-001",
                status="deprecated",
                deprecation={"reason": "Replaced by a newer rule."},
            ),
        ],
    }


def test_sarif_catalog_lists_only_enabled_rules() -> None:
    sarif = build_sarif([_mixed_status_pack()])

    [run] = sarif["runs"]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["TEST-ENABLED-001"]


def test_semgrep_scaffold_lists_only_enabled_rules() -> None:
    scaffold = build_semgrep_scaffold([_mixed_status_pack()])

    assert [rule["id"] for rule in scaffold["rules"]] == ["TEST-ENABLED-001"]
