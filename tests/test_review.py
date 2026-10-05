"""`appsec-rules review`: a review record checked against the pack's own policy (ADR-0006).

Most tests start from the worked example in examples/review/, which is valid against the
baseline, and break one thing at a time.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.review import review_payloads

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "rules" / "appsec-baseline.yaml"
EXAMPLE = ROOT / "examples" / "review" / "payments-api-review.yaml"
REPORT_SCHEMA = json.loads(
    (ROOT / "src/appsec_rules_pack/schemas/review-report.schema.json").read_text(encoding="utf-8")
)
AS_OF = dt.date(2026, 10, 5)


@pytest.fixture(scope="module")
def baseline() -> dict:
    return yaml.safe_load(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture
def record() -> dict:
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def _entry(record: dict, rule_id: str) -> dict:
    return next(entry for entry in record["results"] if entry["rule"] == rule_id)


def _codes(result) -> list[str]:
    return [issue.code for issue in result.issues]


def _cli(*args: str) -> tuple[int, dict]:
    result = runner.invoke(app, ["review", *args, "--format", "json"])
    return result.exit_code, json.loads(result.stdout)


# --- the worked example ---------------------------------------------------------------


def test_worked_example_is_a_valid_record(baseline: dict, record: dict) -> None:
    result = review_payloads(baseline, record, as_of=AS_OF)

    assert result.issues == ()
    counts = result.status_counts()
    assert counts == {"met": 12, "not-applicable": 5, "not-met": 1, "excepted": 1}


def test_cli_report_matches_the_published_schema() -> None:
    exit_code, report = _cli(str(BASELINE), str(EXAMPLE), "--as-of", "2026-10-05")

    jsonschema.validate(report, REPORT_SCHEMA)
    assert exit_code == 0
    assert report["schema"] == "appsec-rules-review/v1"
    assert report["pack"] == {"id": "appsec-baseline", "version": "0.4.0"}
    assert report["summary"]["ok"] is True
    assert report["summary"]["open_by_severity"] == {"medium": 1}
    assert report["summary"]["open_by_enforcement"] == {"advisory": 1}
    [open_rule] = [item for item in report["results"] if item["status"] == "not-met"]
    assert open_rule["rule_id"] == "APPSEC-LOG-001"
    assert open_rule["notes"].startswith("Refund failures")


def test_open_rules_never_change_the_exit_code(record: dict, tmp_path: Path) -> None:
    for entry in record["results"]:
        if entry["status"] == "met":
            entry["status"] = "not-met"
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(record), encoding="utf-8")

    exit_code, report = _cli(str(BASELINE), str(path), "--as-of", "2026-10-05")

    assert exit_code == 0
    assert report["summary"]["not_met"] == 13


def test_text_output_lists_rules_and_a_verdict() -> None:
    result = runner.invoke(app, ["review", str(BASELINE), str(EXAMPLE), "--as-of", "2026-10-05"])

    assert result.exit_code == 0
    assert "APPSEC-LOG-001" in result.stdout
    assert result.stdout.strip().splitlines()[-1].startswith("Review passed: 19 rules; 12 met")


def test_results_follow_pack_order(baseline: dict, record: dict) -> None:
    record["results"].reverse()

    result = review_payloads(baseline, record, as_of=AS_OF)

    assert [outcome.rule_id for outcome in result.outcomes] == [
        rule["id"] for rule in baseline["rules"]
    ]


def test_quoted_and_unquoted_dates_mean_the_same(baseline: dict, record: dict) -> None:
    quoted = copy.deepcopy(record)
    quoted["review"]["date"] = "2026-10-01"

    assert review_payloads(baseline, quoted, as_of=AS_OF).issues == ()
    assert isinstance(record["review"]["date"], dt.date)
    assert review_payloads(baseline, record, as_of=AS_OF).issues == ()


# --- record consistency ---------------------------------------------------------------


def test_record_for_another_pack_is_rejected(baseline: dict, record: dict) -> None:
    record["review"]["pack"] = "other-pack"

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["review-pack-mismatch"]


def test_pack_version_drift_is_a_warning(baseline: dict, record: dict) -> None:
    record["review"]["pack_version"] = "0.3.0"

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert (issue.level, issue.code) == ("warning", "review-pack-version-mismatch")


def test_unknown_rule_is_an_error(baseline: dict, record: dict) -> None:
    record["results"].append({"rule": "APPSEC-NOPE-001", "status": "met", "evidence": ["x"]})

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert (issue.code, issue.rule_id) == ("review-unknown-rule", "APPSEC-NOPE-001")


def test_second_result_for_a_rule_is_an_error(baseline: dict, record: dict) -> None:
    record["results"].append({"rule": "APPSEC-AUTHZ-001", "status": "not-met"})

    result = review_payloads(baseline, record, as_of=AS_OF)

    assert _codes(result) == ["review-duplicate-result"]
    assert _entry(record, "APPSEC-AUTHZ-001")["status"] == "met"
    assert result.status_counts()["met"] == 12


def test_enabled_rules_without_a_result_are_unreviewed(baseline: dict, record: dict) -> None:
    record["results"] = [r for r in record["results"] if r["rule"] != "APPSEC-INJECT-001"]

    result = review_payloads(baseline, record, as_of=AS_OF)

    [issue] = result.issues
    assert (issue.level, issue.code, issue.rule_id) == (
        "warning",
        "review-missing-result",
        "APPSEC-INJECT-001",
    )
    assert result.status_counts()["unreviewed"] == 1
    assert result.open_counts("severity") == {"critical": 1, "medium": 1}


def test_fail_on_warnings_fails_an_incomplete_record(record: dict, tmp_path: Path) -> None:
    record["results"] = record["results"][1:]
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(record), encoding="utf-8")

    lenient, _ = _cli(str(BASELINE), str(path), "--as-of", "2026-10-05")
    strict, report = _cli(str(BASELINE), str(path), "--as-of", "2026-10-05", "--fail-on-warnings")

    assert (lenient, strict) == (0, 1)
    assert report["summary"]["ok"] is False


def test_result_for_a_rule_that_is_not_enabled_warns(baseline: dict, record: dict) -> None:
    pack = copy.deepcopy(baseline)
    pack["rules"][0]["status"] = "draft"

    result = review_payloads(pack, record, as_of=AS_OF)

    [issue] = result.issues
    assert (issue.level, issue.code, issue.rule_id) == (
        "warning",
        "review-rule-not-enabled",
        "APPSEC-AUTHZ-001",
    )


def test_met_without_evidence_is_an_error(baseline: dict, record: dict) -> None:
    del _entry(record, "APPSEC-SSRF-001")["evidence"]

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert (issue.code, issue.rule_id, issue.path) == (
        "review-evidence-missing",
        "APPSEC-SSRF-001",
        ("results", 3),
    )


def test_exception_on_a_rule_that_is_not_excepted_is_an_error(baseline: dict, record: dict) -> None:
    _entry(record, "APPSEC-LOG-001")["exception"] = {"expires_at": "2026-11-01"}

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["review-exception-unexpected"]


def test_excepted_rule_without_an_exception_is_an_error(baseline: dict, record: dict) -> None:
    del _entry(record, "APPSEC-RATELIMIT-001")["exception"]

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["review-exception-missing"]


# --- exceptions against the pack's policy ---------------------------------------------


def _except(record: dict, rule_id: str, **exception: str) -> None:
    entry = _entry(record, rule_id)
    entry.pop("evidence", None)
    entry["status"] = "excepted"
    entry["exception"] = exception


FULL = {
    "owner": "team",
    "justification": "planned fix",
    "compensating_control": "gateway limit",
    "granted_at": "2026-10-01",
}


def test_exception_to_a_rule_that_forbids_them_is_an_error(baseline: dict, record: dict) -> None:
    _except(record, "APPSEC-INJECT-001", **FULL, expires_at="2026-10-15")

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert (issue.code, issue.rule_id) == ("exception-not-allowed", "APPSEC-INJECT-001")


def test_exception_missing_a_field_the_pack_requires(baseline: dict, record: dict) -> None:
    fields = {k: v for k, v in FULL.items() if k != "compensating_control"}
    _except(record, "APPSEC-AUTHZ-001", **fields, expires_at="2026-10-15")

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert issue.code == "exception-field-missing"
    assert issue.message.endswith("compensating_control")


def test_fields_the_pack_does_not_require_may_be_omitted(baseline: dict, record: dict) -> None:
    # APPSEC-LOG-001 requires owner, justification, and expires_at only.
    _except(record, "APPSEC-LOG-001", owner="team", justification="fix", expires_at="2026-10-15")

    assert review_payloads(baseline, record, as_of=AS_OF).issues == ()


@pytest.mark.parametrize(
    ("as_of", "expired"),
    [(dt.date(2026, 12, 14), False), (dt.date(2026, 12, 15), True)],
    ids=["day-before", "on-expiry-day"],
)
def test_exception_expires_on_its_expiry_date(
    baseline: dict, record: dict, as_of: dt.date, expired: bool
) -> None:
    codes = _codes(review_payloads(baseline, record, as_of=as_of))

    assert codes == (["exception-expired"] if expired else [])


@pytest.mark.parametrize(
    ("expires_at", "codes"),
    [
        ("2026-12-30", []),  # 90 days after 2026-10-01: the pack's limit
        ("2026-12-31", ["exception-window-exceeded"]),
    ],
)
def test_exception_window_is_bounded_by_max_days(
    baseline: dict, record: dict, expires_at: str, codes: list[str]
) -> None:
    _entry(record, "APPSEC-RATELIMIT-001")["exception"]["expires_at"] = expires_at

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == codes


def test_window_starts_at_the_review_date_without_granted_at(baseline: dict, record: dict) -> None:
    exception = _entry(record, "APPSEC-RATELIMIT-001")["exception"]
    del exception["granted_at"]
    record["review"]["date"] = "2026-09-01"  # 105 days before 2026-12-15

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["exception-window-exceeded"]


def test_exception_expiring_before_it_was_granted(baseline: dict, record: dict) -> None:
    exception = _entry(record, "APPSEC-RATELIMIT-001")["exception"]
    exception["granted_at"] = "2026-12-20"

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["exception-dates-invalid"]


def test_impossible_calendar_date_is_reported(baseline: dict, record: dict) -> None:
    _entry(record, "APPSEC-RATELIMIT-001")["exception"]["expires_at"] = "2026-02-30"

    [issue] = review_payloads(baseline, record, as_of=AS_OF).issues

    assert issue.code == "review-date-invalid"
    assert issue.path == ("results", 18, "exception", "expires_at")


def test_timestamp_is_not_accepted_as_a_date(baseline: dict, record: dict) -> None:
    record["review"]["date"] = dt.datetime(2026, 10, 1, 9, 30)

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["schema-pattern"]


# --- inputs that cannot be reviewed ---------------------------------------------------


def test_record_schema_errors_name_the_rule(baseline: dict, record: dict) -> None:
    _entry(record, "APPSEC-DEP-001")["status"] = "done"

    result = review_payloads(baseline, record, as_of=AS_OF)

    [issue] = result.issues
    assert (issue.code, issue.rule_id) == ("schema-enum", "APPSEC-DEP-001")
    assert result.outcomes == ()


def test_secret_in_a_record_is_an_error(baseline: dict, record: dict) -> None:
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    _entry(record, "APPSEC-SECRETS-001")["evidence"].append(f"rotated {fake_key}")

    assert _codes(review_payloads(baseline, record, as_of=AS_OF)) == ["sensitive-value"]


def test_invalid_pack_is_refused(baseline: dict, record: dict) -> None:
    pack = copy.deepcopy(baseline)
    pack["rules"][0]["severity"] = "urgent"

    result = review_payloads(pack, record, as_of=AS_OF)

    assert _codes(result) == ["review-pack-invalid"]
    assert result.outcomes == ()


def test_unparseable_record_file(tmp_path: Path) -> None:
    path = tmp_path / "record.yaml"
    path.write_text("review: [unclosed\n", encoding="utf-8")

    exit_code, report = _cli(str(BASELINE), str(path), "--as-of", "2026-10-05")

    jsonschema.validate(report, REPORT_SCHEMA)
    assert exit_code == 1
    assert [issue["code"] for issue in report["issues"]] == ["yaml-invalid"]
    assert report["pack"]["id"] == "appsec-baseline"


def test_unparseable_pack_file(tmp_path: Path) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text("pack: [unclosed\n", encoding="utf-8")

    exit_code, report = _cli(str(path), str(EXAMPLE), "--as-of", "2026-10-05")

    jsonschema.validate(report, REPORT_SCHEMA)
    assert exit_code == 1
    assert [issue["code"] for issue in report["issues"]] == ["review-pack-invalid"]


def test_bad_as_of_is_a_usage_error() -> None:
    result = runner.invoke(app, ["review", str(BASELINE), str(EXAMPLE), "--as-of", "05/10/2026"])

    assert result.exit_code == 2


def test_as_of_defaults_to_today(record: dict, tmp_path: Path) -> None:
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(record), encoding="utf-8")

    _, report = _cli(str(BASELINE), str(path))

    assert report["as_of"] == dt.datetime.now(dt.UTC).date().isoformat()


def test_every_review_issue_code_is_documented() -> None:
    source = (ROOT / "src/appsec_rules_pack/review.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'code="([a-z0-9-]+)"', source))
    emitted |= set(re.findall(r'issue\(\s*"([a-z0-9-]+)"', source))
    versioning = (ROOT / "VERSIONING.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `([a-z0-9-]+)` \|", versioning, re.M))

    assert len(emitted) >= 12, emitted
    assert emitted <= documented, sorted(emitted - documented)


def test_readme_record_is_valid_against_the_baseline(baseline: dict) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(
        r"<!-- readme-example:review-record[^\n]*\n\s*```yaml\n(?P<body>.*?)\n```", readme, re.S
    )
    assert match is not None
    record = yaml.safe_load(match.group("body"))

    result = review_payloads(baseline, record, as_of=AS_OF)

    assert result.error_count == 0
    assert {issue.code for issue in result.issues} == {"review-missing-result"}


def test_text_output_names_the_rule_of_each_issue(record: dict, tmp_path: Path) -> None:
    del _entry(record, "APPSEC-SSRF-001")["evidence"]
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(record), encoding="utf-8")

    result = runner.invoke(app, ["review", str(BASELINE), str(path), "--as-of", "2026-10-05"])

    assert result.exit_code == 1
    assert "ERROR results.3: a met rule must cite" in result.stdout
    assert "[APPSEC-SSRF-001]" in result.stdout
    assert "Review failed:" in result.stdout
