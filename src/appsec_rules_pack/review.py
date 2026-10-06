"""Check a review record against the rules pack it claims to follow (ADR-0006).

A review record states, rule by rule, what a reviewer found when they reviewed one
subject (a service, repository, or release) against a pack: met, not met, not
applicable, or excepted. This module checks that the record is consistent with the
pack's own policy: every rule exists, met rules cite evidence, and each exception is
allowed, carries the fields the pack requires, and sits inside the pack's window.

It never inspects the subject itself. Whether open rules should block a merge is the
gate's decision, made from the report (ADR-0004).
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from appsec_rules_pack.validator import (
    ValidationIssue,
    _load_rules_payload,
    _schema_issues,
    _sensitive_value_issues,
    validate_rules_payload,
)

RECORD_SCHEMA = "review-record.schema.json"
OPEN_STATUSES = frozenset(("not-met", "unreviewed"))
# A rule left open or ruled out needs a reason a later reader can check.
JUSTIFIED_STATUSES = frozenset(("not-met", "not-applicable"))


@dataclass(frozen=True)
class RuleOutcome:
    """What the record says about one rule, with the rule's policy attributes."""

    rule_id: str
    title: str
    severity: str
    enforcement: str
    status: str
    evidence: tuple[str, ...] = ()
    notes: str | None = None
    exception: dict[str, str] | None = None
    # The record's own x- fields for this rule, passed through to the report unread.
    extensions: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReviewResult:
    """Outcome of checking a review record against a rules pack."""

    pack_id: str | None
    pack_version: str | None
    review: dict[str, Any] | None
    as_of: dt.date
    outcomes: tuple[RuleOutcome, ...]
    issues: tuple[ValidationIssue, ...]

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.level == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.level == "warning")

    @property
    def ok(self) -> bool:
        return self.error_count == 0

    def status_counts(self) -> Counter[str]:
        return Counter(outcome.status for outcome in self.outcomes)

    def open_counts(self, attribute: str) -> dict[str, int]:
        counts = Counter(
            getattr(outcome, attribute)
            for outcome in self.outcomes
            if outcome.status in OPEN_STATUSES
        )
        return dict(sorted(counts.items()))


def review_files(pack_path: Path, record_path: Path, *, as_of: dt.date) -> ReviewResult:
    """Load a rules pack and a review record from disk and check one against the other."""

    pack, pack_load_issues = _load_rules_payload(pack_path)
    record, record_load_issues = _load_rules_payload(record_path)
    if pack_load_issues:
        return _failed(as_of, [_pack_invalid(len(pack_load_issues))])
    if record_load_issues:
        return _failed(as_of, list(record_load_issues), pack)
    return review_payloads(pack, record, as_of=as_of)


def review_payloads(pack: Any, record: Any, *, as_of: dt.date) -> ReviewResult:
    """Check an in-memory review record against an in-memory rules pack."""

    pack_result = validate_rules_payload(pack)
    if not pack_result.ok:
        return _failed(as_of, [_pack_invalid(pack_result.error_count)])

    record = _dates_to_strings(record)
    schema_issues = _schema_issues(record, RECORD_SCHEMA)
    if schema_issues:
        return _failed(as_of, _with_result_rule_ids(schema_issues, record), pack)

    issues: list[ValidationIssue] = list(_sensitive_value_issues(record))
    review = record["review"]
    review_date = _parse_date(review["date"], ("review", "date"), issues)

    pack_meta = pack["pack"]
    if review["pack"] != pack_meta["id"]:
        issues.append(
            ValidationIssue(
                level="error",
                message=(
                    f"record is for pack {review['pack']!r}, but the rules pack is "
                    f"{pack_meta['id']!r}"
                ),
                path=("review", "pack"),
                code="review-pack-mismatch",
            )
        )
    if "pack_version" in review and review["pack_version"] != pack_meta["version"]:
        issues.append(
            ValidationIssue(
                level="warning",
                message=(
                    f"record was made against pack version {review['pack_version']!r}; "
                    f"the rules pack is version {pack_meta['version']!r}"
                ),
                path=("review", "pack_version"),
                code="review-pack-version-mismatch",
            )
        )

    rules = {rule["id"]: rule for rule in pack["rules"]}
    outcomes: list[RuleOutcome] = []
    reviewed: set[str] = set()

    for index, entry in enumerate(record["results"]):
        path = ("results", index)
        rule_id = entry["rule"]
        rule = rules.get(rule_id)
        if rule is None:
            issues.append(
                ValidationIssue(
                    level="error",
                    message=f"rule {rule_id!r} is not in pack {pack_meta['id']!r}",
                    path=(*path, "rule"),
                    code="review-unknown-rule",
                    rule_id=rule_id,
                )
            )
            continue
        if rule_id in reviewed:
            issues.append(
                ValidationIssue(
                    level="error",
                    message=f"rule {rule_id!r} has more than one result",
                    path=(*path, "rule"),
                    code="review-duplicate-result",
                    rule_id=rule_id,
                )
            )
            continue
        reviewed.add(rule_id)

        if rule["status"] != "enabled":
            issues.append(
                ValidationIssue(
                    level="warning",
                    message=f"rule {rule_id!r} is {rule['status']} in the pack",
                    path=(*path, "rule"),
                    code="review-rule-not-enabled",
                    rule_id=rule_id,
                )
            )

        issues.extend(_entry_issues(entry, rule, path, review_date, as_of))
        outcomes.append(
            RuleOutcome(
                rule_id=rule_id,
                title=rule["title"],
                severity=rule["severity"],
                enforcement=rule["enforcement"],
                status=entry["status"],
                evidence=tuple(entry.get("evidence", ())),
                notes=entry.get("notes"),
                exception=entry.get("exception"),
                extensions={key: value for key, value in entry.items() if key.startswith("x-")},
            )
        )

    for rule_id, rule in rules.items():
        if rule["status"] != "enabled" or rule_id in reviewed:
            continue
        issues.append(
            ValidationIssue(
                level="warning",
                message=f"enabled rule {rule_id!r} has no result in the record",
                path=("results",),
                code="review-missing-result",
                rule_id=rule_id,
            )
        )
        outcomes.append(
            RuleOutcome(
                rule_id=rule_id,
                title=rule["title"],
                severity=rule["severity"],
                enforcement=rule["enforcement"],
                status="unreviewed",
            )
        )

    # Report rules in pack order, whatever order the record lists them in.
    position = {rule_id: index for index, rule_id in enumerate(rules)}
    outcomes.sort(key=lambda outcome: position[outcome.rule_id])
    return ReviewResult(
        pack_id=pack_meta["id"],
        pack_version=pack_meta["version"],
        review=review,
        as_of=as_of,
        outcomes=tuple(outcomes),
        issues=tuple(issues),
    )


def _entry_issues(
    entry: dict[str, Any],
    rule: dict[str, Any],
    path: tuple[str | int, ...],
    review_date: dt.date | None,
    as_of: dt.date,
) -> list[ValidationIssue]:
    rule_id = rule["id"]
    status = entry["status"]
    exception = entry.get("exception")
    issues: list[ValidationIssue] = []

    def issue(code: str, message: str, *suffix: str) -> None:
        issues.append(
            ValidationIssue(
                level="error",
                message=message,
                path=(*path, *suffix),
                code=code,
                rule_id=rule_id,
            )
        )

    if status == "met" and not entry.get("evidence"):
        issue("review-evidence-missing", "a met rule must cite at least one piece of evidence")

    if status in JUSTIFIED_STATUSES and "notes" not in entry:
        issues.append(
            ValidationIssue(
                level="warning",
                message=f"a {status} rule needs notes saying why",
                path=path,
                code="review-justification-missing",
                rule_id=rule_id,
            )
        )

    if status != "excepted":
        if exception is not None:
            issue(
                "review-exception-unexpected",
                f"an exception is only valid with status 'excepted', not {status!r}",
                "exception",
            )
        return issues

    if exception is None:
        issue("review-exception-missing", "an excepted rule needs an exception block")
        return issues

    policy = rule["exceptions"]
    if not policy["allowed"]:
        issue(
            "exception-not-allowed",
            f"the pack does not allow exceptions to {rule_id}",
            "exception",
        )
        return issues

    missing = [field for field in policy["required_fields"] if field not in exception]
    if missing:
        issue(
            "exception-field-missing",
            "the pack requires these exception fields: " + ", ".join(missing),
            "exception",
        )

    expires = _parse_date(exception["expires_at"], (*path, "exception", "expires_at"), issues)
    if "granted_at" in exception:
        granted = _parse_date(exception["granted_at"], (*path, "exception", "granted_at"), issues)
    else:
        granted = review_date
    if expires is None:
        return issues

    if expires <= as_of:
        issue(
            "exception-expired",
            f"the exception expired on {expires.isoformat()}",
            "exception",
            "expires_at",
        )
    if granted is not None:
        window = (expires - granted).days
        if window <= 0:
            issue(
                "exception-dates-invalid",
                "the exception expires on or before the day it was granted",
                "exception",
                "expires_at",
            )
        elif window > policy["max_days"]:
            issue(
                "exception-window-exceeded",
                f"the exception runs {window} days; the pack allows at most "
                f"{policy['max_days']} for {rule_id}",
                "exception",
                "expires_at",
            )
    return issues


def _parse_date(
    value: str, path: tuple[str | int, ...], issues: list[ValidationIssue]
) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        issues.append(
            ValidationIssue(
                level="error",
                message="value is not a valid calendar date",
                path=path,
                code="review-date-invalid",
            )
        )
        return None


def _dates_to_strings(value: Any) -> Any:
    """Turn YAML dates back into the ISO strings the record schema expects.

    YAML reads an unquoted 2026-10-05 as a date. Writing it quoted or not should not
    matter to the author. A timestamp keeps its time part, so it still fails the
    date pattern instead of being truncated silently.
    """

    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _dates_to_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dates_to_strings(item) for item in value]
    return value


def _with_result_rule_ids(issues: list[ValidationIssue], record: Any) -> list[ValidationIssue]:
    results = record.get("results") if isinstance(record, dict) else None
    if not isinstance(results, list):
        return issues

    attributed = []
    for issue in issues:
        path = issue.path
        if len(path) >= 2 and path[0] == "results" and isinstance(path[1], int):
            entry = results[path[1]] if path[1] < len(results) else None
            rule_id = entry.get("rule") if isinstance(entry, dict) else None
            if isinstance(rule_id, str):
                issue = replace(issue, rule_id=rule_id)
        attributed.append(issue)
    return attributed


def _pack_invalid(error_count: int) -> ValidationIssue:
    noun = "error" if error_count == 1 else "errors"
    return ValidationIssue(
        level="error",
        message=(
            f"the rules pack has {error_count} validation {noun}; "
            "run `appsec-rules validate` on it first"
        ),
        code="review-pack-invalid",
    )


def _failed(as_of: dt.date, issues: list[ValidationIssue], pack: Any = None) -> ReviewResult:
    meta = pack.get("pack") if isinstance(pack, dict) else None
    meta = meta if isinstance(meta, dict) else {}
    pack_id = meta.get("id")
    pack_version = meta.get("version")
    return ReviewResult(
        pack_id=pack_id if isinstance(pack_id, str) else None,
        pack_version=pack_version if isinstance(pack_version, str) else None,
        review=None,
        as_of=as_of,
        outcomes=(),
        issues=tuple(issues),
    )
