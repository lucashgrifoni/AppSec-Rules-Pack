"""Validation logic for AppSec rules pack YAML files."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import jsonschema
import yaml

from appsec_rules_pack.loader import load_yaml_file

IssueLevel = Literal["error", "warning"]
IssuePath = tuple[str | int, ...]
StringItem = tuple[IssuePath, str]

MAX_EXCEPTION_DAYS = 90
REQUIRED_EXCEPTION_FIELDS = ("owner", "justification", "expires_at")

# Expected identifier formats for framework mappings. References:
#   OWASP API Security Top 10 2023 -> API1:2023 .. API10:2023
#   CWE -> CWE-<number>
#   NIST SSDF SP 800-218 -> practices PO/PS/PW/RV with optional task suffix
#   OWASP ASVS -> chapter/section dotted V-notation
MAPPING_ID_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "owasp_asvs": (
        re.compile(r"^V\d+(\.\d+){1,2}$"),
        "expected ASVS V-notation such as V5.3 or V5.3.1",
    ),
    "owasp_api_top_10_2023": (
        re.compile(r"^API([1-9]|10):2023$"),
        "expected an OWASP API Top 10 2023 id such as API1:2023",
    ),
    "cwe": (
        re.compile(r"^CWE-\d+$"),
        "expected a CWE id such as CWE-79",
    ),
    "nist_ssdf": (
        re.compile(r"^(PO|PS|PW|RV)\.\d+(\.\d+)?$"),
        "expected a NIST SSDF practice id such as PW.4 or PW.4.1",
    ),
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
)


@dataclass(frozen=True)
class ValidationIssue:
    """A structural or semantic validation issue."""

    level: IssueLevel
    message: str
    path: IssuePath = ()


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a rules pack."""

    issues: tuple[ValidationIssue, ...]
    rule_count: int

    @property
    def ok(self) -> bool:
        """Return true when no validation errors are present."""

        return self.error_count == 0

    @property
    def error_count(self) -> int:
        """Count validation errors."""

        return sum(1 for issue in self.issues if issue.level == "error")

    @property
    def warning_count(self) -> int:
        """Count validation warnings."""

        return sum(1 for issue in self.issues if issue.level == "warning")


def validate_rules_file(path: Path, *, require_examples: bool = False) -> ValidationResult:
    """Validate a rules pack YAML file."""

    payload, load_issues = _load_rules_payload(path)
    if load_issues:
        return ValidationResult(issues=load_issues, rule_count=0)

    return validate_rules_payload(payload, require_examples=require_examples)


def validate_rules_files(
    paths: Sequence[Path],
    *,
    require_examples: bool = False,
) -> tuple[tuple[Path, ValidationResult], ...]:
    """Validate multiple rules pack files, including cross-file duplicate rule IDs."""

    ordered_paths = tuple(sorted(paths, key=lambda item: str(item).lower()))
    if len(ordered_paths) <= 1:
        return tuple(
            (path, validate_rules_file(path, require_examples=require_examples))
            for path in ordered_paths
        )

    seen_ids: dict[str, tuple[Path, int]] = {}
    cross_file_issues: dict[Path, list[ValidationIssue]] = defaultdict(list)
    per_file_results: list[tuple[Path, ValidationResult]] = []

    for path in ordered_paths:
        payload, load_issues = _load_rules_payload(path)
        if load_issues:
            per_file_results.append((path, ValidationResult(issues=load_issues, rule_count=0)))
            continue

        result = validate_rules_payload(payload, require_examples=require_examples)
        for rule_id, rule_index in _iter_rule_ids(payload):
            if rule_id in seen_ids:
                first_path, first_index = seen_ids[rule_id]
                if first_path != path:
                    cross_file_issues[path].append(
                        ValidationIssue(
                            level="error",
                            message=(
                                f"duplicate rule id {rule_id!r}; first seen in "
                                f"{first_path.name} at rules.{first_index}"
                            ),
                            path=("rules", rule_index, "id"),
                        )
                    )
            else:
                seen_ids[rule_id] = (path, rule_index)

        merged_issues = result.issues + tuple(cross_file_issues[path])
        per_file_results.append(
            (
                path,
                ValidationResult(issues=merged_issues, rule_count=result.rule_count),
            )
        )

    return tuple(per_file_results)


def _load_rules_payload(path: Path) -> tuple[Any, tuple[ValidationIssue, ...]]:
    try:
        return load_yaml_file(path), ()
    except OSError as exc:
        return None, (
            ValidationIssue(
                level="error",
                message=f"could not read YAML file: {exc}",
            ),
        )
    except yaml.YAMLError as exc:
        return None, (
            ValidationIssue(
                level="error",
                message=_yaml_error_message(exc),
            ),
        )


def validate_rules_payload(payload: Any, *, require_examples: bool = False) -> ValidationResult:
    """Validate an in-memory rules pack payload."""

    issues: list[ValidationIssue] = []
    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)

    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        issues.append(
            ValidationIssue(
                level="error",
                message=_schema_issue_message(error),
                path=tuple(error.absolute_path),
            )
        )

    if isinstance(payload, dict):
        issues.extend(_semantic_issues(payload, require_examples=require_examples))

    return ValidationResult(
        issues=tuple(issues),
        rule_count=_rule_count(payload),
    )


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    schema_file = resources.files("appsec_rules_pack").joinpath("schemas/appsec-rule.schema.json")
    with schema_file.open("r", encoding="utf-8") as handle:
        schema = yaml.safe_load(handle)

    if not isinstance(schema, dict):
        raise TypeError("schema resource must contain a JSON object")

    jsonschema.Draft202012Validator.check_schema(schema)
    return schema


def _yaml_error_message(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None)
    mark = getattr(error, "problem_mark", None)

    location = ""
    if mark is not None:
        location = f" at line {mark.line + 1}, column {mark.column + 1}"

    if isinstance(problem, str) and problem:
        return f"could not parse YAML file{location}: {problem}"

    return f"could not parse YAML file{location}"


def _schema_issue_message(error: jsonschema.ValidationError) -> str:
    """Return a concise schema error without echoing untrusted input values."""

    if error.validator == "required" and isinstance(error.instance, dict):
        required_fields = error.validator_value
        missing_fields = [
            field
            for field in required_fields
            if isinstance(field, str) and field not in error.instance
        ]
        return _format_missing_fields(missing_fields)

    if error.validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed_fields = set(error.schema.get("properties", {}))
        unexpected_fields = sorted(
            str(field) for field in error.instance if field not in allowed_fields
        )
        return _format_unexpected_fields(unexpected_fields)

    if error.validator == "enum" and isinstance(error.validator_value, list):
        allowed_values = ", ".join(str(value) for value in error.validator_value)
        return f"value must be one of: {allowed_values}"

    if error.validator == "type":
        expected_type = error.validator_value
        if isinstance(expected_type, list):
            expected_type = " or ".join(str(value) for value in expected_type)
        return f"invalid type; expected {expected_type}"

    if error.validator == "pattern":
        return f"value does not match required pattern: {error.validator_value}"

    if error.validator == "minLength":
        return f"value is too short; minimum length is {error.validator_value}"

    if error.validator == "maxLength":
        return f"value is too long; maximum length is {error.validator_value}"

    if error.validator == "minItems":
        return f"array is too short; minimum items is {error.validator_value}"

    if error.validator == "uniqueItems":
        return "array items must be unique"

    if error.validator == "minimum":
        return f"value is below minimum {error.validator_value}"

    if error.validator == "maximum":
        return f"value is above maximum {error.validator_value}"

    return error.message


def _format_missing_fields(fields: list[str]) -> str:
    if len(fields) == 1:
        return f"missing required field {fields[0]!r}"
    return "missing required fields: " + ", ".join(repr(field) for field in fields)


def _format_unexpected_fields(fields: list[str]) -> str:
    if len(fields) == 1:
        return f"unexpected field {fields[0]!r} is not allowed"
    return "unexpected fields are not allowed: " + ", ".join(repr(field) for field in fields)


def _rule_count(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    rules = payload.get("rules")
    return len(rules) if isinstance(rules, list) else 0


def _semantic_issues(payload: dict[str, Any], *, require_examples: bool) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    rules = payload.get("rules")

    if isinstance(rules, list):
        issues.extend(_duplicate_id_issues(rules))
        issues.extend(_exception_issues(rules))
        issues.extend(_exception_consistency_issues(rules))
        issues.extend(_mapping_format_issues(rules))
        if require_examples:
            issues.extend(_missing_examples_issues(rules))

    issues.extend(_sensitive_value_issues(payload))
    return issues


def _iter_rule_ids(payload: Any) -> list[tuple[str, int]]:
    if not isinstance(payload, dict):
        return []

    rules = payload.get("rules")
    if not isinstance(rules, list):
        return []

    rule_ids: list[tuple[str, int]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            rule_ids.append((rule_id, index))

    return rule_ids


def _duplicate_id_issues(rules: list[Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    seen: dict[str, int] = {}

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str):
            continue
        if rule_id in seen:
            issues.append(
                ValidationIssue(
                    level="error",
                    message=f"duplicate rule id {rule_id!r}; first seen at rules.{seen[rule_id]}",
                    path=("rules", index, "id"),
                )
            )
        else:
            seen[rule_id] = index

    return issues


def _exception_issues(rules: list[Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        exceptions = rule.get("exceptions")
        if not isinstance(exceptions, dict):
            continue
        max_days = exceptions.get("max_days")
        if isinstance(max_days, int) and max_days > MAX_EXCEPTION_DAYS:
            issues.append(
                ValidationIssue(
                    level="warning",
                    message=(
                        f"exception window is {max_days} days; "
                        f"default review limit is {MAX_EXCEPTION_DAYS} days"
                    ),
                    path=("rules", index, "exceptions", "max_days"),
                )
            )

    return issues


def _exception_consistency_issues(rules: list[Any]) -> list[ValidationIssue]:
    """Flag exception metadata that contradicts its own allowed/required fields."""

    issues: list[ValidationIssue] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        exceptions = rule.get("exceptions")
        if not isinstance(exceptions, dict):
            continue

        allowed = exceptions.get("allowed")
        max_days = exceptions.get("max_days")
        required_fields = exceptions.get("required_fields")
        field_set = set(required_fields) if isinstance(required_fields, list) else set()

        if allowed is False:
            if isinstance(max_days, int) and max_days > 0:
                issues.append(
                    ValidationIssue(
                        level="error",
                        message=(
                            "exception is not allowed but defines a non-zero "
                            f"max_days of {max_days}"
                        ),
                        path=("rules", index, "exceptions", "max_days"),
                    )
                )
            if field_set:
                issues.append(
                    ValidationIssue(
                        level="error",
                        message="exception is not allowed but declares required_fields",
                        path=("rules", index, "exceptions", "required_fields"),
                    )
                )
        elif allowed is True:
            missing = [field for field in REQUIRED_EXCEPTION_FIELDS if field not in field_set]
            if missing:
                issues.append(
                    ValidationIssue(
                        level="warning",
                        message=("allowed exception should require: " + ", ".join(missing)),
                        path=("rules", index, "exceptions", "required_fields"),
                    )
                )
            if isinstance(max_days, int) and max_days == 0:
                issues.append(
                    ValidationIssue(
                        level="warning",
                        message="allowed exception has a zero-day window",
                        path=("rules", index, "exceptions", "max_days"),
                    )
                )

    return issues


def _mapping_format_issues(rules: list[Any]) -> list[ValidationIssue]:
    """Warn when framework mapping identifiers do not match expected formats."""

    issues: list[ValidationIssue] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        mappings = rule.get("mappings")
        if not isinstance(mappings, dict):
            continue

        for field, (pattern, hint) in MAPPING_ID_PATTERNS.items():
            values = mappings.get(field)
            if not isinstance(values, list):
                continue
            for value_index, value in enumerate(values):
                if isinstance(value, str) and not pattern.match(value):
                    issues.append(
                        ValidationIssue(
                            level="warning",
                            message=f"mapping id {value!r} is malformed; {hint}",
                            path=("rules", index, "mappings", field, value_index),
                        )
                    )

    return issues


def _missing_examples_issues(rules: list[Any]) -> list[ValidationIssue]:
    """Warn when an enabled rule does not ship compliant and violating examples.

    The schema enforces the shape of an ``examples`` block when it is present;
    this opt-in check (``--require-examples``) flags enabled rules that omit it.
    """

    issues: list[ValidationIssue] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("status") != "enabled":
            continue
        if "examples" not in rule:
            issues.append(
                ValidationIssue(
                    level="warning",
                    message="enabled rule should include compliant and violating examples",
                    path=("rules", index, "examples"),
                )
            )

    return issues


def _sensitive_value_issues(payload: Any) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    for path, value in _walk_strings(payload):
        # Rule examples deliberately contain insecure anti-pattern snippets
        # (including hard-coded-secret demonstrations), so they are exempt.
        if "examples" in path:
            continue
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            issues.append(
                ValidationIssue(
                    level="error",
                    message="possible sensitive value detected; remove secrets from rule content",
                    path=path,
                )
            )

    return issues


def _walk_strings(value: Any, path: IssuePath = ()) -> list[StringItem]:
    if isinstance(value, str):
        return [(path, value)]

    if isinstance(value, dict):
        strings: list[StringItem] = []
        for key, item in value.items():
            strings.extend(_walk_strings(item, (*path, str(key))))
        return strings

    if isinstance(value, list):
        strings = []
        for index, item in enumerate(value):
            strings.extend(_walk_strings(item, (*path, index)))
        return strings

    return []
