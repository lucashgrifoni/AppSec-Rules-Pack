"""Validation logic for AppSec rules pack YAML files."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import jsonschema
import yaml

from appsec_rules_pack.loader import RulesFileTooLargeError, load_yaml_file

IssueLevel = Literal["error", "warning"]
IssuePath = tuple[str | int, ...]
StringItem = tuple[IssuePath, str]

MAX_EXCEPTION_DAYS = 90
# Highest rules-pack schema version this validator understands (pack.schema_version).
SUPPORTED_SCHEMA_VERSION = (0, 5)
REQUIRED_EXCEPTION_FIELDS = ("owner", "justification", "expires_at")
RULE_SCHEMA = "appsec-rule.schema.json"

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
    "owasp_top_10_2025": (
        re.compile(r"^A(0[1-9]|10):2025$"),
        "expected an OWASP Top 10:2025 id such as A01:2025",
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
# Shapes of real credential material. These are checked everywhere, including inside
# rule examples, because no example needs a working key to make its point.
KEY_MATERIAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"\bsk_live_[0-9A-Za-z]{16,}"),
)
# Basic patterns, not a secret scanner. All are linear: no nested quantifiers.
SECRET_PATTERNS = (
    *KEY_MATERIAL_PATTERNS,
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
)


@dataclass(frozen=True)
class ValidationIssue:
    """A structural or semantic validation issue.

    ``code`` is a stable, machine-readable identifier for the kind of issue; messages
    may be reworded between releases, codes may not (see VERSIONING.md). ``rule_id`` is
    the id of the rule the issue belongs to, when there is one.
    """

    level: IssueLevel
    message: str
    path: IssuePath = ()
    code: str = "invalid"
    rule_id: str | None = None


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
                            code="duplicate-rule-id",
                            rule_id=rule_id,
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
                code="file-unreadable",
            ),
        )
    except UnicodeDecodeError as exc:
        return None, (
            ValidationIssue(
                level="error",
                message=f"could not decode YAML file as UTF-8: {exc.reason}",
                code="file-not-utf8",
            ),
        )
    except RecursionError:
        return None, (
            ValidationIssue(
                level="error",
                message="could not parse YAML file: nesting depth exceeds the supported limit",
                code="yaml-too-deep",
            ),
        )
    except RulesFileTooLargeError as exc:
        return None, (
            ValidationIssue(
                level="error",
                message=f"could not read YAML file: {exc.problem}",
                code="file-too-large",
            ),
        )
    except yaml.YAMLError as exc:
        return None, (
            ValidationIssue(
                level="error",
                message=_yaml_error_message(exc),
                code="yaml-invalid",
            ),
        )


def validate_rules_payload(payload: Any, *, require_examples: bool = False) -> ValidationResult:
    """Validate an in-memory rules pack payload."""

    issues = _schema_issues(payload, RULE_SCHEMA)

    if isinstance(payload, dict):
        issues.extend(_semantic_issues(payload, require_examples=require_examples))

    return ValidationResult(
        issues=tuple(_with_rule_ids(issues, payload)),
        rule_count=_rule_count(payload),
    )


def _schema_issues(payload: Any, schema_name: str) -> list[ValidationIssue]:
    """Check a payload against one of the packaged schemas."""

    validator = jsonschema.Draft202012Validator(_load_schema(schema_name))
    issues: list[ValidationIssue] = []

    # jsonschema reports one error per missing required property, but the rendered
    # message names every missing field at that location. Three missing fields therefore
    # produced three byte-identical lines, and inflated the reported error count. An
    # identical level+path+message carries no extra information, so it is dropped.
    seen_schema_issues: set[tuple[str, tuple[Any, ...]]] = set()
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        message = _schema_issue_message(error)
        path = tuple(error.absolute_path)
        if (message, path) in seen_schema_issues:
            continue
        seen_schema_issues.add((message, path))
        issues.append(
            ValidationIssue(
                level="error",
                message=message,
                path=path,
                code=_SCHEMA_ISSUE_CODES.get(str(error.validator), "schema-invalid"),
            )
        )
    return issues


_SCHEMA_ISSUE_CODES = {
    "required": "schema-missing-field",
    "additionalProperties": "schema-unexpected-field",
    "enum": "schema-enum",
    "type": "schema-type",
    "pattern": "schema-pattern",
    "minLength": "schema-length",
    "maxLength": "schema-length",
    "minItems": "schema-min-items",
    "uniqueItems": "schema-unique-items",
    "minimum": "schema-range",
    "maximum": "schema-range",
}


def _with_rule_ids(issues: list[ValidationIssue], payload: Any) -> list[ValidationIssue]:
    """Attach the owning rule's id to every issue located under ``rules.<n>``."""

    rule_ids = dict((index, rule_id) for rule_id, index in _iter_rule_ids(payload))
    attributed: list[ValidationIssue] = []
    for issue in issues:
        path = issue.path
        if (
            issue.rule_id is None
            and len(path) >= 2
            and path[0] == "rules"
            and isinstance(path[1], int)
            and path[1] in rule_ids
        ):
            issue = replace(issue, rule_id=rule_ids[path[1]])
        attributed.append(issue)
    return attributed


@lru_cache(maxsize=4)
def _load_schema(name: str) -> dict[str, Any]:
    schema_file = resources.files("appsec_rules_pack").joinpath(f"schemas/{name}")
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
        allowed_patterns = [
            re.compile(pattern) for pattern in error.schema.get("patternProperties", {})
        ]
        unexpected_fields = sorted(
            _display_value(str(field))
            for field in error.instance
            if field not in allowed_fields
            and not any(pattern.search(str(field)) for pattern in allowed_patterns)
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


def _format_unexpected_fields(labels: list[str]) -> str:
    if len(labels) == 1:
        return f"unexpected field {labels[0]} is not allowed"
    return "unexpected fields are not allowed: " + ", ".join(labels)


def _display_value(value: str) -> str:
    """Quote an input value for a message, without echoing secrets or huge strings."""

    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        return "<redacted>"
    if len(value) > 60:
        value = value[:57] + "..."
    return repr(value)


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
        issues.extend(_deprecation_issues(rules))
        if require_examples:
            issues.extend(_missing_examples_issues(rules))

    issues.extend(_schema_version_issues(payload))
    issues.extend(_sensitive_value_issues(payload))
    return issues


def _schema_version_issues(payload: dict[str, Any]) -> list[ValidationIssue]:
    """Refuse a pack that targets a newer schema than this validator understands."""

    pack = payload.get("pack")
    declared = pack.get("schema_version") if isinstance(pack, dict) else None
    if not isinstance(declared, str):
        return []
    parts = declared.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return []  # the schema pattern reports the malformed value
    if (int(parts[0]), int(parts[1])) <= SUPPORTED_SCHEMA_VERSION:
        return []
    supported = ".".join(str(part) for part in SUPPORTED_SCHEMA_VERSION)
    return [
        ValidationIssue(
            level="error",
            message=(
                f"pack targets schema version {declared}; this validator supports up to "
                f"{supported}. Upgrade appsec-rules-pack."
            ),
            path=("pack", "schema_version"),
            code="schema-version-unsupported",
        )
    ]


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
                    code="duplicate-rule-id",
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
                    code="exception-window-too-long",
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
        field_set = (
            {field for field in required_fields if isinstance(field, str)}
            if isinstance(required_fields, list)
            else set()
        )

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
                        code="exception-disallowed-window",
                    )
                )
            if field_set:
                issues.append(
                    ValidationIssue(
                        level="error",
                        message="exception is not allowed but declares required_fields",
                        path=("rules", index, "exceptions", "required_fields"),
                        code="exception-disallowed-fields",
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
                        code="exception-missing-fields",
                    )
                )
            if isinstance(max_days, int) and max_days == 0:
                issues.append(
                    ValidationIssue(
                        level="warning",
                        message="allowed exception has a zero-day window",
                        path=("rules", index, "exceptions", "max_days"),
                        code="exception-zero-window",
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
                            message=f"mapping id {_display_value(value)} is malformed; {hint}",
                            path=("rules", index, "mappings", field, value_index),
                            code="mapping-id-malformed",
                        )
                    )

    return issues


def _deprecation_issues(rules: list[Any]) -> list[ValidationIssue]:
    """Flag inconsistencies between rule status and deprecation metadata."""

    issues: list[ValidationIssue] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        status = rule.get("status")
        has_block = isinstance(rule.get("deprecation"), dict)
        if status == "deprecated" and not has_block:
            issues.append(
                ValidationIssue(
                    level="warning",
                    message="deprecated rule should document a deprecation reason",
                    path=("rules", index, "deprecation"),
                    code="deprecation-missing",
                )
            )
        elif has_block and status != "deprecated":
            issues.append(
                ValidationIssue(
                    level="warning",
                    message="deprecation metadata present but status is not 'deprecated'",
                    path=("rules", index, "status"),
                    code="deprecation-status-mismatch",
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
                    code="examples-missing",
                )
            )

    return issues


def _sensitive_value_issues(payload: Any) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    for path, value in _walk_strings(payload):
        if "examples" in path:
            # Rule examples deliberately show insecure snippets such as a hard-coded
            # password, so the generic keyword pattern is skipped there. Real key
            # material is still flagged, as a warning.
            if any(pattern.search(value) for pattern in KEY_MATERIAL_PATTERNS):
                issues.append(
                    ValidationIssue(
                        level="warning",
                        message=(
                            "example contains what looks like real key material; "
                            "use an obvious placeholder instead"
                        ),
                        path=path,
                        code="example-key-material",
                    )
                )
            continue
        if any(pattern.search(value) for pattern in SECRET_PATTERNS):
            issues.append(
                ValidationIssue(
                    level="error",
                    message="possible sensitive value detected; remove secrets from rule content",
                    path=path,
                    code="sensitive-value",
                )
            )

    return issues


def _walk_strings(value: Any) -> list[StringItem]:
    """Collect every string in the payload, mapping keys included, in document order.

    Iterative, so payload depth cannot exhaust the interpreter stack, and each container
    is visited once, so a self-referencing payload cannot loop.
    """

    strings: list[StringItem] = []
    seen: set[int] = set()
    stack: list[tuple[IssuePath, Any]] = [((), value)]

    while stack:
        path, node = stack.pop()
        if isinstance(node, str):
            strings.append((path, node))
            continue
        if not isinstance(node, dict | list) or id(node) in seen:
            continue
        seen.add(id(node))

        children: list[tuple[IssuePath, Any]] = []
        if isinstance(node, dict):
            for key, item in node.items():
                child_path = (*path, str(key))
                children.append((child_path, key))
                children.append((child_path, item))
        else:
            children.extend(((*path, index), item) for index, item in enumerate(node))
        stack.extend(reversed(children))

    return strings
