"""Derive a framework-mapping coverage report from rules pack files.

Derivation only: this reads mapping metadata and summarizes coverage. It never
executes rules, scans code, or emits findings, so it preserves the engine-agnostic
boundary of the validator (see ADR-0001).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from appsec_rules_pack.loader import load_yaml_file

COVERAGE_SCHEMA = "appsec-rules-coverage/v1"

# Mapping frameworks reported. owasp_top_10_2025 and owasp_api_top_10_2023 are optional
# in the schema, so their coverage is the informative one; ASVS, CWE, and NIST SSDF are
# required and should read 100%.
_FRAMEWORKS = (
    "owasp_asvs",
    "owasp_api_top_10_2023",
    "owasp_top_10_2025",
    "cwe",
    "nist_ssdf",
)


def _rules(payload: Any) -> list[dict[str, Any]]:
    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        return []
    return [rule for rule in rules if isinstance(rule, dict)]


def _has_mapping(rule: dict[str, Any], framework: str) -> bool:
    mappings = rule.get("mappings")
    if not isinstance(mappings, dict):
        return False
    values = mappings.get(framework)
    return isinstance(values, list) and len(values) > 0


def build_coverage(payloads: list[Any]) -> dict[str, Any]:
    """Build a coverage report across one or more pack payloads."""

    rules: list[dict[str, Any]] = []
    for payload in payloads:
        rules.extend(_rules(payload))

    total = len(rules)
    frameworks: dict[str, Any] = {}
    for framework in _FRAMEWORKS:
        unmapped = [rule for rule in rules if not _has_mapping(rule, framework)]
        # A rule without a string id still counts as unmapped; it is only left out of
        # the `missing` list, which names rules by id.
        missing = [rule["id"] for rule in unmapped if isinstance(rule.get("id"), str)]
        frameworks[framework] = {
            "covered": total - len(unmapped),
            "total": total,
            "missing": missing,
        }

    categories = Counter(
        rule["category"] for rule in rules if isinstance(rule.get("category"), str)
    )

    return {
        "schema": COVERAGE_SCHEMA,
        "rules": total,
        "frameworks": frameworks,
        "categories": dict(sorted(categories.items())),
    }


def build_coverage_from_files(paths: list[Path]) -> dict[str, Any]:
    """Load each YAML file and derive the coverage report."""

    return build_coverage([load_yaml_file(path) for path in paths])
