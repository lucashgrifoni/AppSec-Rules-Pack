"""Derive a reference Semgrep scaffold from the rules pack.

IMPORTANT: this is derivation only and produces a NON-RUNNABLE scaffold. The
engine-agnostic review rules carry no detection patterns (see ADR-0001), so every
emitted Semgrep rule uses a placeholder ``pattern-regex`` that a consumer must
replace with a real detection before use. This keeps an interoperability path in
``exports/`` without turning the validator into a scanning engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from appsec_rules_pack.loader import load_yaml_file

PATTERN_PLACEHOLDER = "TODO-REPLACE-WITH-DETECTION-PATTERN"

_SEVERITY_MAP = {
    "critical": "ERROR",
    "high": "ERROR",
    "medium": "WARNING",
    "low": "INFO",
}

_METADATA_FIELDS = (
    ("cwe", "cwe"),
    ("owasp-asvs", "owasp_asvs"),
    ("owasp-api-top-10-2023", "owasp_api_top_10_2023"),
    ("owasp-top-10-2025", "owasp_top_10_2025"),
    ("nist-ssdf", "nist_ssdf"),
)


def _semgrep_rule(rule: dict[str, Any]) -> dict[str, Any]:
    mappings = rule.get("mappings") if isinstance(rule.get("mappings"), dict) else {}
    # Exports skip validation, so a malformed pack may carry a list or mapping here.
    severity = rule.get("severity") if isinstance(rule.get("severity"), str) else None
    metadata: dict[str, Any] = {
        "source-rule": rule.get("id"),
        "category": rule.get("category"),
        "status": rule.get("status"),
        "scaffold": "Non-runnable: replace pattern-regex with a real detection before use.",
    }
    for out_key, field in _METADATA_FIELDS:
        value = mappings.get(field)
        if isinstance(value, list) and value:
            metadata[out_key] = list(value)

    return {
        "id": rule.get("id"),
        "message": f"{rule.get('title')} - {rule.get('description')}",
        "severity": _SEVERITY_MAP.get(severity, "WARNING"),
        "languages": ["generic"],
        "metadata": metadata,
        "pattern-regex": PATTERN_PLACEHOLDER,
    }


def build_semgrep_scaffold(payloads: list[Any]) -> dict[str, Any]:
    """Build a non-runnable Semgrep scaffold from one or more pack payloads.

    Only ``enabled`` rules are emitted; disabled, draft, and deprecated rules are
    skipped because they are not active detections.
    """

    rules: list[dict[str, Any]] = []
    for payload in payloads:
        pack_rules = payload.get("rules") if isinstance(payload, dict) else None
        if not isinstance(pack_rules, list):
            continue
        rules.extend(
            _semgrep_rule(rule)
            for rule in pack_rules
            if isinstance(rule, dict) and rule.get("status") == "enabled"
        )
    return {"rules": rules}


def build_semgrep_scaffold_from_files(paths: list[Path]) -> dict[str, Any]:
    """Load each YAML file and derive the Semgrep scaffold."""

    return build_semgrep_scaffold([load_yaml_file(path) for path in paths])
