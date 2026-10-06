"""Derive a SARIF rule-catalog export from the rules pack.

Derivation only: this declares the pack's rules as SARIF reportingDescriptors
(``tool.driver.rules``) with an EMPTY ``results`` array. The pack does not execute or
scan code (see ADR-0001), so it produces no findings; this export lets SARIF-aware
tools ingest the rule catalog and its metadata, not scan results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from appsec_rules_pack.loader import load_yaml_file

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "AppSec Rules Pack"
INFORMATION_URI = "https://github.com/lucashgrifoni/AppSec-Rules-Pack"

# SARIF result levels and GitHub code-scanning security-severity bands.
_LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}

_PROPERTY_FIELDS = (
    ("cwe", "cwe"),
    ("owasp-asvs", "owasp_asvs"),
    ("owasp-api-top-10-2023", "owasp_api_top_10_2023"),
    ("owasp-top-10-2025", "owasp_top_10_2025"),
    ("owasp-llm-top-10-2025", "owasp_llm_top_10_2025"),
    ("nist-ssdf", "nist_ssdf"),
)


def _descriptor(rule: dict[str, Any]) -> dict[str, Any]:
    mappings = rule.get("mappings") if isinstance(rule.get("mappings"), dict) else {}
    # Exports skip validation, so a malformed pack may carry a list or mapping here.
    severity = rule.get("severity") if isinstance(rule.get("severity"), str) else None

    tags = ["security"]
    if isinstance(rule.get("category"), str):
        tags.append(rule["category"])
    cwes = mappings.get("cwe")
    if isinstance(cwes, list):
        tags.extend(cwe for cwe in cwes if isinstance(cwe, str))

    properties: dict[str, Any] = {"tags": tags}
    if severity in _SECURITY_SEVERITY:
        properties["security-severity"] = _SECURITY_SEVERITY[severity]
    for out_key, field in _PROPERTY_FIELDS:
        value = mappings.get(field)
        if isinstance(value, list) and value:
            properties[out_key] = list(value)

    return {
        "id": rule.get("id"),
        "name": rule.get("id"),
        "shortDescription": {"text": rule.get("title")},
        "fullDescription": {"text": rule.get("description")},
        "helpUri": INFORMATION_URI,
        "defaultConfiguration": {"level": _LEVEL_MAP.get(severity, "warning")},
        "properties": properties,
    }


def _tool_version(payloads: list[Any]) -> str:
    for payload in payloads:
        pack = payload.get("pack") if isinstance(payload, dict) else None
        if isinstance(pack, dict) and isinstance(pack.get("version"), str):
            return pack["version"]
    return "0.0.0"


def build_sarif(payloads: list[Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 rule-catalog document (no results) from pack payloads."""

    descriptors: list[dict[str, Any]] = []
    for payload in payloads:
        rules = payload.get("rules") if isinstance(payload, dict) else None
        if not isinstance(rules, list):
            continue
        descriptors.extend(
            _descriptor(rule)
            for rule in rules
            if isinstance(rule, dict) and rule.get("status") == "enabled"
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFORMATION_URI,
                        "version": _tool_version(payloads),
                        "rules": descriptors,
                    }
                },
                "results": [],
            }
        ],
    }


def build_sarif_from_files(paths: list[Path]) -> dict[str, Any]:
    """Load each YAML file and derive the SARIF rule-catalog document."""

    return build_sarif([load_yaml_file(path) for path in paths])
