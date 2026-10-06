"""Derive a machine-readable index from rules pack files.

This module only *reads and derives* metadata from a rules pack. It never executes
rules, scans code, or emits findings/SARIF, so it preserves the engine-agnostic
boundary of the validator (see ADR-0001).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from appsec_rules_pack.loader import load_yaml_file

INDEX_SCHEMA = "appsec-rules-index/v1"

# Per-rule fields copied into the index. Derivation only: no rule body, match
# logic, examples, or evidence snippets are executed or expanded.
_RULE_FIELDS = (
    "id",
    "title",
    "severity",
    "category",
    "status",
    "enforcement",
    "targets",
    "mappings",
    "exceptions",
    "deprecation",
)
_PACK_FIELDS = ("id", "name", "version")


def _pack_summary(payload: Any) -> dict[str, Any]:
    pack = payload.get("pack") if isinstance(payload, dict) else None
    if not isinstance(pack, dict):
        return {}
    return {field: pack[field] for field in _PACK_FIELDS if field in pack}


def _rule_summary(rule: Any) -> dict[str, Any]:
    if not isinstance(rule, dict):
        return {}
    return {field: rule[field] for field in _RULE_FIELDS if field in rule}


def build_pack_index(payload: Any) -> dict[str, Any]:
    """Build the index entry for a single rules pack payload."""

    rules = payload.get("rules") if isinstance(payload, dict) else None
    rule_entries = [_rule_summary(rule) for rule in rules] if isinstance(rules, list) else []
    return {"pack": _pack_summary(payload), "rules": rule_entries}


def build_index(payloads: list[Any]) -> dict[str, Any]:
    """Build the full index document from one or more pack payloads."""

    return {
        "schema": INDEX_SCHEMA,
        "packs": [build_pack_index(payload) for payload in payloads],
    }


def build_index_from_files(paths: list[Path]) -> dict[str, Any]:
    """Load each YAML file and derive the index, preserving the given order."""

    return build_index([load_yaml_file(path) for path in paths])
