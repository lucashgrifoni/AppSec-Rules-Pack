"""docs/rule-fields.md must name every field the rule schema defines."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "src/appsec_rules_pack/schemas/appsec-rule.schema.json").read_text(encoding="utf-8")
)
DOC = (ROOT / "docs" / "rule-fields.md").read_text(encoding="utf-8")


def _field_names(node: dict, defs: dict) -> set[str]:
    """Every property name reachable from a schema node, following local $refs."""

    names: set[str] = set()
    stack = [node]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if "$ref" in current:
            stack.append(defs[current["$ref"].rsplit("/", 1)[-1]])
        for name, child in current.get("properties", {}).items():
            names.add(name)
            stack.append(child)
        if isinstance(current.get("items"), dict):
            stack.append(current["items"])
    return names


def test_every_schema_field_is_documented() -> None:
    fields = _field_names(SCHEMA, SCHEMA["$defs"]) - {"pack", "rules"}

    missing = sorted(name for name in fields if f"`{name}`" not in DOC)

    assert len(fields) > 30
    assert missing == []


def test_every_enum_value_is_documented() -> None:
    enums: set[str] = set()
    stack: list = [SCHEMA]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            enums.update(str(value) for value in node.get("enum", []))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)

    missing = sorted(value for value in enums if f"`{value}`" not in DOC)

    assert missing == []
