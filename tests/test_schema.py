"""Tests for schema identity and versioning metadata."""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA_PATH = Path("src/appsec_rules_pack/schemas/appsec-rule.schema.json")


def test_schema_id_is_canonical_and_not_placeholder() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema_id = schema["$id"]

    assert "example.invalid" not in schema_id
    assert schema_id.startswith(
        "https://raw.githubusercontent.com/lucashgrifoni/AppSec-Rules-Pack/"
    )
    assert schema_id.endswith("/appsec-rule.schema.json")


def test_schema_documents_versioning_policy() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema.get("$comment", "").strip()
