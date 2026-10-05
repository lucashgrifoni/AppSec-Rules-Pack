"""Tests for the machine-readable rule index exporter and the export CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.exporter import INDEX_SCHEMA, build_index, build_index_from_files
from appsec_rules_pack.loader import load_yaml_file

BASELINE_PATH = Path("rules/appsec-baseline.yaml")
INDEX_PATH = Path("exports/appsec-baseline.index.json")

runner = CliRunner()

_RULE_KEYS = {
    "id",
    "title",
    "severity",
    "category",
    "status",
    "enforcement",
    "targets",
    "mappings",
}


def test_build_index_derives_pack_and_rule_summaries() -> None:
    index = build_index_from_files([BASELINE_PATH])

    assert index["schema"] == INDEX_SCHEMA
    assert len(index["packs"]) == 1

    pack = index["packs"][0]
    assert pack["pack"] == {
        "id": "appsec-baseline",
        "name": "AppSec Baseline Rules Pack",
        "version": "0.4.0",
    }
    assert len(pack["rules"]) == 19

    first = pack["rules"][0]
    assert first["id"] == "APPSEC-AUTHZ-001"
    assert set(first) == _RULE_KEYS
    # Derivation only: rule body, examples, match logic, and evidence stay out.
    assert "examples" not in first
    assert "match" not in first
    assert "evidence" not in first


def test_index_rule_order_matches_pack() -> None:
    payload = load_yaml_file(BASELINE_PATH)
    expected_ids = [rule["id"] for rule in payload["rules"]]

    index = build_index_from_files([BASELINE_PATH])

    assert [rule["id"] for rule in index["packs"][0]["rules"]] == expected_ids


def test_committed_index_matches_current_pack() -> None:
    # Drift guard: the checked-in exports/ artifact must equal a fresh derivation.
    committed = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    derived = build_index_from_files([BASELINE_PATH])

    assert committed == derived


def test_cli_export_index_to_stdout() -> None:
    result = runner.invoke(app, ["export", "index", str(BASELINE_PATH)])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema"] == INDEX_SCHEMA
    assert len(payload["packs"][0]["rules"]) == 19


def test_cli_export_index_to_file(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "index.json"

    result = runner.invoke(app, ["export", "index", str(BASELINE_PATH), "--output", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["packs"][0]["pack"]["id"] == "appsec-baseline"


def test_cli_export_index_no_rule_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["export", "index", str(tmp_path)])

    assert result.exit_code == 1
    assert "no YAML rule files found" in result.output


def test_build_index_tolerates_malformed_payloads() -> None:
    index = build_index([{"pack": "nope", "rules": ["not-a-rule", {"id": "X"}]}, "garbage"])

    assert index["schema"] == INDEX_SCHEMA
    first = index["packs"][0]
    assert first["pack"] == {}  # non-dict pack -> empty summary
    assert first["rules"][0] == {}  # non-dict rule -> empty summary
    assert first["rules"][1] == {"id": "X"}
    assert index["packs"][1] == {"pack": {}, "rules": []}  # non-dict payload
