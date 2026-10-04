"""Inventory guards; behavioral checks run in the dedicated Semgrep CI job."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
LAYER = ROOT / "exports" / "semgrep-rules"
RULE_FILES = sorted((LAYER / "rules").glob("*.yaml"))


def test_executable_rules_cover_only_the_documented_baseline_subset() -> None:
    baseline = yaml.safe_load((ROOT / "rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
    baseline_by_id = {rule["id"]: rule for rule in baseline["rules"]}
    detections = [
        rule
        for path in RULE_FILES
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
    ]
    assert len(detections) == 2
    assert len({rule["id"] for rule in detections}) == len(detections)
    assert {rule["metadata"]["baseline_id"] for rule in detections} == {
        "APPSEC-INJECT-001",
        "APPSEC-SSRF-001",
    }
    for rule in detections:
        parent = baseline_by_id[rule["metadata"]["baseline_id"]]
        assert parent["status"] == "enabled"
        assert all(
            cwe.split(":")[0] in parent["mappings"]["cwe"] for cwe in rule["metadata"]["cwe"]
        )
        assert rule["languages"] == ["python"]
        assert rule["mode"] == "taint"
        assert rule["pattern-sources"] and rule["pattern-sinks"]
        assert all(source["exact"] for source in rule["pattern-sources"])
        assert "pattern-regex" not in rule


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda path: path.stem)
def test_each_rule_has_real_positive_and_negative_fixtures(rule_file: Path) -> None:
    rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))["rules"][0]
    fixture = LAYER / "tests" / f"{rule_file.stem}.py"
    text = fixture.read_text(encoding="utf-8")
    ast.parse(text)
    annotations = re.findall(r"^\s*# (ruleid|ok): ([\w-]+)$", text, re.MULTILINE)
    assert {kind for kind, _ in annotations} == {"ruleid", "ok"}
    assert all(rule_id == rule["id"] for _, rule_id in annotations)
    # No skipped TODO expectations that could make a broken rule look tested.
    assert not re.search(r"#\s*todo(?:ruleid|ok):", text)


def test_generic_scan_excludes_only_the_intentional_semgrep_fixtures() -> None:
    ignores = {
        line.strip()
        for line in (ROOT / ".semgrepignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    fixtures = {f"/{path.relative_to(ROOT).as_posix()}" for path in (LAYER / "tests").glob("*.py")}
    assert ignores == fixtures
    assert len(fixtures) == len(RULE_FILES) == 2
