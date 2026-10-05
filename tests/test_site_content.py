"""Published page counts must follow repository data, including the package version."""

import json
import re
from pathlib import Path

import pytest
import yaml

from appsec_rules_pack import __version__
from appsec_rules_pack.cli import export_app

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "site/index.html").read_text(encoding="utf-8")
BASELINE = yaml.safe_load((ROOT / "rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
SCHEMA = json.loads(
    (ROOT / "src/appsec_rules_pack/schemas/appsec-rule.schema.json").read_text(encoding="utf-8")
)
COUNTS = {
    label: int(number)
    for number, label in re.findall(
        r'<div class="stat"><div class="n">(\d+)</div><div class="l">([^<]+)</div>', PAGE
    )
}


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("baseline rules", len(BASELINE["rules"])),
        ("framework maps", len(SCHEMA["$defs"]["rule"]["properties"]["mappings"]["properties"])),
        ("export formats", len(export_app.registered_commands)),
        ("rule categories", len({rule["category"] for rule in BASELINE["rules"]})),
    ],
)
def test_page_counts_match_repository(label: str, expected: int) -> None:
    assert COUNTS[label] == expected


def test_page_eyebrow_matches_package_version() -> None:
    eyebrow = re.search(r'<span class="eyebrow">v([^ ]+) ', PAGE)
    assert eyebrow is not None
    assert eyebrow.group(1) == __version__
