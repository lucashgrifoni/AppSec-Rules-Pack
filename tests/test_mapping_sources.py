"""Check baseline ASVS IDs against the official 5.0.0 release, without network access.

The snapshot was extracted from English chapter headings and requirement table IDs:
https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en
Commit: 5cf9b032440be53ce345ab3c130fda46ba1ce7a2.
The supplied v5.0.0 URL is a release branch, rather than the immutable release tag.
"""

import json
from pathlib import Path

import pytest
import yaml

BASELINE = yaml.safe_load(Path("rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
SNAPSHOT = json.loads(Path("tests/fixtures/asvs-5.0.0-ids.json").read_text(encoding="utf-8"))
ASVS_IDS = set(SNAPSHOT["sections"]) | set(SNAPSHOT["requirements"])


@pytest.mark.parametrize("rule", BASELINE["rules"], ids=lambda rule: rule["id"])
def test_baseline_asvs_ids_exist_in_official_release(rule: dict) -> None:
    for identifier in rule["mappings"]["owasp_asvs"]:
        assert identifier in ASVS_IDS, f"{rule['id']}: {identifier} is absent in ASVS 5.0.0"


def test_mapping_rationale_covers_every_rule_with_its_final_ids() -> None:
    rows = {
        cells[0]: " ".join(cells[1:])
        for line in Path("docs/mapping-rationale.md").read_text(encoding="utf-8").splitlines()
        if line.startswith("| APPSEC-")
        for cells in [[cell.strip() for cell in line.strip("|").split("|")]]
    }
    assert set(rows) == {rule["id"] for rule in BASELINE["rules"]}
    for rule in BASELINE["rules"]:
        for framework in ("owasp_asvs", "nist_ssdf"):
            for identifier in rule["mappings"][framework]:
                assert identifier in rows[rule["id"]], (rule["id"], identifier)
