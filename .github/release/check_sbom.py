"""Reject release SBOMs with a wrong root identity or installer components."""

import ast
import json
import re
import sys
from pathlib import Path


def check_sbom(bom: dict, version: str) -> None:
    root = bom.get("metadata", {}).get("component", {})
    expected = {
        "name": "appsec-rules-pack",
        "version": version,
        "purl": f"pkg:pypi/appsec-rules-pack@{version}",
    }
    for field, value in expected.items():
        if root.get(field) != value:
            raise ValueError(f"SBOM root {field} must be {value!r}, got {root.get(field)!r}")
    pending = list(bom.get("components", [])) + list(root.get("components", []))
    while pending:
        component = pending.pop()
        name = re.sub(r"[-_.]+", "-", component.get("name", "")).lower()
        if name in {"pip", "setuptools", "wheel"}:
            raise ValueError(f"Installer component in release SBOM: {component['name']}")
        pending.extend(component.get("components", []))


if __name__ == "__main__":
    source = ast.parse(Path("src/appsec_rules_pack/__init__.py").read_text(encoding="utf-8"))
    version = next(
        ast.literal_eval(node.value)
        for node in source.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
    )
    bom = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    check_sbom(bom, version)
    print(f"SBOM verified: appsec-rules-pack {version}, correct purl, no installer components")
