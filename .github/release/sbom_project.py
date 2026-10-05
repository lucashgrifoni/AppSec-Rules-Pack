"""Resolve the SBOM root's dynamic version from the installed release wheel."""

import json
import re
import sys
import tomllib
from importlib.metadata import metadata
from pathlib import Path


def resolve_project(source: str, name: str, version: str) -> str:
    project = tomllib.loads(source)["project"]
    if project["name"] != name or project.get("dynamic") != ["version"]:
        raise ValueError("Expected the release project with only a dynamic version")
    resolved, count = re.subn(
        r'^dynamic = \["version"\]$',
        f"version = {json.dumps(version)}",
        source,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1 or tomllib.loads(resolved)["project"]["version"] != version:
        raise ValueError("Could not resolve the wheel version into the SBOM project")
    return resolved


if __name__ == "__main__":
    wheel = metadata("appsec-rules-pack")
    source = Path(sys.argv[1]).read_text(encoding="utf-8")
    Path(sys.argv[2]).write_text(
        resolve_project(source, wheel["Name"], wheel["Version"]),
        encoding="utf-8",
        newline="\n",
    )
