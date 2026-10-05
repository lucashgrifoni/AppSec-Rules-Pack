"""Release SBOM checks must reject missing identity and installer contamination."""

import importlib.util
import json
import subprocess
import sys
import tomllib
from copy import deepcopy
from pathlib import Path

import pytest

from appsec_rules_pack import __version__


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, Path(".github/release") / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = load_script("check_sbom")
PROJECT = load_script("sbom_project")


@pytest.fixture
def bom() -> dict:
    return {
        "metadata": {
            "component": {
                "name": "appsec-rules-pack",
                "version": __version__,
                "purl": f"pkg:pypi/appsec-rules-pack@{__version__}",
            }
        },
        "components": [{"name": "PyYAML", "version": "6.0.1"}],
    }


@pytest.mark.parametrize("field", ["name", "version", "purl"])
@pytest.mark.parametrize("wrong", [None, "wrong"])
def test_wrong_or_missing_root_field_is_rejected(bom: dict, field: str, wrong: str | None) -> None:
    if wrong is None:
        del bom["metadata"]["component"][field]
    else:
        bom["metadata"]["component"][field] = wrong
    with pytest.raises(ValueError, match=f"root {field}"):
        CHECK.check_sbom(bom, __version__)


def test_missing_root_is_rejected(bom: dict) -> None:
    del bom["metadata"]["component"]
    with pytest.raises(ValueError, match="root name"):
        CHECK.check_sbom(bom, __version__)


@pytest.mark.parametrize("name", ["pip", "setuptools", "wheel", "PIP"])
def test_installer_component_is_rejected(bom: dict, name: str) -> None:
    bom["components"].append({"name": name})
    with pytest.raises(ValueError, match="Installer component"):
        CHECK.check_sbom(bom, __version__)


def test_nested_installer_component_is_rejected(bom: dict) -> None:
    bom["components"][0]["components"] = [{"name": "wheel"}]
    with pytest.raises(ValueError, match="Installer component"):
        CHECK.check_sbom(bom, __version__)


def test_clean_sbom_passes_without_changing_it(bom: dict) -> None:
    original = deepcopy(bom)
    CHECK.check_sbom(bom, __version__)
    assert bom == original


def test_check_step_exits_nonzero_on_regression(bom: dict, tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(bom), encoding="utf-8")
    command = [sys.executable, ".github/release/check_sbom.py", str(path)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    del bom["metadata"]["component"]["version"]
    path.write_text(json.dumps(bom), encoding="utf-8")
    assert subprocess.run(command, capture_output=True).returncode != 0


def test_resolved_project_preserves_metadata_and_uses_wheel_version() -> None:
    source = Path("pyproject.toml").read_text(encoding="utf-8")
    original = tomllib.loads(source)
    resolved = tomllib.loads(PROJECT.resolve_project(source, "appsec-rules-pack", __version__))
    expected = deepcopy(original)
    del expected["project"]["dynamic"]
    expected["project"]["version"] = __version__
    assert resolved == expected


def test_resolver_rejects_a_different_project() -> None:
    source = Path("pyproject.toml").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="Expected the release project"):
        PROJECT.resolve_project(source, "another-project", __version__)
