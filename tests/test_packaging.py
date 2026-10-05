"""Packaging checks for distribution readiness."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest
from helpers import run_python

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the distribution once and share it across the packaging assertions."""

    outdir = tmp_path_factory.mktemp("dist")
    result = run_python(["-m", "build", "--outdir", str(outdir), str(REPO_ROOT)], cwd=REPO_ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    return outdir


def test_package_builds_wheel(built: Path) -> None:
    wheels = list(built.glob("*.whl"))
    assert len(wheels) == 1
    assert wheels[0].name.startswith("appsec_rules_pack-")


def test_wheel_bundles_the_schema(built: Path) -> None:
    """The schema is loaded from the installed package, so it has to be in the wheel."""

    names = zipfile.ZipFile(next(built.glob("*.whl"))).namelist()
    assert "appsec_rules_pack/schemas/appsec-rule.schema.json" in names
    assert "appsec_rules_pack/schemas/review-record.schema.json" in names
    assert "appsec_rules_pack/schemas/review-report.schema.json" in names
    assert "appsec_rules_pack/templates/minimal-pack.yaml" in names


def test_sdist_does_not_ship_a_test_suite_it_cannot_run(built: Path) -> None:
    """Regression: the sdist used to carry tests/*.py without their dependencies.

    setuptools picked up the test modules but not ``tests/helpers.py``,
    ``tests/fixtures/``, or ``rules/appsec-baseline.yaml``, so ``pytest`` inside an
    unpacked sdist died on ``from helpers import run_python`` before running anything.
    Shipping the missing pieces would mean putting the rules pack into a distribution
    that deliberately does not carry one, so ``MANIFEST.in`` prunes tests instead. A
    partial test suite is worse than none: it reads as a broken project.
    """

    with tarfile.open(next(built.glob("*.tar.gz"))) as archive:
        members = archive.getnames()

    shipped_tests = [name for name in members if "/tests/" in name or name.endswith("/tests")]
    assert shipped_tests == [], f"sdist ships tests without their fixtures: {shipped_tests}"
