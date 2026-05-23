"""Packaging checks for distribution readiness."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_package_builds_wheel(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--outdir",
            str(tmp_path),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    assert wheels[0].name.startswith("appsec_rules_pack-")
