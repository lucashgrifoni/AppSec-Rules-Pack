"""Unit tests for YAML loading helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from appsec_rules_pack.loader import load_yaml_file


def test_load_yaml_file_parses_mapping(tmp_path: Path) -> None:
    target = tmp_path / "pack.yaml"
    target.write_text("pack:\n  id: demo\n", encoding="utf-8")

    assert load_yaml_file(target) == {"pack": {"id": "demo"}}


def test_load_yaml_file_missing_file_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load_yaml_file(tmp_path / "does-not-exist.yaml")


def test_load_yaml_file_malformed_raises_yaml_error(tmp_path: Path) -> None:
    target = tmp_path / "broken.yaml"
    target.write_text("pack: [unterminated\n", encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        load_yaml_file(target)
