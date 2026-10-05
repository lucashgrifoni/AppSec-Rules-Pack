"""`appsec-rules init` writes a starter pack that passes the strict gate."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.validator import validate_rules_file

runner = CliRunner()
TEMPLATE = Path("src/appsec_rules_pack/templates/minimal-pack.yaml")


def test_init_writes_a_pack_that_passes_the_strict_gate(tmp_path: Path) -> None:
    target = tmp_path / "packs" / "my-pack.yaml"

    result = runner.invoke(app, ["init", str(target)])

    assert result.exit_code == 0, result.output
    assert target.read_text(encoding="utf-8") == TEMPLATE.read_text(encoding="utf-8")
    validation = validate_rules_file(target, require_examples=True)
    assert validation.issues == ()
    strict = runner.invoke(
        app, ["validate", str(target), "--require-examples", "--fail-on-warnings"]
    )
    assert strict.exit_code == 0


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    target = tmp_path / "pack.yaml"
    target.write_text("keep me\n", encoding="utf-8")

    refused = runner.invoke(app, ["init", str(target)])

    assert refused.exit_code == 1
    assert "already exists" in refused.output
    assert target.read_text(encoding="utf-8") == "keep me\n"

    forced = runner.invoke(app, ["init", str(target), "--force"])

    assert forced.exit_code == 0
    assert target.read_text(encoding="utf-8") == TEMPLATE.read_text(encoding="utf-8")


def test_init_into_a_directory_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path)])

    assert result.exit_code != 0
    assert list(tmp_path.iterdir()) == []
