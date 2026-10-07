"""v0.9.0 CLI behavior: issue locations, several paths, link-safe walks, init ids, help."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import _TYPER_SETTINGS, app
from appsec_rules_pack.review import review_files

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "rules" / "appsec-baseline.yaml"
MINIMAL = ROOT / "examples" / "minimal-pack.yaml"
EXAMPLE = ROOT / "examples" / "review" / "payments-api-review.yaml"


def _validate_json(*paths: Path) -> tuple[int, dict]:
    result = runner.invoke(app, ["validate", *map(str, paths), "--format", "json"])
    return result.exit_code, json.loads(result.stdout)


def _issues(report: dict) -> list[dict]:
    return [issue for entry in report["files"] for issue in entry["issues"]]


# --- issue locations ------------------------------------------------------------------


def test_schema_issue_points_at_the_offending_value(tmp_path: Path) -> None:
    text = MINIMAL.read_text(encoding="utf-8").replace("severity: medium", "severity: severe")
    pack = tmp_path / "pack.yaml"
    pack.write_text(text, encoding="utf-8")
    line = text.splitlines().index("    severity: severe") + 1

    exit_code, report = _validate_json(pack)

    [issue] = _issues(report)
    assert exit_code == 1
    assert (issue["path"], issue["line"], issue["column"]) == ("rules.0.severity", line, 15)


def test_missing_field_points_at_the_object_that_lacks_it(tmp_path: Path) -> None:
    payload = yaml.safe_load(MINIMAL.read_text(encoding="utf-8"))
    del payload["rules"][0]["title"]
    pack = tmp_path / "pack.yaml"
    pack.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    line = pack.read_text(encoding="utf-8").splitlines().index("- id: MYPACK-ERRORS-001") + 1

    _, report = _validate_json(pack)

    [issue] = _issues(report)
    assert (issue["code"], issue["line"], issue["column"]) == ("schema-missing-field", line, 3)


def test_text_output_shows_the_location(tmp_path: Path) -> None:
    text = MINIMAL.read_text(encoding="utf-8").replace("severity: medium", "severity: severe")
    pack = tmp_path / "pack.yaml"
    pack.write_text(text, encoding="utf-8")

    line = text.splitlines().index("    severity: severe") + 1

    result = runner.invoke(app, ["validate", str(pack)])

    assert "pack.yaml: ERROR rules.0.severity:" in result.stdout
    assert f"(line {line}, column 15)" in result.stdout


def test_yaml_error_carries_its_location(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text("pack:\n  id: [unclosed\n", encoding="utf-8")

    _, report = _validate_json(pack)

    [issue] = _issues(report)
    assert issue["code"] == "yaml-invalid"
    assert issue["line"] is not None and issue["column"] is not None


def test_issue_without_a_path_has_no_location(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text("[]\n", encoding="utf-8")

    _, report = _validate_json(pack)

    assert all(issue["line"] is None for issue in _issues(report) if issue["path"] == "<root>")


def test_review_issue_points_into_the_record(tmp_path: Path) -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "  - rule: APPSEC-SSRF-001\n    status: met", "  - rule: APPSEC-SSRF-001\n    status: done"
    )
    record = tmp_path / "record.yaml"
    record.write_text(text, encoding="utf-8")
    line = text.splitlines().index("    status: done") + 1

    result = review_files(BASELINE, record, as_of=__import__("datetime").date(2026, 10, 5))

    [issue] = result.issues
    assert (issue.code, issue.line, issue.column) == ("schema-enum", line, 13)


# --- several paths ----------------------------------------------------------------------


def test_several_paths_are_validated_together(tmp_path: Path) -> None:
    own = tmp_path / "own"
    own.mkdir()
    (own / "acme.yaml").write_bytes(MINIMAL.read_bytes())

    exit_code, report = _validate_json(BASELINE, own)

    assert exit_code == 0
    assert report["summary"]["files"] == 2
    assert {entry["path"] for entry in report["files"]} == {"appsec-baseline.yaml", "acme.yaml"}


def test_duplicate_rule_ids_are_found_across_arguments(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "one.yaml").write_bytes(MINIMAL.read_bytes())
    (second / "two.yaml").write_bytes(MINIMAL.read_bytes())

    exit_code, report = _validate_json(first, second)

    assert exit_code == 1
    assert "duplicate-rule-id" in {issue["code"] for issue in _issues(report)}


def test_a_file_reached_twice_is_validated_once(tmp_path: Path) -> None:
    (tmp_path / "pack.yaml").write_bytes(MINIMAL.read_bytes())

    exit_code, report = _validate_json(tmp_path, tmp_path / "pack.yaml")

    assert exit_code == 0
    assert report["summary"]["files"] == 1


def test_no_files_names_every_searched_path(tmp_path: Path) -> None:
    empty_a, empty_b = tmp_path / "a", tmp_path / "b"
    empty_a.mkdir()
    empty_b.mkdir()

    result = runner.invoke(app, ["validate", str(empty_a), str(empty_b)])

    assert result.exit_code == 1
    assert empty_a.as_posix() in result.stdout and empty_b.as_posix() in result.stdout


def test_linked_directories_are_not_entered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "real").mkdir(parents=True)
    (tree / "real" / "pack.yaml").write_bytes(MINIMAL.read_bytes())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "other.yaml").write_text("not: a pack\n", encoding="utf-8")
    try:
        os.symlink(outside, tree / "link", target_is_directory=True)
        os.symlink(tree, tree / "loop", target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks needs a privilege this platform lacks")

    exit_code, report = _validate_json(tree)

    assert exit_code == 0
    assert [entry["path"] for entry in report["files"]] == ["real/pack.yaml"]


# --- init ids, notes length, help -------------------------------------------------------


def test_init_takes_the_pack_id_and_rule_prefix(tmp_path: Path) -> None:
    target = tmp_path / "acme.yaml"

    result = runner.invoke(app, ["init", str(target), "--id", "acme-web", "--prefix", "ACME"])

    assert result.exit_code == 0, result.output
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert payload["pack"]["id"] == "acme-web"
    assert [rule["id"] for rule in payload["rules"]] == ["ACME-ERRORS-001"]
    strict = runner.invoke(
        app, ["validate", str(target), "--require-examples", "--fail-on-warnings"]
    )
    assert strict.exit_code == 0


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--id", "Acme_Web"),
        ("--id", "acme\n"),
        ("--id", "-acme"),
        ("--prefix", "acme"),
        ("--prefix", "1X"),
    ],
)
def test_init_rejects_ids_the_schema_would_reject(tmp_path: Path, option: str, value: str) -> None:
    target = tmp_path / "pack.yaml"

    result = runner.invoke(app, ["init", str(target), option, value])

    assert result.exit_code == 2
    assert not target.exists()


@pytest.mark.parametrize(("length", "codes"), [(960, []), (961, ["schema-length"])])
def test_notes_hold_up_to_960_characters(tmp_path: Path, length: int, codes: list[str]) -> None:
    record = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    for entry in record["results"]:
        if entry["rule"] == "APPSEC-LOG-001":
            entry["notes"] = "x" * length
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(record), encoding="utf-8")

    result = review_files(BASELINE, path, as_of=__import__("datetime").date(2026, 10, 5))

    assert [issue.code for issue in result.issues] == codes


def test_help_reflows_docstring_paragraphs() -> None:
    assert _TYPER_SETTINGS["rich_markup_mode"] == "markdown"
    result = runner.invoke(app, ["review", "--help"], terminal_width=80)

    lines = [line.strip(" |") for line in result.stdout.splitlines()]
    assert "does" not in lines and "change" not in lines
    assert "Exit 1 means the record is invalid." in " ".join(result.stdout.split())
