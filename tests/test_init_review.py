"""`appsec-rules init-review`: a record to fill in, which cannot pass until it is filled."""

from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path

import yaml
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.review import review_payloads

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "rules" / "appsec-baseline.yaml"


def _init(pack: Path, record: Path, *extra: str):
    return runner.invoke(
        app,
        ["init-review", str(pack), str(record), "--subject", "payments-api", "--reviewer", "me"]
        + list(extra),
    )


def test_record_lists_every_enabled_rule_as_open(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"

    result = _init(BASELINE, record, "--subject-ref", "v3.2.0")

    assert result.exit_code == 0, result.output
    pack = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    written = yaml.safe_load(record.read_text(encoding="utf-8"))
    assert written["review"] == {
        "pack": "appsec-baseline",
        "pack_version": pack["pack"]["version"],
        "subject": "payments-api",
        "subject_ref": "v3.2.0",
        "reviewer": "me",
        "date": dt.datetime.now(dt.UTC).date().isoformat(),
    }
    assert written["results"] == [
        {"rule": rule["id"], "status": "not-met"}
        for rule in pack["rules"]
        if rule["status"] == "enabled"
    ]


def test_unfilled_record_is_valid_but_fails_the_strict_gate(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"
    _init(BASELINE, record)

    lenient = runner.invoke(app, ["review", str(BASELINE), str(record)])
    strict = runner.invoke(app, ["review", str(BASELINE), str(record), "--fail-on-warnings"])

    assert lenient.exit_code == 0
    assert "29 open" in lenient.stdout
    assert lenient.stdout.count("needs notes saying why") == 29
    assert strict.exit_code == 1


def test_titles_are_comments_that_do_not_change_the_record(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"
    _init(BASELINE, record)

    text = record.read_text(encoding="utf-8")

    assert "  # Enforce server-side object authorization (high, advisory)\n" in text
    assert "--fail-on-warnings fails" in text


def test_only_enabled_rules_are_listed(tmp_path: Path) -> None:
    pack = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    pack["rules"][0]["status"] = "draft"
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text(yaml.safe_dump(pack, sort_keys=False), encoding="utf-8")
    record = tmp_path / "review.yaml"

    result = _init(pack_path, record)

    assert result.exit_code == 0, result.output
    results = yaml.safe_load(record.read_text(encoding="utf-8"))["results"]
    rules = [entry["rule"] for entry in results]
    assert pack["rules"][0]["id"] not in rules
    assert len(rules) == len(pack["rules"]) - 1


def test_values_with_yaml_syntax_survive_the_round_trip(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"
    subject = 'api: "v2" # not a comment, [x], {y}, &anchor'

    result = runner.invoke(
        app,
        ["init-review", str(BASELINE), str(record), "--subject", subject, "--reviewer", "ação"],
    )

    assert result.exit_code == 0, result.output
    written = yaml.safe_load(record.read_text(encoding="utf-8"))
    assert written["review"]["subject"] == subject
    assert written["review"]["reviewer"] == "ação"


def test_existing_file_is_kept_without_force(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"
    record.write_text("keep me\n", encoding="utf-8")

    refused = _init(BASELINE, record)
    forced = _init(BASELINE, record, "--force")

    assert refused.exit_code == 1
    assert "already exists" in refused.output
    assert forced.exit_code == 0
    assert record.read_text(encoding="utf-8").startswith("# Review record")


def test_invalid_pack_is_refused(tmp_path: Path) -> None:
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_text("pack: {}\nrules: []\n", encoding="utf-8")
    record = tmp_path / "review.yaml"

    result = _init(pack_path, record)

    assert result.exit_code == 1
    assert "validation error" in result.output
    assert not record.exists()


def test_value_the_record_schema_rejects_is_refused_before_writing(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"

    result = runner.invoke(
        app,
        ["init-review", str(BASELINE), str(record), "--subject", "x" * 241, "--reviewer", "me"],
    )

    assert result.exit_code == 1
    assert "review.subject: value is too long" in result.output
    assert not record.exists()


def test_writing_over_the_pack_is_refused(tmp_path: Path) -> None:
    pack_path = tmp_path / "pack.yaml"
    pack_path.write_bytes(BASELINE.read_bytes())

    result = _init(pack_path, pack_path, "--force")

    assert result.exit_code == 1
    assert pack_path.read_bytes() == BASELINE.read_bytes()


def test_filled_record_passes_the_strict_gate(tmp_path: Path) -> None:
    record = tmp_path / "review.yaml"
    _init(BASELINE, record)
    pack = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    filled = yaml.safe_load(record.read_text(encoding="utf-8"))
    for entry in filled["results"]:
        entry["status"] = "not-applicable"
        entry["notes"] = "Out of scope for this test."

    result = review_payloads(pack, copy.deepcopy(filled), as_of=dt.date(2026, 10, 6))

    assert result.issues == ()
