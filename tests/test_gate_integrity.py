"""Regression tests for gate integrity on hostile or malformed rule packs.

Rule packs arrive in pull requests, so the validator treats them as untrusted. Each
test here reproduces a defect found in the v0.5.0 review: a pack that made the gate
pass while dropping content, a pack that stalled CI, a pack that crashed a command
with a traceback, or output that echoed secret material into CI logs.

Secret-shaped strings are assembled at runtime so that secret scanners reading this
file do not mistake them for real credentials.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from appsec_rules_pack import loader
from appsec_rules_pack.cli import app, export_app, report_app
from appsec_rules_pack.reporter import build_coverage
from appsec_rules_pack.validator import validate_rules_file, validate_rules_payload

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
MINIMAL = ROOT / "tests" / "fixtures" / "pass" / "minimal-valid.yaml"
BASELINE = ROOT / "rules" / "appsec-baseline.yaml"

GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 3 + "F6g7H8"
AWS_KEY_ID = "AK" + "IA" + "QWERTYUIOPASDFGH"


def _minimal_payload() -> dict:
    return yaml.safe_load(MINIMAL.read_text(encoding="utf-8"))


def _write(tmp_path: Path, name: str, text: str) -> Path:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return target


# --- YAML aliases ---------------------------------------------------------------


def test_alias_is_rejected_with_location(tmp_path: Path) -> None:
    pack = _write(tmp_path, "alias.yaml", "pack: &p {id: x}\nrules:\n  - *p\n")

    result = validate_rules_file(pack)

    assert not result.ok
    [issue] = result.issues
    assert issue.message == (
        "could not parse YAML file at line 3, column 5: "
        "YAML aliases are not supported in rules packs"
    )


def test_self_referencing_alias_fails_closed_with_parseable_json(tmp_path: Path) -> None:
    pack = _write(tmp_path, "cycle.yaml", "pack: &a [*a]\n")

    result = runner.invoke(app, ["validate", str(pack), "--format", "json"])

    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["summary"]["ok"] is False
    assert "aliases are not supported" in report["files"][0]["issues"][0]["message"]


def test_alias_bomb_is_rejected_quickly(tmp_path: Path) -> None:
    lines = ['a0: &a0 ["x", "x", "x", "x", "x", "x", "x", "x", "x", "x"]']
    for level in range(1, 10):
        refs = ", ".join([f"*a{level - 1}"] * 10)
        lines.append(f"a{level}: &a{level} [{refs}]")
    pack = _write(tmp_path, "bomb.yaml", "\n".join(lines) + "\n")
    assert pack.stat().st_size < 2048

    started = time.perf_counter()
    result = runner.invoke(app, ["validate", str(pack)])
    elapsed = time.perf_counter() - started

    assert result.exit_code == 1
    assert "aliases are not supported" in result.stdout
    assert elapsed < 2


@pytest.mark.parametrize(
    "command",
    [["export", "index"], ["export", "sarif"], ["export", "semgrep"], ["report", "coverage"]],
)
def test_derivation_commands_reject_aliases(tmp_path: Path, command: list[str]) -> None:
    pack = _write(tmp_path, "alias.yaml", "pack: &p {id: x}\nrules: [*p]\n")

    result = runner.invoke(app, [*command, str(pack)])

    assert result.exit_code == 1
    assert "aliases are not supported" in result.stderr
    assert "Traceback" not in result.output


# --- Duplicate keys ---------------------------------------------------------------


def test_duplicate_rules_key_cannot_silently_drop_rules(tmp_path: Path) -> None:
    text = BASELINE.read_text(encoding="utf-8") + ("\nrules:\n  - id: APPSEC-ONLY-001\n")
    pack = _write(tmp_path, "duplicate-rules.yaml", text)

    result = runner.invoke(app, ["validate", str(pack)])

    assert result.exit_code == 1
    assert "duplicate key 'rules'" in result.stdout


def test_duplicate_nested_key_is_an_error(tmp_path: Path) -> None:
    text = MINIMAL.read_text(encoding="utf-8").replace(
        "    status: enabled\n", "    status: enabled\n    status: disabled\n", 1
    )
    pack = _write(tmp_path, "duplicate-status.yaml", text)

    result = validate_rules_file(pack)

    assert not result.ok
    assert "duplicate key 'status'" in result.issues[0].message


# --- File size --------------------------------------------------------------------


def test_oversized_file_is_refused_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "MAX_RULES_FILE_BYTES", 100)
    pack = _write(tmp_path, "big.yaml", MINIMAL.read_text(encoding="utf-8"))

    result = validate_rules_file(pack)

    assert not result.ok
    [issue] = result.issues
    assert issue.message.startswith("could not read YAML file: file is ")
    assert "maximum supported rules file size is 100 bytes" in issue.message


# --- Crashes on malformed values --------------------------------------------------


def test_unhashable_required_field_does_not_crash() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["exceptions"]["required_fields"] = [[]]

    result = validate_rules_payload(payload)

    assert not result.ok


@pytest.mark.parametrize("command", [["export", "sarif"], ["export", "semgrep"]])
@pytest.mark.parametrize("severity", ["[high]", "{level: high}"])
def test_non_scalar_severity_does_not_crash_exports(
    tmp_path: Path, command: list[str], severity: str
) -> None:
    text = MINIMAL.read_text(encoding="utf-8").replace(
        "severity: medium", f"severity: {severity}", 1
    )
    pack = _write(tmp_path, "severity.yaml", text)

    result = runner.invoke(app, [*command, str(pack)])

    assert result.exit_code == 0, result.output


def test_unrepresentable_value_is_a_clean_export_error(tmp_path: Path) -> None:
    text = MINIMAL.read_text(encoding="utf-8").replace("- CWE-209", "- 2026-01-01", 1)
    pack = _write(tmp_path, "date.yaml", text)

    result = runner.invoke(app, ["export", "index", str(pack)])

    assert result.exit_code == 1
    assert "contains a value JSON cannot represent" in result.stderr
    assert "Traceback" not in result.output


def test_tracebacks_never_print_local_variables() -> None:
    for typer_app in (app, export_app, report_app):
        assert typer_app.pretty_exceptions_show_locals is False


# --- Output paths -----------------------------------------------------------------


def test_output_cannot_overwrite_an_input_pack(tmp_path: Path) -> None:
    pack = _write(tmp_path, "pack.yaml", MINIMAL.read_text(encoding="utf-8"))
    before = pack.read_bytes()

    result = runner.invoke(app, ["export", "sarif", str(pack), "-o", str(pack)])

    assert result.exit_code == 1
    assert "is one of the input rules files" in result.stderr
    assert pack.read_bytes() == before


# --- Sensitive values -------------------------------------------------------------


def test_github_token_in_description_is_an_error() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["description"] = f"Use {GITHUB_TOKEN} to call the API."

    result = validate_rules_payload(payload)

    assert not result.ok
    assert any(
        issue.path == ("rules", 0, "description") and "sensitive value" in issue.message
        for issue in result.issues
    )


def test_secret_used_as_a_mapping_key_is_detected_and_not_echoed() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["mappings"][AWS_KEY_ID] = ["x"]

    result = validate_rules_payload(payload)

    assert any("sensitive value" in issue.message for issue in result.issues)
    assert all(AWS_KEY_ID not in issue.message for issue in result.issues)


def test_secret_in_a_malformed_mapping_id_is_redacted() -> None:
    payload = _minimal_payload()
    payload["rules"][0]["mappings"]["cwe"] = [AWS_KEY_ID]

    result = validate_rules_payload(payload)

    assert all(AWS_KEY_ID not in issue.message for issue in result.issues)
    assert any("mapping id <redacted> is malformed" in issue.message for issue in result.issues)


def test_secret_is_found_in_a_later_rule_after_an_examples_block() -> None:
    payload = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    payload["rules"][1]["remediation"]["guidance"] = f"Rotate {GITHUB_TOKEN}."

    result = validate_rules_payload(payload)

    assert any(issue.path == ("rules", 1, "remediation", "guidance") for issue in result.issues)


def test_key_material_in_examples_is_a_warning_but_demo_passwords_are_not() -> None:
    payload = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    examples = payload["rules"][0]["examples"]
    examples["violating"]["snippet"] += f'\naws_key = "{AWS_KEY_ID}"\n'

    result = validate_rules_payload(payload)

    assert result.ok
    flagged = [issue for issue in result.issues if "real key material" in issue.message]
    assert [issue.level for issue in flagged] == ["warning"]
    assert flagged[0].path[:3] == ("rules", 0, "examples")


def test_baseline_examples_raise_no_key_material_warning() -> None:
    result = validate_rules_file(BASELINE, require_examples=True)

    assert result.ok
    assert result.warning_count == 0


# --- Coverage report --------------------------------------------------------------


def test_rule_without_id_is_not_counted_as_covered() -> None:
    payload = {
        "rules": [
            {"title": "no id"},
            {"id": "APPSEC-X-001", "mappings": {"cwe": ["CWE-1"]}},
        ]
    }

    coverage = build_coverage([payload])

    assert coverage["frameworks"]["cwe"] == {"covered": 1, "total": 2, "missing": []}
