"""The downstream gate in examples/validation_gate.py must behave as documented."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

GATE_PATH = Path("examples/validation_gate.py")
VALID = "tests/fixtures/pass/minimal-valid.yaml"
INVALID = "tests/fixtures/fail/invalid-enum.yaml"
WARNING = "tests/fixtures/warn/exception-window-warning.yaml"
REAL_CLI = (sys.executable, "-m", "appsec_rules_pack")


def _load_gate():
    spec = importlib.util.spec_from_file_location("validation_gate", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _fake_cli(stdout: str, code: int) -> tuple[str, ...]:
    script = f"import sys; sys.stdout.write({stdout!r}); sys.exit({code})"
    return (sys.executable, "-c", script)


def test_valid_fixture_passes() -> None:
    assert gate.run_gate([VALID], cli=REAL_CLI) == 0


def test_invalid_fixture_fails() -> None:
    assert gate.run_gate([INVALID], cli=REAL_CLI) == 1


def test_fail_on_warnings_flag_is_forwarded() -> None:
    assert gate.run_gate([WARNING], cli=REAL_CLI) == 0
    assert gate.run_gate([WARNING, "--fail-on-warnings"], cli=REAL_CLI) == 1


def test_require_examples_flag_is_forwarded(capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.run_gate([VALID, "--require-examples"], cli=REAL_CLI) == 0
    assert "warnings=1" in capsys.readouterr().out


@pytest.mark.parametrize(
    "stdout",
    ["", "not json", "[]", '{"files": []}', '{"summary": {}}', '{"summary": {"ok": "yes"}}'],
)
def test_malformed_json_is_a_gate_failure(stdout: str) -> None:
    assert gate.run_gate([VALID], cli=_fake_cli(stdout, 0)) == 1


def test_ok_json_with_nonzero_exit_is_a_gate_failure() -> None:
    assert gate.run_gate([VALID], cli=_fake_cli('{"summary": {"ok": true}}', 2)) == 1


def test_unavailable_cli_is_a_gate_failure() -> None:
    assert gate.run_gate([VALID], cli=("appsec-rules-does-not-exist",)) == 1
