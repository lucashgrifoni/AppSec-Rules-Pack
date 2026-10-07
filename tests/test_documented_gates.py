"""Keep downstream documentation aligned with the strict repository quality gate."""

from __future__ import annotations

import json
import re
import runpy
import shlex
import textwrap
from pathlib import Path

import pytest
import yaml
from helpers import run_python

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples/README.md").read_text(encoding="utf-8")
COMMANDS = re.findall(
    r"^\s*(?:run:\s+)?(?:appsec-rules|python -m appsec_rules_pack) (validate rules[^\n]*)$",
    EXAMPLES,
    re.MULTILINE,
)


def test_documented_validation_commands_use_strict_json_gate() -> None:
    assert len(COMMANDS) == 3
    for command in COMMANDS:
        args = shlex.split(command)
        assert args[:2] == ["validate", "rules"]
        assert "--require-examples" in args
        assert "--fail-on-warnings" in args
        assert args[args.index("--format") + 1] == "json"


@pytest.mark.parametrize("command", COMMANDS, ids=["workflow", "local", "powershell"])
@pytest.mark.parametrize("case", ["valid", "missing_examples", "warning"])
def test_documented_gate_accepts_and_rejects_real_packs(
    tmp_path: Path, command: str, case: str
) -> None:
    payload = yaml.safe_load((ROOT / "rules/appsec-baseline.yaml").read_text(encoding="utf-8"))
    if case == "missing_examples":
        payload["rules"][0].pop("examples")
    elif case == "warning":
        payload["rules"][0]["exceptions"]["max_days"] = 91
    target = tmp_path / "pack.yaml"
    target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    args = shlex.split(command)
    args[1] = str(target)
    result = run_python(
        ["-m", "appsec_rules_pack", *args],
        cwd=ROOT,
        extra_env={"PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == (0 if case == "valid" else 1), result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["errors"] == 0
    assert report["summary"]["warnings"] == (0 if case == "valid" else 1)


def test_pull_request_template_lists_every_required_gate() -> None:
    template = (ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert "python -m ruff check ." in template
    assert "python -m pytest --cov=appsec_rules_pack --cov-report=term-missing" in template
    strict = "python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings"
    assert strict in template
    assert "python -m build" in template
    assert "regression test" in template


def _step_script(step: str) -> str:
    pattern = rf"- name: {step}\n.*?python - <<'PY'\n(?P<body>.*?)\n\s*PY\n"
    return textwrap.dedent(re.search(pattern, EXAMPLES, re.S).group("body"))


GATE_SCRIPT = _step_script("Gate on open rules")
RECORDS_SCRIPT = _step_script("Check review records")


@pytest.mark.parametrize(
    ("open_by_severity", "open_by_enforcement", "expected"),
    [
        ({}, {}, 0),
        ({"medium": 2, "low": 1}, {"advisory": 3}, 0),
        ({"high": 1}, {"advisory": 1}, 1),
        ({"critical": 1}, {"advisory": 1}, 1),
        ({"medium": 1}, {"blocking": 1}, 1),
    ],
)
def test_template_gate_stops_on_critical_high_or_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    open_by_severity: dict,
    open_by_enforcement: dict,
    expected: int,
) -> None:
    """The README tells users to gate on critical or high; the template must do the same."""
    reports = tmp_path / "reports"
    reports.mkdir()
    summary = {"open_by_severity": open_by_severity, "open_by_enforcement": open_by_enforcement}
    (reports / "svc.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")
    gate = tmp_path / "gate.py"
    gate.write_text(GATE_SCRIPT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    # In-process: a child started outside the repository would not find the coverage config.
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(gate), run_name="__main__")

    assert stopped.value.code == expected


def _run_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, summary: dict) -> int:
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "svc.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")
    gate = tmp_path / "gate.py"
    gate.write_text(GATE_SCRIPT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(gate), run_name="__main__")
    return stopped.value.code


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"GATE_SEVERITIES": "critical"}, 0),
        ({"GATE_SEVERITIES": "critical,high,medium"}, 1),
        ({"GATE_ENFORCEMENT": "", "GATE_SEVERITIES": "medium"}, 1),
        ({"GATE_SEVERITY_VIEW": "effective"}, 0),
        ({"GATE_SEVERITY_VIEW": "effective", "GATE_SEVERITIES": "low"}, 1),
    ],
)
def test_template_gate_thresholds_are_tunable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env: dict, expected: int
) -> None:
    # One open high rule, which the reviewer assessed as low, and one open medium rule.
    summary = {
        "open_by_severity": {"high": 1, "medium": 1},
        "open_by_effective_severity": {"low": 1, "medium": 1},
        "open_by_enforcement": {"advisory": 2},
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    assert _run_gate(tmp_path, monkeypatch, summary) == expected


def test_effective_view_falls_back_for_reports_without_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A report from a CLI older than 0.8.0 has no effective counts; the gate must not
    # read that as "nothing open".
    monkeypatch.setenv("GATE_SEVERITY_VIEW", "effective")
    summary = {"open_by_severity": {"high": 1}, "open_by_enforcement": {"advisory": 1}}

    assert _run_gate(tmp_path, monkeypatch, summary) == 1


def test_template_checks_each_record_against_the_pack_it_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from appsec_rules_pack.cli import app

    (tmp_path / "rules" / "vendor").mkdir(parents=True)
    baseline = (ROOT / "rules/appsec-baseline.yaml").read_bytes()
    (tmp_path / "rules" / "vendor" / "appsec-baseline.yaml").write_bytes(baseline)
    minimal = (ROOT / "examples/minimal-pack.yaml").read_bytes()
    (tmp_path / "rules" / "acme.yaml").write_bytes(minimal)
    (tmp_path / "reviews").mkdir()
    worked = (ROOT / "examples/review/payments-api-review.yaml").read_bytes()
    (tmp_path / "reviews" / "payments.yaml").write_bytes(worked)
    own = {
        "review": {"pack": "my-pack", "subject": "svc", "reviewer": "me", "date": "2026-10-07"},
        "results": [{"rule": "MYPACK-ERRORS-001", "status": "met", "evidence": ["test"]}],
    }
    (tmp_path / "reviews" / "own.yaml").write_text(yaml.safe_dump(own), encoding="utf-8")
    (tmp_path / "reports").mkdir()
    calls: list[list[str]] = []

    class Done:
        def __init__(self, code: int) -> None:
            self.returncode = code

    def fake_run(command: list[str], stdout) -> Done:
        calls.append(command)
        result = CliRunner().invoke(app, [*command[1:], "--as-of", "2026-10-05"])
        stdout.write(result.stdout)
        return Done(result.exit_code)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.chdir(tmp_path)
    script = tmp_path / "records.py"
    script.write_text(RECORDS_SCRIPT, encoding="utf-8")
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(script), run_name="__main__")

    assert stopped.value.code == 0
    used = {Path(command[3]).name: Path(command[2]).name for command in calls}
    assert used == {"own.yaml": "acme.yaml", "payments.yaml": "appsec-baseline.yaml"}
    assert json.loads((tmp_path / "reports" / "own.json").read_text())["summary"]["met"] == 1
