"""Keep downstream documentation aligned with the strict repository quality gate."""

from __future__ import annotations

import json
import re
import shlex
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
