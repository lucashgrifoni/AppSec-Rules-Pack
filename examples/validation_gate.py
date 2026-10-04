"""Minimal downstream gate that consumes ``appsec-rules validate --format json``.

Portable (no GitHub Actions needed) and stdlib-only. The gate passes only when the CLI
exits 0 *and* its JSON reports ``summary.ok: true``. A process that launched but
printed nothing usable, or that disagrees with its own exit code, is a gate failure:
starting the CLI successfully is not the same as the pack passing.

Usage:
    python examples/validation_gate.py rules [--require-examples] [--fail-on-warnings]
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys

DEFAULT_CLI = ("appsec-rules",)


def run_gate(args: list[str], cli: tuple[str, ...] = DEFAULT_CLI) -> int:
    """Run the validator and return 0 when the pack passes, 1 otherwise."""
    command = [*cli, "validate", *args, "--format", "json"]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        print(f"gate: FAIL - could not start {shlex.join(command)}: {exc}", file=sys.stderr)
        return 1

    try:
        summary = json.loads(proc.stdout)["summary"]
        ok = summary["ok"]
        if not isinstance(ok, bool):
            raise TypeError("summary.ok is not a boolean")
    except (ValueError, KeyError, TypeError) as exc:
        print(f"gate: FAIL - unusable JSON (exit {proc.returncode}): {exc}", file=sys.stderr)
        return 1

    print(
        f"rules={summary.get('rules')} errors={summary.get('errors')} "
        f"warnings={summary.get('warnings')} ok={ok} exit={proc.returncode}"
    )
    if ok and proc.returncode == 0:
        print("gate: PASS")
        return 0
    if ok:
        print(f"gate: FAIL - summary.ok is true but CLI exited {proc.returncode}")
    else:
        print("gate: FAIL - validation did not pass")
    return 1


if __name__ == "__main__":
    raise SystemExit(run_gate(sys.argv[1:]))
