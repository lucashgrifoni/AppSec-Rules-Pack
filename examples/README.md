# CI Integration Example

This template shows how a downstream repository can validate an AppSec rules
directory in GitHub Actions.

Pin `appsec-rules-pack` to a reviewed release version before using it in a production
quality gate.

```yaml
name: Validate AppSec Rules

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  appsec-rules:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out repository
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6
        with:
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6
        with:
          python-version: "3.12"

      - name: Install AppSec Rules Pack
        run: python -m pip install "appsec-rules-pack==0.4.0"

      - name: Validate rules
        run: appsec-rules validate rules --require-examples --fail-on-warnings --format json
```

For local development inside this repository, install the project in editable mode
and validate the bundled baseline rules:

```bash
python -m pip install -e ".[dev]"
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings --format json
```

Both examples apply the repository's strict validation flags: enabled rules need
compliant and violating examples, and warnings produce a failing exit code.
`tests/test_documented_gates.py` executes these documented commands against valid,
missing-example, and warning cases to keep the examples aligned with that contract.

## Portable JSON Gate (any CI or local shell)

[`validation_gate.py`](validation_gate.py) is a stdlib-only consumer of
`--format json` for systems other than GitHub Actions. It passes only when the CLI exits
`0` **and** the JSON reports `summary.ok: true`. Missing, malformed, or contradictory
output, or a CLI that cannot be started, fails the gate. Successfully starting the
process is not treated as a passing pack.

```bash
python -m pip install "appsec-rules-pack==0.4.0"   # pin a reviewed release
python examples/validation_gate.py rules --require-examples --fail-on-warnings
```

- `--require-examples` warns when an enabled rule lacks compliant/violating examples.
- `--fail-on-warnings` makes the CLI exit non-zero when any warning is present.

Real results against the repository fixtures:

| Fixture | CLI exit | `summary.ok` | Gate |
|---|---|---|---|
| `tests/fixtures/pass/minimal-valid.yaml` | `0` | `true` | PASS (`0`) |
| `tests/fixtures/fail/invalid-enum.yaml` | `1` | `false` | FAIL (`1`) |
