# AppSec Rules Pack

[![CI](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/ci.yml/badge.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/ci.yml)
[![Security CI/CD](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/security-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/security-ci-cd.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lucashgrifoni/AppSec-Rules-Pack/badge)](https://scorecard.dev/viewer/?uri=github.com/lucashgrifoni/AppSec-Rules-Pack)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)

Reusable AppSec policy-as-code rules for secure application review, CI quality gates,
and manual evidence collection.

This initial pack is intentionally generic. It does not contain product names,
tenant identifiers, customer data, secrets, internal endpoints, or environment-specific
configuration.

## What Is Included

- A short technical specification in `TECHNICAL_SPEC.md` and a direction summary in
  `ROADMAP.md`.
- A JSON Schema rule contract in `src/appsec_rules_pack/schemas/appsec-rule.schema.json`.
- A baseline YAML rules pack of 10 generic rules in `rules/appsec-baseline.yaml`,
  covering authentication, authorization, input validation, injection, SSRF, secrets,
  file handling, logging, dependency risk, and configuration. Every rule ships an
  explicit compliant and violating code example.
- A Python 3.12 validator with a Typer CLI supporting `--version`,
  `--fail-on-warnings`, `--require-examples`, and `--format json` output for CI.
- Unit tests and pass/fail/warn fixtures for valid packs, invalid schema shape,
  enum/type/additionalProperties failures, duplicate rule IDs, cross-file
  duplicate IDs, exception-window warnings, exception-policy contradictions,
  malformed framework mapping IDs, and sensitive-value detection.
- A 90% coverage gate plus a hardened CI/CD surface: a build/lint/test workflow,
  a security pipeline (Semgrep, CodeQL, Bandit, Trivy, KICS, pip-audit, Gitleaks,
  Dependency Review, actionlint), and OpenSSF Scorecard analysis.
- Contribution guidance for safe rule additions, a code of conduct, and issue/PR
  templates.
- A CI integration template in `examples/`.

## Project Layout

```text
.
|-- .github/
|   |-- ISSUE_TEMPLATE/
|   |   |-- bug_report.md
|   |   |-- config.yml
|   |   `-- rule_proposal.md
|   |-- workflows/
|   |   |-- ci.yml
|   |   |-- scorecard.yml
|   |   `-- security-ci-cd.yml
|   |-- CODEOWNERS
|   |-- PULL_REQUEST_TEMPLATE.md
|   `-- dependabot.yml
|-- examples/
|   `-- README.md
|-- rules/
|   `-- appsec-baseline.yaml
|-- src/
|   `-- appsec_rules_pack/
|       |-- __init__.py
|       |-- __main__.py
|       |-- cli.py
|       |-- loader.py
|       |-- validator.py
|       `-- schemas/
|           `-- appsec-rule.schema.json
|-- tests/
|   |-- fixtures/
|   |   |-- cross-file-dup/
|   |   |-- exception-consistency/
|   |   |-- fail/
|   |   |-- pass/
|   |   `-- warn/
|   |-- test_edge_cases.py
|   |-- test_examples.py
|   |-- test_loader.py
|   |-- test_packaging.py
|   |-- test_validator.py
|   `-- test_validator_paths.py
|-- CHANGELOG.md
|-- CODE_OF_CONDUCT.md
|-- CONTRIBUTING.md
|-- LICENSE
|-- README.md
|-- ROADMAP.md
|-- SECURITY.md
|-- STATUS.md
|-- TECHNICAL_SPEC.md
`-- pyproject.toml
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

On macOS/Linux:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

If the dependencies already exist in the active Python environment, the validator can
also be run directly with `PYTHONPATH=src`.

## Usage

Validate the baseline rules pack:

```bash
python -m appsec_rules_pack validate rules/appsec-baseline.yaml
```

Validate every `.yaml` or `.yml` rules pack under a directory:

```bash
python -m appsec_rules_pack validate rules
```

Or, after installation, use the console script:

```bash
appsec-rules validate rules/appsec-baseline.yaml
```

Fail on warnings as well as errors:

```bash
appsec-rules validate rules/appsec-baseline.yaml --fail-on-warnings
```

Warn when an enabled rule ships no compliant/violating examples (opt-in):

```bash
appsec-rules validate rules --require-examples
```

Emit machine-readable JSON for CI pipelines:

```bash
appsec-rules validate rules --format json
```

Show the installed version:

```bash
appsec-rules --version
```

The JSON report contains a `summary` object (`files`, `rules`, `errors`, `warnings`,
`ok`) and a `files` array with per-file issues (`level`, `path`, `message`). The exit
code is non-zero when validation fails, matching the text output.

## Use It In Your CI

`examples/README.md` contains a GitHub Actions template for installing the pack,
validating a rules directory, and failing the build on errors (and optionally
warnings). Pin the template to a reviewed tag or commit before enabling it as a
quality gate.

## Rule Pack Model

Rules are advisory by default. Each rule defines:

- a stable ID and severity;
- the target surface and AppSec category;
- framework mappings such as OWASP ASVS, OWASP API Security Top 10, CWE, and NIST SSDF;
- expected evidence and review signals;
- match guidance for reviewers or automation;
- remediation and validation guidance;
- exception metadata requirements;
- a compliant and a violating code example with a short explanation.

The initial version is optimized for reviewability and deterministic validation, not for
deep scanner-specific matching.

## Validation

```bash
python -m pytest
PYTHONPATH=src python -m appsec_rules_pack validate rules
```

The validator checks JSON Schema compliance, duplicate rule IDs within a file and across
a validated directory, exception-window limits, exception-policy contradictions
(for example, a disallowed exception that still declares a window), malformed framework
mapping identifiers (CWE, OWASP API Top 10 2023, OWASP ASVS, NIST SSDF), and basic
sensitive-value patterns. Directory validation reports each issue with the relative file
path, schema path, severity, and a concise remediation-oriented message.

## Contributing

See `CONTRIBUTING.md` for rule authoring principles, the severity model, exception
requirements, and the required checks. All participation is governed by
`CODE_OF_CONDUCT.md`. To report a security issue, follow `SECURITY.md`.

## License

Licensed under the Apache License 2.0. See `LICENSE`.
