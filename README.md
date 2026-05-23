# AppSec Rules Pack

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
  file handling, logging, dependency risk, and configuration.
- A Python 3.12 validator with a Typer CLI supporting `--version`,
  `--fail-on-warnings`, and `--format json` output for CI.
- Unit tests and pass/fail/warn fixtures for valid packs, invalid schema shape,
  enum/type/additionalProperties failures, duplicate rule IDs, cross-file
  duplicate IDs, exception-window warnings, exception-policy contradictions,
  malformed framework mapping IDs, and sensitive-value detection.
- A coverage gate and a hardened GitHub Actions CI workflow.
- Contribution guidance for safe rule additions.

## Project Layout

```text
.
|-- .github/
|   `-- workflows/
|       `-- ci.yml
|-- CONTRIBUTING.md
|-- README.md
|-- TECHNICAL_SPEC.md
|-- pyproject.toml
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
`-- tests/
    |-- fixtures/
    |   |-- cross-file-dup/
    |   |   |-- first-pack.yaml
    |   |   `-- second-pack.yaml
    |   |-- exception-consistency/
    |   |   `-- disallowed-with-window.yaml
    |   |-- fail/
    |   |   |-- additional-property.yaml
    |   |   |-- duplicate-id.yaml
    |   |   |-- invalid-enum.yaml
    |   |   |-- invalid-type.yaml
    |   |   `-- missing-required-field.yaml
    |   |-- pass/
    |   |   `-- minimal-valid.yaml
    |   `-- warn/
    |       `-- exception-window-warning.yaml
    |-- test_loader.py
    |-- test_packaging.py
    |-- test_validator.py
    `-- test_validator_paths.py
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

If the dependencies already exist in the active Python environment, the validator can
also be run directly with `PYTHONPATH=src`.

## Usage

Validate the baseline rules pack:

```powershell
python -m appsec_rules_pack validate rules/appsec-baseline.yaml
```

Validate every `.yaml` or `.yml` rules pack under a directory:

```powershell
python -m appsec_rules_pack validate rules
```

Or, after installation:

```powershell
appsec-rules validate rules/appsec-baseline.yaml
```

Fail on warnings as well as errors:

```powershell
appsec-rules validate rules/appsec-baseline.yaml --fail-on-warnings
```

Emit machine-readable JSON for CI pipelines:

```powershell
appsec-rules validate rules --format json
```

Show the installed version:

```powershell
appsec-rules --version
```

The JSON report contains a `summary` object (`files`, `rules`, `errors`, `warnings`,
`ok`) and a `files` array with per-file issues (`level`, `path`, `message`). The exit
code is non-zero when validation fails, matching the text output.

## Rule Pack Model

Rules are advisory by default. Each rule defines:

- a stable ID and severity;
- the target surface and AppSec category;
- framework mappings such as OWASP ASVS, OWASP API Security Top 10, CWE, and NIST SSDF;
- expected evidence and review signals;
- match guidance for reviewers or automation;
- remediation and validation guidance;
- exception metadata requirements.

The first release is optimized for reviewability and deterministic validation, not for
deep scanner-specific matching.

## Validation

```powershell
python -m pytest
$env:PYTHONPATH = "src"; python -m appsec_rules_pack validate rules
```

The validator checks JSON Schema compliance, duplicate rule IDs within a file and across
a validated directory, exception-window limits, exception-policy contradictions
(for example, a disallowed exception that still declares a window), malformed framework
mapping identifiers (CWE, OWASP API Top 10 2023, OWASP ASVS, NIST SSDF), and basic
sensitive-value patterns. Directory validation reports each issue with the relative file
path, schema path, severity, and a concise remediation-oriented message.
