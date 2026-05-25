# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Added an optional `examples` field to the rule schema: each rule may declare a
  `compliant` and a `violating` example with `language`, `snippet`, and `explanation`.
  The schema enforces the shape when present.
- Populated all 10 baseline rules with explicit compliant and violating examples.
- Added a `--require-examples` CLI flag that warns when an enabled rule ships no
  examples; the CI baseline validation now runs with it.
- Excluded rule `examples` from sensitive-value detection, since violating examples
  intentionally demonstrate insecure anti-patterns.

## v0.1.0 - 2026-05-25

- Initialized the standalone repository and prepared the first local `v0.1.0`
  release candidate.
- Added a `.gitleaks.toml` that allowlists the intentional fake-secret fixtures in
  `tests/test_validator_paths.py`, clearing a Gitleaks false positive while keeping
  secret scanning active everywhere else.
- Added a packaging metadata pass for PyPI (license, classifiers, keywords, and
  project URLs).
- Added a security pipeline (Semgrep, CodeQL, Bandit, Trivy, KICS, pip-audit,
  Gitleaks, Dependency Review, actionlint), OpenSSF Scorecard analysis,
  Dependabot, and CODEOWNERS.
- Added community-health files: a code of conduct, issue templates, a pull
  request template, and a CI integration template under `examples/`.
- Added technical specification, AppSec rule schema, initial baseline rules,
  validator CLI, documentation, and tests.
- Added baseline security reporting documentation.
- Added pass/fail validation fixtures, directory validation support, clearer schema
  validation messages, and CLI coverage for file and directory inputs.
- Added negative fixtures for enum, type, additionalProperties, and duplicate rule
  ID validation.
- Added cross-file duplicate rule ID validation for directory inputs.
- Added warning fixtures, `--fail-on-warnings` coverage, and packaging build tests.
- Expanded test coverage for loader errors, schema message branches, sensitive-value
  patterns, and CLI edge cases, with a 90% coverage gate.
- Single-sourced the package version and added a `--version` CLI flag.
- Added exception-policy consistency checks (disallowed exceptions that still declare
  a window or fields are errors; allowed exceptions missing core fields warn).
- Added framework mapping identifier format validation for CWE, OWASP API Top 10 2023,
  OWASP ASVS, and NIST SSDF.
- Added `--format json` machine-readable validation output for CI.
- Added four baseline rules covering authentication, logging, dependency risk, and
  configuration, bringing the pack to 10 rules across all schema categories.
- Added a hardened GitHub Actions CI workflow with least-privilege permissions and
  SHA-pinned actions.
