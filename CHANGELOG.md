# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

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
