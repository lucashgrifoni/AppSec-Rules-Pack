# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Added derivation-only export and reporting commands (engine-agnostic, see ADR-0001):
  `report coverage` (framework-mapping coverage as text/JSON), `export semgrep` (a clearly
  labeled NON-runnable Semgrep scaffold), and `export sarif` (a SARIF 2.1.0 rule catalog
  with empty results). Checked-in `exports/` artifacts are drift-tested.
- Added reference CI workflows: `policy-gate.yml` (a separate gate that consumes the
  validator JSON, per ADR-0004) and `release.yml` (build + CycloneDX SBOM + SLSA build
  provenance attestation + PyPI Trusted Publishing via OIDC; the PyPI publisher config is
  an owner handoff).
- Expanded the baseline pack from 12 to 19 rules: `APPSEC-CSRF-001` (CSRF),
  `APPSEC-ENUM-001` (user enumeration), `APPSEC-MSGAUTH-001` (webhook/message authenticity),
  `APPSEC-DATAEXPO-001` (excessive data exposure), `APPSEC-MASSASSIGN-001` (mass assignment),
  `APPSEC-REDIRECT-001` (open redirect), and `APPSEC-RATELIMIT-001` (rate limiting). Each
  ships compliant and violating examples and ASVS 5.0 / API Top 10 / CWE / NIST SSDF mappings.
- Added an optional `owasp_top_10_2025` mapping field (OWASP Top 10:2025, for example
  `A01:2025`), populated where a 2025 category maps cleanly. Backward-compatible.
- Added rule-lifecycle support: a `deprecated` status and an optional `deprecation` block
  (reason, replaced_by, since), with validator consistency warnings.
- Extended the `category` vocabulary with `csrf`, `integrity`, `data-exposure`,
  `open-redirect`, and `rate-limiting` (additive; existing rules unaffected).
- Migrated all baseline rule `owasp_asvs` mappings to OWASP ASVS 5.0.0. The 5.0
  reorganization renumbered chapters, so identifiers were re-derived by topic against
  the official 5.0.0 chapter sources (OWASP publishes no v4-to-v5 crosswalk) — for
  example authorization `V4.1`->`V8.2`, authentication/session `V2.1,V3.2`->`V6.3,V7.2`,
  injection/XSS `V5.3`->`V1.2`, logging `V7.1`->`V16.2,V16.3`, configuration/secrets
  `V14.1,V14.8`->`V13.4,V13.3`, dependencies `V14.2`->`V15.2`, files `V12.1`->`V5.2,V5.3`,
  SSRF `V12.6`->`V1.3`. Mappings remain evidence aids, not a conformance claim.
- Added two baseline rules, raising the pack to 12 rules: `APPSEC-SESSION-001`
  (session cookie and lifecycle hardening) and `APPSEC-XSS-001` (output encoding /
  cross-site scripting). Both ship compliant and violating examples and were prioritised
  from coverage gaps observed against a vulnerable-app test suite.
- Added an `export index` CLI subcommand that derives a machine-readable JSON rule
  index (pack id/name/version plus per-rule id, title, severity, category, status,
  enforcement, targets, and mappings). Derivation only — it never executes rules,
  preserving the engine-agnostic boundary.
- Added a checked-in derived index at `exports/appsec-baseline.index.json` with a
  drift test that keeps it in sync with the pack.
- Replaced the schema `$id` placeholder (`example.invalid`) with a canonical,
  tag-versioned URL and documented the versioning policy via a schema `$comment`.
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
