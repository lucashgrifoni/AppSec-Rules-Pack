# Technical Specification

## Goal

Create a small, reviewable AppSec rules pack that can be versioned, validated, and used
as a starting point for secure code review or CI policy gates.

## Scope

- Generic AppSec baseline rules only.
- YAML rule pack authored against a JSON Schema contract.
- Python 3.12+ CLI validator using Typer.
- Review records: the per-rule outcome of reviewing one subject against a pack, checked
  against the pack's exception policy (ADR-0006).
- Unit tests for structural and semantic validation.
- Documentation for setup, usage, and contribution.

## Non-Goals

- No customer-specific controls, secrets, identifiers, endpoints, or proprietary data.
- No production enforcement built into the validator; `policy-gate.yml` is a reference
  gate that consumes the validator JSON (ADR-0004), not a managed enforcement service.
- No execution of rules or code scanning in any engine (Semgrep, CodeQL, OPA/Rego).
  The `exports/` Semgrep scaffold and SARIF catalog are derivation-only references
  (a non-runnable scaffold and a no-results catalog), not working detections (ADR-0001).
- No vulnerability severity claims without evidence from the local rule content.

## Rule Contract

A rules pack contains:

- `pack`: metadata for ID, name, version, mode, owner, and description.
- `rules`: one or more rule objects.

Each rule contains:

- identity: `id`, `title`, `description`, `status`;
- policy attributes: `severity`, `category`, `enforcement`, `targets`;
- evidence mappings: `mappings`, `evidence`, `match`;
- remediation guidance: `remediation`;
- exception process: `exceptions`.

Optional parts: `pack.schema_version` declares the schema version a pack targets;
`examples` and `deprecation` on a rule; the `owasp_top_10_2025` and
`owasp_api_top_10_2023` mappings; and `x-` prefixed extension keys on the pack, on rules,
and in `mappings`. Rule ids follow `PREFIX-AREA-NNN`. `VERSIONING.md` defines what may
change between releases.

## Validation Design

The validator performs two layers of checks:

1. Structural validation against `appsec-rule.schema.json`.
2. Semantic validation for:
   - duplicate IDs within a file and across YAML files in a validated directory;
   - exception expiry limits above the default review window (warning);
   - exception-policy contradictions, such as a disallowed exception that still
     declares a non-zero window or required fields (error), or an allowed exception
     missing core accountability fields (warning);
   - malformed framework mapping identifiers for CWE, OWASP API Top 10 2023,
     OWASP ASVS, NIST SSDF, and the optional OWASP Top 10:2025 (warning);
   - rule-lifecycle consistency: a `deprecated` status should carry a `deprecation`
     block, and a `deprecation` block should accompany a `deprecated` status (warning);
   - sensitive-value patterns in free-text fields (error).

Results are available as human-readable text or as structured JSON (`--format json`)
for CI consumption.

## Review Records

`appsec-rules review <pack> <record>` checks a record (`review-record.schema.json`)
against a valid pack. It reports an error when the record names another pack, names an
unknown rule or one rule twice, marks a rule `met` without evidence, or holds an exception
the rule forbids, that lacks a field the rule requires, that has expired as of the run
date (`--as-of`, today by default), or that runs longer than `max_days` from `granted_at`
or the review date. Enabled rules with no result are `unreviewed` (warning). The JSON
report (`appsec-rules-review/v1`) counts open rules (`not-met` or `unreviewed`) by
enforcement and severity. The command does not read the reviewed code, and its exit code
does not depend on open rules: the gate decides.

## Security And Governance Lens

- Default mode is advisory to avoid accidental break-build behavior.
- Rules must include owner-ready remediation and validation guidance.
- Exceptions require owner, justification, and expiry metadata.
- Sensitive or environment-specific data must not be committed to the pack.
- Framework mappings reference OWASP ASVS 5.0.0 and are evidence aids, not a claim of
  full ASVS or NIST compliance.

## Future Extension Points

- Deepen reference exports under `exports/` (rule index, Semgrep scaffold, and SARIF
  rule catalog are delivered; add real detection patterns or other formats as needed).
- Add executable detection fixtures only alongside a separate engine-specific layer.
  Every baseline rule already includes compliant and violating examples, checked by
  `tests/test_examples.py`; validator pass/fail fixtures live in `tests/fixtures/`.

Signed release evidence is in place: tagged releases publish to PyPI via Trusted
Publishing (OIDC, no long-lived token) and attach a CycloneDX SBOM plus a SLSA
build-provenance attestation through `.github/workflows/publish-pypi.yml`.

CI integration via GitHub Actions (`.github/workflows/ci.yml`) and a coverage gate
are in place — the workflow lints, tests with coverage, validates the baseline with
`--fail-on-warnings`, and builds distribution artifacts — alongside a security
pipeline (`security-ci-cd.yml`), OpenSSF Scorecard (`scorecard.yml`), and a reference
policy gate (`policy-gate.yml`).
