# Technical Specification

## Goal

Create a small, reviewable AppSec rules pack that can be versioned, validated, and used
as a starting point for secure code review or CI policy gates.

## Scope

- Generic AppSec baseline rules only.
- YAML rule pack authored against a JSON Schema contract.
- Python 3.12 CLI validator using Typer.
- Unit tests for structural and semantic validation.
- Documentation for setup, usage, and contribution.

## Non-Goals

- No customer-specific controls, secrets, identifiers, endpoints, or proprietary data.
- No production enforcement integration in the first skeleton.
- No scanner-specific rule language such as Semgrep, CodeQL, OPA/Rego, or SARIF output yet.
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
     OWASP ASVS, and NIST SSDF (warning);
   - sensitive-value patterns in free-text fields (error).

Results are available as human-readable text or as structured JSON (`--format json`)
for CI consumption.

## Security And Governance Lens

- Default mode is advisory to avoid accidental break-build behavior.
- Rules must include owner-ready remediation and validation guidance.
- Exceptions require owner, justification, and expiry metadata.
- Sensitive or environment-specific data must not be committed to the pack.
- Framework mappings are evidence aids, not a claim of full ASVS or NIST compliance.

## Future Extension Points

- Add scanner-specific exports under `exports/`.
- Add pass/fail fixtures per rule under `fixtures/`.
- Add signed release evidence once versioned releases begin.

CI integration via GitHub Actions (`.github/workflows/ci.yml`) and a coverage gate
are already in place; the workflow lints, tests with coverage, validates the baseline
with `--fail-on-warnings`, and builds distribution artifacts.
