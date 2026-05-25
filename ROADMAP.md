# Roadmap

This roadmap describes the intended direction of the AppSec Rules Pack. It is a
statement of intent, not a delivery commitment, and is kept consistent with
`STATUS.md` and the future extension points in `TECHNICAL_SPEC.md`.

## Principles

- Keep rules generic, reusable, and evidence-backed; never embed secrets, customer
  data, or environment-specific identifiers.
- Prefer deterministic, reviewable validation over broad checklist language.
- Add capabilities only when each one has tests and validation evidence.
- Treat scanner-specific execution engines as a deliberate, separate boundary.

## Now — Delivered (v0.1.0, pre-release)

- JSON Schema rule contract and a baseline pack of 10 rules across all schema
  categories.
- Python 3.12 validator with a Typer CLI: single-file and directory validation,
  `--fail-on-warnings`, `--version`, and `--format json` output.
- Semantic checks: duplicate IDs within a file and across a directory, exception
  window warnings, exception-policy consistency, framework mapping format validation,
  and sensitive-value detection.
- 59 tests, a 90% coverage gate (currently ~93%), ruff linting, and a build check.
- A hardened GitHub Actions CI workflow (least-privilege permissions, SHA-pinned
  actions), staged locally and ready for first use.
- Per-rule compliant and violating examples on every baseline rule, with an opt-in
  `--require-examples` validation flag (delivered after the v0.1.0 tag).

## Next — Near term

- Track this project in its own Git repository so the CI workflow runs on push and
  pull request.
- Cut the first tagged release (`v0.1.0`) with changelog and release notes once the
  repository is in place.
- Expand the baseline pack with additional generic rules where each addition has
  clear evidence, remediation, and validation steps (for example, cryptography,
  session management depth, and rate limiting / resource consumption).

## Later — Mid term

- Optional scanner-specific exports under `exports/` (for example, a mapping layer
  to Semgrep or policy formats), kept strictly separate from the validator so the
  rule contract stays engine-agnostic.
- Richer mapping coverage and validation (additional ASVS chapters, CWE coverage
  reports, and NIST SSDF task-level mapping).
- A machine-readable rule index and summary export to support downstream tooling.

## Future — Longer term

- Signed release evidence and provenance once versioned releases begin.
- Integration points for CI policy gates that consume the JSON output to block,
  warn, or baseline based on validation results.
- A documented rule lifecycle (draft → enabled → deprecated) with migration notes.

## Explicit Non-Goals (current)

- No customer-specific controls, secrets, identifiers, endpoints, or proprietary data.
- No production enforcement integration in the current increment.
- No scanner-specific rule execution engine (Semgrep, CodeQL, OPA/Rego, SARIF
  emission) bundled into the validator.
- No vulnerability severity claims without evidence from the local rule content.
