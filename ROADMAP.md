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

- JSON Schema rule contract and a baseline pack of 19 rules spanning access control,
  injection/XSS, SSRF, authentication, session hardening, secrets, file handling, logging,
  dependencies, configuration, CSRF, integrity/webhook authenticity, excessive data
  exposure, mass assignment, open redirect, and rate limiting.
- Python 3.12 validator with a Typer CLI: single-file and directory validation,
  `--fail-on-warnings`, `--version`, `--format json` output, and an `export index`
  subcommand that derives a machine-readable rule index (derivation only).
- Semantic checks: duplicate IDs within a file and across a directory, exception
  window warnings, exception-policy consistency, framework mapping format validation,
  and sensitive-value detection.
- 78 tests, a 90% coverage gate (currently ~94%), ruff linting, and a build check.
- A hardened GitHub Actions CI/CD surface (least-privilege permissions, SHA-pinned
  actions): build/lint/test CI, a security pipeline, and OpenSSF Scorecard, running on
  the public GitHub remote and green on `master`.
- Per-rule compliant and violating examples on every baseline rule, with an opt-in
  `--require-examples` validation flag (delivered after the v0.1.0 tag).
- All `owasp_asvs` mappings migrated to OWASP ASVS 5.0.0 (re-derived by topic; OWASP
  publishes no official v4->v5 crosswalk). Mappings remain evidence aids, not a claim.
- Tagged `v0.1.0` release published; the GitHub repository is public as of 2026-06-02.
- Optional `owasp_top_10_2025` mapping field (additive, backward-compatible) populated on
  the rules where a 2025 category maps cleanly.
- Rule lifecycle support: a `deprecated` status plus an optional `deprecation` block
  (reason, replaced_by, since), with validator consistency checks.

## Next — Near term

- Enable branch protection and required status checks on `master` now that the repository
  is public and CI is green.
- Expand the baseline pack further by demand where each addition has clear evidence,
  remediation, and validation steps (for example, cryptography-at-rest and additional
  business-logic abuse cases); the CSRF, enumeration, webhook-authenticity, data-exposure,
  mass-assignment, open-redirect, and rate-limiting rules are now delivered.
- Finish the v0.3 supply-chain release path: the `release.yml` workflow (CycloneDX SBOM +
  SLSA build-provenance attestation + PyPI Trusted Publishing via OIDC) is in place;
  configure the PyPI Trusted Publisher and the `pypi` environment, then cut a tagged
  release to exercise it end to end.

## Later — Mid term

- Deepen the reference exports (delivered: rule index, Semgrep scaffold, SARIF rule
  catalog, and a coverage report) — for example real Semgrep detection patterns or an
  OPA/Rego mapping, kept strictly separate from the validator so the contract stays
  engine-agnostic.
- Richer mapping coverage (additional ASVS chapters and NIST SSDF task-level mapping).

## Future — Longer term

- Stabilize the expanded contract (new categories, rule lifecycle, the optional 2025
  mapping, and the exports) and cut a `v1.0` with frozen schema guarantees once it has
  had real-world use.
- Promote the reference `policy-gate.yml` (which already consumes the validator JSON) to
  an enforced required check where teams want it, with tunable severity thresholds.

## Explicit Non-Goals (current)

- No customer-specific controls, secrets, identifiers, endpoints, or proprietary data.
- No production enforcement integration in the current increment.
- No scanner-specific rule execution engine (Semgrep, CodeQL, OPA/Rego, SARIF
  emission) bundled into the validator.
- No vulnerability severity claims without evidence from the local rule content.
