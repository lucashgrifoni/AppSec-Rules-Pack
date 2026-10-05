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

## Now — Delivered through v0.4.0

- JSON Schema rule contract and a baseline pack of 19 rules spanning access control,
  injection/XSS, SSRF, authentication, session hardening, secrets, file handling, logging,
  dependencies, configuration, CSRF, integrity/webhook authenticity, excessive data
  exposure, mass assignment, open redirect, and rate limiting.
- Python 3.12+ validator with a Typer CLI: single-file and directory validation,
  `--fail-on-warnings`, `--require-examples`, `--version`, and `--format json` output;
  derivation-only `export index`, `export semgrep`, `export sarif`, and `report coverage`.
- Semantic checks: duplicate IDs within a file and across a directory, exception
  window warnings, exception-policy consistency, framework mapping format validation,
  and sensitive-value detection.
- A test suite with a 95% coverage gate (currently ~97%), ruff linting, and a build check.
- A hardened GitHub Actions CI/CD surface (least-privilege permissions, SHA-pinned
  actions): build/lint/test CI, a security pipeline, and OpenSSF Scorecard. See
  `STATUS.md` for dated remote results; configured workflows do not imply passing runs.
- Per-rule compliant and violating examples on every baseline rule, with an opt-in
  `--require-examples` validation flag (delivered after the v0.1.0 tag).
- All `owasp_asvs` mappings migrated to OWASP ASVS 5.0.0 (assigned by topic and verified
  against the 5.0.0 chapter/section structure and the official v5.0.0-to-v4.0.3 mapping
  under `5.0/mappings/`). Mappings remain evidence aids, not a claim.
- Tagged releases through `v0.4.0` published; see `STATUS.md` for current repository visibility.
- The default branch is protected by a ruleset (2026-06-03); renamed from `master` to `main`
  on 2026-10-05.
- Tagged `v0.2.0` published to PyPI as `appsec-rules-pack` via OIDC Trusted Publishing
  (2026-06-03), with a CycloneDX SBOM and a SLSA build-provenance attestation attached to
  the GitHub Release.
- Tagged `v0.3.0` published (2026-08-05). Each Release now also carries the baseline pack
  itself as `appsec-baseline.yaml`, so consumers can pin a copy of the 19 rules without
  cloning; the distribution still ships the validator and schema only.
- Tagged `v0.3.1` published (2026-08-27), with controlled CLI read/write errors,
  text coverage-report output, and corrected validation-summary pluralization. The
  release workflow attests the baseline pack and SBOM as well as the wheel and sdist.
- Tagged `v0.4.0` (2026-10-05): an optional, tested Semgrep layer with two Python/Flask
  detections, a portable downstream JSON gate example, strict example commands, issue
  forms, and the signed provenance bundle attached to each Release.
- Optional `owasp_top_10_2025` mapping field (additive, backward-compatible) populated on
  the rules where a 2025 category maps cleanly.
- Rule lifecycle support: a `deprecated` status plus an optional `deprecation` block
  (reason, replaced_by, since), with validator consistency checks.

## Next — Near term

- Expand the baseline pack further by demand where each addition has clear evidence,
  remediation, and validation steps (for example, cryptography-at-rest and additional
  business-logic abuse cases); the CSRF, enumeration, webhook-authenticity, data-exposure,
  mass-assignment, open-redirect, and rate-limiting rules are now delivered.

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
