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

## Now — Delivered through v0.6.0

- JSON Schema rule contract and a released baseline pack of 19 rules spanning access control,
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
- Tagged releases through `v0.5.0` published; see `STATUS.md` for current repository visibility.
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
- Tagged `v0.4.1` (2026-10-05): the rewritten README on the PyPI project page and the
  move of the default branch to `main`. No functional change.
- Tagged `v0.5.0` (2026-10-05): `appsec-rules review` checks per-service review records
  against a pack's exception policy (ADR-0006); a versioned JSON report with stable issue
  codes and `VERSIONING.md`; custom rule-id prefixes and `x-` extension keys;
  `appsec-rules init`; a restricted YAML loader; a property-based harness; and a release
  pipeline that builds with hash-pinned tools away from the publishing credential
  (ADR-0007).
- Optional `owasp_top_10_2025` mapping field (additive, backward-compatible) populated on
  the rules where a 2025 category maps cleanly.
- Rule lifecycle support: a `deprecated` status plus an optional `deprecation` block
  (reason, replaced_by, since), with validator consistency checks.

## Delivered in v0.9.0 (2026-10-07)

- Baseline version 0.9.0 with 29 rules: federated sign-in (ASVS V10), token issuance and
  verification (V9, V11.5), a second approver for high-risk actions (V2.3), sensitive
  data in storage and caches (V14), and safe deserialization (V1.5). Argument injection,
  privileged-attribute binding, and retrieval-corpus sources are covered in existing rules.
- An executable Semgrep reference rule for unsafe deserialization.
- Issue line and column, `validate` over several paths without entering linked
  directories, `init --id/--prefix`, longer review notes, reflowed help, and Python 3.11.
- A CI template that checks records against your own packs and takes its gate policy
  from variables, and an adoption feedback form for the 1.0 evidence.

## Delivered in v0.8.0 (2026-10-07)

- `assessed_severity` on review results, with `effective_severity` and
  `open_by_effective_severity` in the report; the rule-severity counts are unchanged.
- ADR-0009, which also rejects a record-level subject type on evidence from the lab
  records.

## Delivered in v0.7.0 (2026-10-06)

- Baseline version 0.7.0 with 24 rules: function-level authorization, prompt injection
  and model output handling, LLM tool and retrieval permissions, and an audit trail for
  sensitive records. Each closes a coverage gap found while reviewing the internal test
  labs with the 0.6.0 baseline.
- `init-review`, the `review-justification-missing` warning, `review.subject_ref`, the
  exception policy in `export index`, and `x-` fields carried into the review report.
- An optional OWASP Top 10 for LLM Applications 2025 mapping; ASVS becomes optional
  because ASVS 5.0.0 does not cover LLM prompts.

## Delivered in v0.6.0 (2026-10-05)

- Baseline version 0.6.0 with 20 rules, including password storage, CORS guidance,
  and a prohibition on secret fallback values.
- Per-rule mapping rationale, ASVS release-tag ID tests, and practice-level SSDF
  mappings with a proposed ADR.
- Advisory review-gate guidance, a versioned report compatibility floor, and a
  [1.0 readiness proposal](docs/v1-readiness.md) with external feedback pending
  from at least three users, subject to owner confirmation.
- SBOM root identity and installer-exclusion checks before artifact upload.
- Landing copy limited to pack validation and review records, with drift tests
  for its numeric claims and package version.

## Next — Near term

- Collect adoption feedback from external users through the issue form (#29); it is
  the remaining 1.0 criterion.
- Expand the baseline only where a reviewed application shows a gap that no rule
  covers; every gap found in the internal lab reviews is covered as of v0.9.0.
- Revisit a finer per-rule applicability vocabulary (for example "makes outbound
  requests" or "has user accounts") only with evidence from external records; ADR-0009
  rejected the coarse subject type.

## Later — Mid term

- More executable Semgrep reference rules (three as of v0.9.0: SQL injection, SSRF, and
  unsafe deserialization), each added only with positive and negative fixtures and kept
  separate from the validator (ADR-0005). An OPA/Rego mapping is not planned until a user
  asks for one; the JSON reports already feed any policy engine.
- Mapping depth stays at ASVS sections and SSDF practices (ADR-0008). v0.9.0 added ASVS
  V1.5, V2.3, V9, V10, V11.5, and V14.3 through the new rules.

## Future — Longer term

- Freeze the contract and cut `v1.0` once the external feedback criterion in
  `docs/v1-readiness.md` is met.

Delivered from earlier versions of this list: the reference gate is a required check in
this repository, and the CI template in `examples/README.md` takes its severities,
enforcement levels, and severity view from variables (v0.9.0).

## Explicit Non-Goals (current)

- No customer-specific controls, secrets, identifiers, endpoints, or proprietary data.
- No production enforcement integration in the current increment.
- No scanner-specific rule execution engine (Semgrep, CodeQL, OPA/Rego) and no SARIF
  results bundled into the validator; the SARIF export is a rule catalog with an empty
  `results` array.
- No vulnerability severity claims without evidence from the local rule content.
