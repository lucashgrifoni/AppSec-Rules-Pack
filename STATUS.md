# AppSec Rules Pack Status

## Current Status

- Project 12 contains a Python 3.12 rules-pack validator, JSON Schema contract,
  a baseline AppSec rules pack of 12 rules across all schema categories, a Typer
  CLI, docs, unit fixtures, a coverage gate, and a hardened CI workflow.
- Validator coverage includes schema validation, duplicate rule IDs within a file
  and across a validated directory, exception-window warnings, exception-policy
  consistency checks, framework mapping format validation, sensitive-value
  detection, single-file and directory CLI validation, `--fail-on-warnings`,
  `--require-examples`, `--version`, and `--format json` output.
- Every baseline rule ships a compliant and a violating code example; the schema
  enforces the example shape and `--require-examples` flags enabled rules that omit it.
- An `export index` subcommand derives a machine-readable JSON rule index into
  `exports/` (derivation only). No export path for a real scanning engine exists; an
  execution/SARIF engine remains intentionally out of scope for the current increment.
- The project is now tracked in its own standalone Git repository with a hardened
  CI/CD surface (build/lint/test CI, a security pipeline, and OpenSSF Scorecard),
  Dependabot, CODEOWNERS, and community-health files.
- The GitHub repository `lucashgrifoni/AppSec-Rules-Pack` is **public** as of 2026-06-02,
  with About metadata populated (description, website, topics). `master` is not yet
  branch-protected (MEL-001).

## Last Increment

- 2026-06-02 (commit `0c23202`, pushed to `origin/master`): migrated all 12 baseline rules'
  `owasp_asvs` mappings to OWASP ASVS 5.0.0, re-derived by topic against the 5.0.0 chapter
  sources (OWASP publishes no official v4->v5 crosswalk). Regenerated
  `exports/appsec-baseline.index.json` and updated docs. Suite green: 78 tests at ~94%
  coverage; baseline 12 rules, 0 errors, 0 warnings. The repository was then made **public**
  and its About metadata (description, website, topics) populated.
- 2026-06-01 (commit `1e94c7b`, pushed to `origin/master`): added two baseline rules,
  `APPSEC-SESSION-001` (session cookie/lifecycle hardening) and `APPSEC-XSS-001`
  (output encoding / XSS), bringing the pack to 12 rules; added an `export index` CLI
  subcommand plus a checked-in `exports/appsec-baseline.index.json` with a drift test;
  and replaced the schema `$id` placeholder with a canonical, tag-versioned URL
  (documented via a schema `$comment`). The suite is now 78 tests at ~94% coverage.
  The two new rules were prioritised from a read-only coverage validation of the pack
  against a vulnerable-app test suite (gaps: session, rate limiting, CSRF, enumeration,
  XSS, webhook authenticity, data exposure).
- Prior (v0.1.0, 2026-05-25): released v0.1.0 (tag + GitHub Release) with wheel/sdist
  assets and green remote CI/CD; added the optional `examples` field plus the
  `--require-examples` flag and `tests/test_examples.py`.

## Checks

- `python -m pytest --cov` passed on 2026-06-01 with 78 tests at ~94% coverage
  (gate 90%); `ruff check .` clean; `validate rules --require-examples
  --fail-on-warnings` reported 1 file, 12 rules, 0 errors, 0 warnings; `export index`
  regenerates `exports/appsec-baseline.index.json` with no drift.
- 2026-06-02 (ASVS 5.0 remap): `pytest --cov` 78 passed at 93.71% (gate 90%); `ruff check .`
  clean; `validate ... --require-examples --fail-on-warnings` = 1 file, 12 rules, 0 errors,
  0 warnings; `export index` regenerated with no drift.
- 2026-06-02: commit `0c23202` pushed to `origin/master`; remote CI/CD verified **green**
  (`CI`, `Security CI/CD`, `OpenSSF Scorecard`, and `Dependency Graph` all succeeded).
- `python -m pytest` passed on 2026-05-25 with 69 tests.
- `python -m pytest --cov=appsec_rules_pack` reported 93% coverage on 2026-05-25
  (gate is 90%).
- `python -m ruff check .` passed on 2026-05-25.
- `$env:PYTHONPATH = "src"; python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings`
  passed on 2026-05-25 with 1 file, 10 rules, 0 errors, and 0 warnings.
- `python -m build` produced a wheel and sdist with the schema bundled.
- On 2026-05-25 the GitHub remote CI/CD ran green on `master` (commit `fff996d`):
  `CI`, `Security CI/CD`, and `OpenSSF Scorecard` all succeeded. A `.gitleaks.toml`
  was added to allowlist the intentional fake-secret fixtures in
  `tests/test_validator_paths.py` (Gitleaks false positive), keeping secret scanning
  active everywhere else.

## Risks And Limits

- Cross-file duplicate ID detection applies only when validating a directory with
  two or more YAML rule packs; single-file validation remains file-local.
- The rule model is still generic and review-oriented. It does not emit rules for
  Semgrep, CodeQL, SARIF, or another execution engine.
- Negative fixtures intentionally validate message stability, so future message
  changes must update tests and CLI expectations together.
- Mapping format checks are warnings, not errors, so unusual but valid identifiers
  are not blocked; review warnings during contribution.
- The CI/CD workflows run on the GitHub remote and are green on `master`. The repository
  is now public, but branch protection and required status checks are not yet configured
  (MEL-001) — direct pushes to `master` are still possible.

## Next Steps

- Enable branch protection and required status checks on `master` now that the repo is
  public and remote CI is green (MEL-001) — highest-value next step.
- (Done 2026-06-02) Migrated framework mappings to OWASP ASVS 5.0. OWASP publishes no
  official v4->v5 crosswalk, so identifiers were re-derived by topic against the 5.0.0
  chapter sources; mappings remain evidence aids, not a conformance claim.
- Keep engine export design separate from this validator. Expand baseline rules only
  when each addition has evidence and validation steps; decide whether rate limiting
  warrants a new schema `category` value before adding a rate-limiting rule.

## Resume Command

```powershell
cd "C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\Projects List - Andamento\12.Projeto - AppSec Rules Pack"
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
```
