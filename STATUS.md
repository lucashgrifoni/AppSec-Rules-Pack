# AppSec Rules Pack Status

## Current Status

- Project 12 contains a Python 3.12 rules-pack validator, JSON Schema contract,
  a baseline AppSec rules pack of 10 rules across all schema categories, a Typer
  CLI, docs, unit fixtures, a coverage gate, and a hardened CI workflow.
- Validator coverage includes schema validation, duplicate rule IDs within a file
  and across a validated directory, exception-window warnings, exception-policy
  consistency checks, framework mapping format validation, sensitive-value
  detection, single-file and directory CLI validation, `--fail-on-warnings`,
  `--version`, and `--format json` output.
- No export path for a real scanning engine exists yet; this remains intentionally
  out of scope for the current increment.
- The project is now tracked in its own standalone Git repository with a hardened
  CI/CD surface (build/lint/test CI, a security pipeline, and OpenSSF Scorecard),
  Dependabot, CODEOWNERS, and community-health files.

## Last Increment

- Added test coverage for loader errors, schema message branches, sensitive-value
  patterns, and CLI edge cases; enforced a 90% coverage gate.
- Single-sourced the package version and added a `--version` CLI flag.
- Added exception-policy consistency checks and framework mapping format validation.
- Added `--format json` machine-readable output for CI.
- Added authentication, logging, dependency-risk, and configuration baseline rules,
  bringing the pack to 10 rules.
- Added a hardened GitHub Actions workflow (least-privilege permissions,
  SHA-pinned actions) and cached schema loading.
- Added negative and edge-case tests for empty files, non-mapping rules, alternate
  file extensions, and mixed directories.

## Checks

- `python -m pytest` passed on 2026-05-22 with 59 tests.
- `python -m pytest --cov=appsec_rules_pack` reported 93% coverage on 2026-05-22
  (gate is 90%).
- `python -m ruff check .` passed on 2026-05-22.
- `$env:PYTHONPATH = "src"; python -m appsec_rules_pack validate rules --fail-on-warnings`
  passed on 2026-05-22 with 1 file, 10 rules, 0 errors, and 0 warnings.
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
- The CI/CD workflows now run on the GitHub remote and are green on `master`.
  Branch protection and required status checks are not yet configured.

## Next Steps

- Enable branch protection and required status checks now that remote CI is green.
- Add per-rule pass/fail fixtures so every baseline rule has an explicit example.
- Keep engine export design separate from this validator fixture work.
- Expand baseline rules only when each addition has evidence and validation steps.

## Resume Command

```powershell
cd "C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\Projects List - Andamento\12.Projeto - AppSec Rules Pack"
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
```
