# AppSec Rules Pack Status

## Current Status

- Project 12 contains a Python 3.12 rules-pack validator, JSON Schema contract,
  a baseline AppSec rules pack of 10 rules across all schema categories, a Typer
  CLI, docs, unit fixtures, a coverage gate, and a hardened CI workflow.
- Validator coverage includes schema validation, duplicate rule IDs within a file
  and across a validated directory, exception-window warnings, exception-policy
  consistency checks, framework mapping format validation, sensitive-value
  detection, single-file and directory CLI validation, `--fail-on-warnings`,
  `--require-examples`, `--version`, and `--format json` output.
- Every baseline rule ships a compliant and a violating code example; the schema
  enforces the example shape and `--require-examples` flags enabled rules that omit it.
- No export path for a real scanning engine exists yet; this remains intentionally
  out of scope for the current increment.
- The project is now tracked in its own standalone Git repository with a hardened
  CI/CD surface (build/lint/test CI, a security pipeline, and OpenSSF Scorecard),
  Dependabot, CODEOWNERS, and community-health files.

## Last Increment

- Released v0.1.0 (tag + GitHub Release) with wheel/sdist assets and green remote CI/CD.
- Added an optional `examples` field to the rule schema (compliant + violating, each
  with language/snippet/explanation) and populated all 10 baseline rules.
- Added the `--require-examples` CLI flag and wired it into the CI baseline validation;
  excluded examples from sensitive-value detection.
- Added `tests/test_examples.py`; the suite is now 69 tests at ~93% coverage.

## Checks

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
- The CI/CD workflows now run on the GitHub remote and are green on `master`.
  Branch protection and required status checks are not yet configured.

## Next Steps

- Enable branch protection and required status checks now that remote CI is green.
- Keep engine export design separate from this validator fixture work.
- Expand baseline rules only when each addition has evidence and validation steps.

## Resume Command

```powershell
cd "C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\Projects List - Andamento\12.Projeto - AppSec Rules Pack"
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
```
