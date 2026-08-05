# Project Status

Current state of the project, kept consistent with `README.md`, `ROADMAP.md`, and
`TECHNICAL_SPEC.md`. Release-by-release detail lives in [`CHANGELOG.md`](CHANGELOG.md);
this file describes where the project stands and what is known to be true right now.

## Where it stands

**Released:** `appsec-rules-pack` **0.3.0**, published to PyPI via Trusted Publishing
(OIDC, no long-lived credential). Each GitHub Release carries the wheel, the sdist, a
CycloneDX SBOM, a SLSA build-provenance attestation, and the baseline pack itself as
`appsec-baseline.yaml`.

**What ships:** a JSON Schema rule contract, a Python 3.12+ validator with a Typer CLI, and
derivation-only export and reporting commands. The distribution contains the validator and
the schema — not the rules; the baseline pack is attached to each release and lives in
[`rules/appsec-baseline.yaml`](rules/appsec-baseline.yaml).

**The baseline pack:** 19 generic rules spanning access control, injection and XSS, SSRF,
authentication, session hardening, secrets, file handling, logging, dependency risk,
configuration, CSRF, webhook integrity, excessive data exposure, mass assignment, open
redirect, and rate limiting. Every rule ships a compliant and a violating example.

**Validator coverage:** JSON Schema validation, duplicate rule IDs within a file and across
a validated directory, exception-window warnings, exception-policy consistency, framework
mapping format checks, rule-lifecycle consistency, and sensitive-value detection. Single-file
and directory validation, `--fail-on-warnings`, `--require-examples`, `--version`, and
`--format json` for CI.

**Derived artifacts:** `export index`, `export semgrep`, `export sarif`, and
`report coverage` produce the drift-tested files under [`exports/`](exports/). The Semgrep
output is a clearly-labelled non-runnable scaffold and the SARIF output is a rule catalog
with no results — the validator never executes rules or scans code
([ADR-0001](docs/adr/0001-engine-agnostic-validator.md)).

**Repository posture:** public, with `master` protected by a ruleset requiring a pull
request and fourteen status checks (build/lint/test, both cross-platform jobs, the Python
3.13 job, and the security pipeline's ten unconditional jobs). The repository owner retains
an admin bypass by design, so owner pushes are still possible; every other actor must open a
pull request that passes the checks.

## Verified checks

Last measured 2026-08-05 on Windows 11 with Python 3.12.10, and confirmed on CI:

| Check | Result |
| --- | --- |
| `ruff check .` | clean |
| `pytest --cov` | 130 passed, 97.46% coverage (gate 95%) |
| `validate rules --require-examples --fail-on-warnings` | 1 file, 19 rules, 0 errors, 0 warnings |
| `report coverage` | ASVS, API Top 10, CWE, SSDF at 19/19; optional Top 10:2025 at 17/19 |
| `exports/` regeneration | no content drift, byte-identical output on every platform |
| `python -m build` + `twine check` | wheel and sdist PASSED |
| Clean-venv install of the built wheel | `appsec-rules` console script works, schema bundled |
| Exit codes | 0 on a valid pack, non-zero on an invalid one |
| Remote CI | `CI`, `Security CI/CD`, and `OpenSSF Scorecard` green on `master` |

The published release was also validated as an end user: from an empty directory,
`pip install appsec-rules-pack` followed by the documented download of the baseline from the
release assets validates at 19 rules, 0 errors, 0 warnings.

## Risks and limits

- Cross-file duplicate ID detection applies only when validating a directory containing two
  or more YAML rule packs. Single-file validation stays file-local.
- The rule model is generic and review-oriented. The pack does not execute rules or scan
  code in any engine; the Semgrep scaffold carries placeholder patterns and the SARIF export
  has an empty `results` array.
- Negative fixtures deliberately assert message stability, so changing a validator message
  means updating its tests and CLI expectations together.
- Framework mapping format checks are warnings rather than errors, so an unusual but valid
  identifier is never blocked. Review warnings when contributing.
- Framework mappings are evidence aids for review, not a claim of conformance. They are
  assigned by topic; see `CONTRIBUTING.md` for the convention.
- `owasp_top_10_2025` is optional and intentionally absent on two rules where no category
  matches without stretching.

## Next steps

- Deepen the reference exports — real Semgrep detection patterns or an OPA/Rego mapping —
  kept strictly separate from the validator so the contract stays engine-agnostic.
- Extend mapping coverage: further ASVS chapters and NIST SSDF task-level mapping.
- Decide `owasp_top_10_2025` for `APPSEC-FILE-001` and `APPSEC-RATELIMIT-001` against the
  written mapping convention.
- Stabilize the expanded contract and cut `v1.0` with frozen schema guarantees, once it has
  had real-world use.

## Working on this project

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings
```

See `CONTRIBUTING.md` for the full set of required checks.
