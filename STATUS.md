# Project Status

Current state of the project, kept consistent with `README.md`, `ROADMAP.md`, and
`TECHNICAL_SPEC.md`. Release-by-release detail lives in [`CHANGELOG.md`](CHANGELOG.md);
this file describes where the project stands and what is known to be true right now.

## Where it stands

**Released:** `appsec-rules-pack` **0.8.0** (2026-10-07), which adds an assessed severity per review result (ADR-0009). 0.7.0 brought 24 baseline rules (pack version 0.7.0),
including function-level authorization, two LLM rules mapped to the OWASP Top 10 for LLM
Applications 2025, and an audit trail for sensitive records; `init-review` to start a
review record; and a warning for results that do not say why a rule is open or does not
apply. 0.6.0 added source-backed mapping rationale, review-gate documentation, report
compatibility fixtures, and SBOM identity and inventory checks. The 1.0 readiness proposal
([`docs/v1-readiness.md`](docs/v1-readiness.md)) leaves external feedback and the 1.0
release decision with the owner.

Release `0.8.0` was published to PyPI via Trusted Publishing
(OIDC, no long-lived credential). The release workflow checks that the tag is on `main`
and matches the package version, builds with hash-pinned tools in a job that cannot
publish, and publishes the wheel, the sdist, a CycloneDX SBOM, `appsec-baseline.yaml`, and
the signed provenance bundle (`appsec-rules-pack-<tag>.intoto.jsonl`) as GitHub Release
assets. Its SLSA build-provenance step covers the first four. Provenance is verified
through GitHub Artifact Attestations; downloading a release asset alone does not verify it.

**OpenSSF Best Practices:** passing since 2026-10-05 ([project 15240](https://www.bestpractices.dev/projects/15240)), with
55 criteria Met and 12 not applicable. The answers and their evidence were checked against
the repository on that date; the 12 N/A cover cryptography the software does not use,
memory-unsafe code it does not contain, and the absence of any reported vulnerability or CVE fix.

**What ships:** a JSON Schema rule contract, a Python 3.12+ validator with a Typer CLI,
derivation-only export and reporting commands, `review` for per-service review records
([ADR-0006](docs/adr/0006-review-records.md)), `init-review` to start a record, `init` for a starter pack, and versioned JSON
reports described in [`VERSIONING.md`](VERSIONING.md). The distribution contains the validator and
the schema — not the rules; the baseline pack is attached to each release and lives in
[`rules/appsec-baseline.yaml`](rules/appsec-baseline.yaml).

**The baseline pack:** 20 generic rules spanning access control,
password storage, injection and XSS, SSRF,
authentication, session hardening, secrets, file handling, logging, dependency risk,
configuration, CSRF, webhook integrity, excessive data exposure, mass assignment, open
redirect, and rate limiting. Every rule ships a compliant and a violating example.

**Validator coverage:** JSON Schema validation, duplicate rule IDs within a file and across
a validated directory, exception-window warnings, exception-policy consistency, framework
mapping format checks, rule-lifecycle consistency, and sensitive-value detection. Single-file
and directory validation, `--fail-on-warnings`, `--require-examples`, `--version`, and
`--format json` for CI.

**Derived artifacts:** `export index`, `export semgrep`, and `export sarif` produce the
drift-tested files under [`exports/`](exports/). `report coverage` summarizes mapping
metadata. The Semgrep output is a clearly-labelled non-runnable scaffold and the SARIF
output is a rule catalog with no results; the validator never executes rules or scans code
([ADR-0001](docs/adr/0001-engine-agnostic-validator.md)).

**Repository posture:** public, verified on 2026-10-05. The `main-protection` ruleset
requires one code-owner approval, approval of the latest push, an up-to-date branch, and
fourteen status checks ([ruleset](https://github.com/lucashgrifoni/AppSec-Rules-Pack/rules/17222248)).
The owner keeps an administrator bypass because this is a single-maintainer project; see
the `Branch-Protection` note under Risks and limits.

## Verified checks

Measured 2026-10-05 on `feat/v0.6.0`, using Windows 11 build 26300, Python
3.12.10 (64-bit), and the project virtual environment. The release-tool
reproduction uses the existing hash lock and a separate inventory environment.
These local checks ran on the release branch before the tag; the published artifacts
were verified separately, as described in the v0.6.0 release notes.

| Check | Result |
| --- | --- |
| `ruff check .` | Clean |
| `ruff format --check` on new or changed Python files | 14 files already formatted |
| `pytest --cov=appsec_rules_pack --cov-report=term-missing` | 367 passed; 98.61% branch-aware coverage (gate 95%) |
| `validate rules --require-examples --fail-on-warnings` | 1 file, 20 rules, 0 errors, 0 warnings |
| `report coverage rules/appsec-baseline.yaml` | ASVS, CWE, SSDF: 20/20; API Top 10 and Top 10:2025: 19/20 each |
| `exports/` regeneration | All three exports regenerated; byte-comparison drift tests pass |
| `python -m build` | `appsec_rules_pack-0.6.0` wheel and source distribution built |
| `twine check dist/*` | All four local distributions passed, including the new 0.6.0 wheel and sdist |
| Property harness, `HYPOTHESIS_PROFILE=ci` | 9 properties passed |
| `actionlint .github/workflows/publish-pypi.yml` | Clean |
| Hash-locked `build --no-isolation` | 0.6.0 wheel and sdist built |
| SBOM construction and gate | Root `appsec-rules-pack` / `0.6.0` / `pkg:pypi/appsec-rules-pack@0.6.0`; 16 runtime components on Windows; no pip, setuptools, or wheel; component inventory and dependency graph preserved |
| Installed-wheel CLI | Version 0.6.0; strict baseline validation passed |
| Repository visibility | Public on 2026-10-05 |

Remote evidence for the v0.6.0 changes (pull request #49, head `dd74e08`):
[CI 37337344267](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/runs/37337344267)
and [Security CI/CD 37337344302](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/runs/37337344302)
passed with all 23 checks, including the 14 required ones, and a manual
[release-workflow run 37335966457](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/runs/37335966457)
passed `verify` and `build` on that head, with publication skipped by design.

Release history and prior end-user installation checks are documented in
[`CHANGELOG.md`](CHANGELOG.md). See the README's release-verification instructions for
checking the provenance of a downloaded asset independently.

## Performance and capacity

The schema resource is parsed and checked once per process, then cached with
`lru_cache`; a `Draft202012Validator` instance is constructed for each validation.
Duplicate-ID detection uses a hash-map pass. Total cost also depends on YAML size,
shape, and schema checks, so no worst-case linear-time or throughput guarantee is
claimed here.

Earlier local checks measured stable memory across 2,000 repeated in-process runs and
sub-second validation for packs of a few thousand rules. These are relative
characteristics, not a per-machine benchmark. The CLI adds Python start-up time on top.

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
- `owasp_top_10_2025` is optional. `APPSEC-FILE-001` remains unmapped after the topic
  review below; `APPSEC-RATELIMIT-001` now maps to `A10:2025`.
- Historical checks recorded two blockers from 2026-08-10 to 2026-08-27, cleared when
  the repository became public:
  GitHub Actions had stopped allocating runners entirely (every job of every workflow ended
  in about three seconds with no runner and no steps executed), and code scanning was
  unavailable, so SARIF uploads and `SAST - CodeQL` could not succeed at all. They are
  recorded because they explain older runs.
- The 2026-08-27 `OpenSSF Scorecard` review recorded 13 alerts. `Maintained` cleared on its own;
  it had been a stale artifact of the period when Scorecard could not evaluate a private
  repository. The rest are accepted
  positions rather than defects, and are recorded here so they are owned rather than merely
  open:
  - `Branch-Protection` previously scored 8/10. It objected that administrators can bypass
    the `main-protection` ruleset, and that only one approving review is required. Both
    are deliberate: this is a single-maintainer project, so a second reviewer does not exist
    and removing the admin bypass would leave nobody able to merge. The residual risk is
    that a mistaken or compromised maintainer action has no second pair of eyes. Revisit if
    the project gains a second maintainer.
  - `Pinned-Dependencies` previously scored 7/10. Every GitHub Action is pinned to a commit
    SHA. Since v0.5.0 the release build installs its tools from a hash-locked requirements
    file, and the job holding the publishing credential installs nothing
    ([ADR-0007](docs/adr/0007-dependency-locking.md)). The test, lint, and security jobs keep
    version ranges on purpose, so CI sees the versions users install; Scorecard will keep
    flagging those, and that is an accepted position.
  - `Fuzzing`: since v0.5.0 a property-based harness (Hypothesis, `tests/property/`) covers
    the loader, validator, JSON report, and `review`, and runs in its own CI job. It found
    two crashes before the release. Scorecard recognizes only Atheris for Python, so a
    coverage-guided Atheris target (`fuzz/fuzz_validate.py`) now runs in CI as well.
- The prior workflow review found two required checks with no applicable files.
  `SCA - Trivy` finds no dependency manifest it can parse (the project uses a setuptools
  `pyproject.toml` with no lockfile), and `IaC and Pipeline - Trivy` finds no supported configuration file (there is
  no Dockerfile, Terraform, or Kubernetes manifest here, and Trivy's misconfiguration
  scanner does not cover GitHub Actions workflows). Their historical passing results
  represented zero scanned files.
  Real SCA coverage comes from `pip-audit`; real workflow coverage from KICS and actionlint.
  Both become meaningful the moment a lockfile or a container/IaC file is added.

## OWASP Top 10:2025 mapping decisions

Reviewed on 2026-10-04 against the [official Top 10:2025](https://owasp.org/Top10/2025/)
and the [topic-based convention](CONTRIBUTING.md#framework-mapping-convention). A mapping
connects a rule to a relevant topic; it is not a claim that the rule covers a category fully.

- **`APPSEC-RATELIMIT-001`: map to `A10:2025` (Mishandling of Exceptional Conditions).**
  The category's [How to prevent](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/#how-to-prevent)
  explicitly says to “add rate limiting, resource quotas, throttling, and other limits”
  to prevent exceptional conditions. It connects those limits to resilience, denial of
  service, brute force, and excessive cloud costs. That directly matches this rule's
  rate limits, quotas, and rejection/backoff when limits are exceeded. Use this one
  category rather than accumulating mappings for each endpoint or CWE.
- **`APPSEC-FILE-001`: keep `owasp_top_10_2025` absent.** The rule combines file-type and
  size validation, storage isolation, and safe path handling. [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/#description)
  centers on permission boundaries, while [A06 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/#description)
  distinguishes missing control design from implementation defects. Those topics overlap
  parts of this rule, but neither is a clean description of its combined file-handling
  scope. A01 listing CWE-22 and A06 listing CWE-434 is not sufficient under the project's
  topic-based convention. Keep the more specific ASVS, API Top 10, and CWE mappings
  instead of forcing a single broad category.

The resulting optional Top 10:2025 coverage is 19 of 20 rules (APPSEC-PWSTORE-001, added in v0.6.0, maps to `A04:2025`). An absent mapping is a
recorded scope decision, not a failed validation or a claim that the control is unnecessary.

## Next steps

- Extend the optional Semgrep layer beyond its two Python/Flask detections, or add an
  OPA/Rego mapping, kept strictly separate from the validator so the contract stays
  engine-agnostic.
- Extend mapping coverage: further ASVS chapters and NIST SSDF task-level mapping.
- Stabilize the expanded contract and cut `v1.0` with frozen schema guarantees, once it has
  had real-world use.

## Working on this project

```bash
python -m pip install -e ".[dev]"
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings
```

See `CONTRIBUTING.md` for the full set of required checks.
