# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## v0.7.0 - 2026-10-06

### Upgrade notes

- Baseline pack 0.7.0 declares `schema_version: "0.7"`. Validate it with package 0.7.0 or
  later; an older CLI refuses it with `schema-version-unsupported`.
- Four rules are new, so an existing record shows them as `unreviewed` with
  `review-missing-result` until it has a result for each, plus
  `review-pack-version-mismatch` until `pack_version` says 0.7.0. `init-review` prints
  the full rule list if you want to compare.
- `not-met` and `not-applicable` results without `notes` now warn
  (`review-justification-missing`). A record that passed `--fail-on-warnings` on 0.6.0
  fails on 0.7.0 until each of those results says why.
- `mappings.owasp_asvs` is now optional, and `APPSEC-LLM-001` has none. Code that reads
  the index or the pack and indexes `owasp_asvs` directly must treat it as absent.

### Added

- Four baseline rules, each with examples, mappings, and a row in
  `docs/mapping-rationale.md`. Each came from a gap found when the 0.6.0 baseline was used
  to review the internal test labs:
  - `APPSEC-AUTHZ-002`: function-level authorization on privileged operations
    (API5:2023, ASVS V8.2, CWE-285). Two labs let any signed-in user call admin routes.
  - `APPSEC-LLM-001`: untrusted content must not act as LLM instructions, and model
    output is validated before use (LLM01, LLM05, LLM07:2025; CWE-1427).
  - `APPSEC-LLM-002`: LLM tools and retrieval are limited to the caller's permissions
    (LLM06, LLM08:2025; ASVS V8.3; CWE-250, CWE-441).
  - `APPSEC-LOG-002`: an audit trail of access to sensitive records (ASVS V16.3, V16.4;
    CWE-778).
  The baseline now has 24 rules, pack version 0.7.0.
- `appsec-rules init-review <pack> <record> --subject ... --reviewer ...` writes a record
  with one `not-met` result per enabled rule, which warns until each rule is filled in.
- Warning `review-justification-missing` for `not-met` and `not-applicable` results
  without `notes`.
- Optional `review.subject_ref` in the record, for the exact revision reviewed.
- Optional `owasp_llm_top_10_2025` mapping, with a format check, in the schema, the
  coverage report, and the SARIF and Semgrep exports.
- `export index` includes each rule's `exceptions` policy.
- Keys starting with `x-` on a record result are copied into that rule's entry in the
  JSON report; they used to be accepted and dropped.
- Coverage-guided fuzzing of the loader and validator with Atheris (`fuzz/fuzz_validate.py`),
  run for two minutes in a new `Fuzzing (Atheris)` CI job with a hash-locked install. A
  first 60-second local run executed 2,231 inputs and found no crash.
- OpenSSF Best Practices badge: the project meets the passing level
  ([project 15240](https://www.bestpractices.dev/projects/15240)). The badge is in the README and on the landing page.

### Fixes

- The CI template in `examples/README.md` pinned 0.5.0; it now pins the current release,
  and a test keeps every documented pin equal to the package version.
- The template's gate stopped only on open `critical` or `blocking` rules, while the
  README suggests `critical` or `high`. The baseline has one critical rule and every rule
  is advisory, so a record with open high-severity rules passed. The gate now also stops on
  `high`, and a test runs the template's gate script.
- README links to `docs/` were relative and broke on PyPI; they are absolute now.

- When a record is invalid, the text summary of `review` said "0 rules; 0 met, ..." as if
  the pack were empty. It now says the record could not be checked.
- A malformed rule id or date in a record reported the raw regular expression; the
  message now shows the expected form.

### Changed

- `mappings.owasp_asvs` is optional (rule schema `$id` moves to v0.7.0). Map to ASVS
  whenever a section covers the rule; `docs/rule-fields.md` explains the exception.
- The record schema `$id` moves to v0.7.0 for `subject_ref`.
- The README quick start covers virtual environments and downloading the baseline in
  PowerShell.
- The README says that a partial record exits 0 without `--fail-on-warnings`, defines an
  open rule (`not-met` or `unreviewed`), and explains what a baseline upgrade does to
  existing records.
- The CI template notes that an expired exception fails the `review` step and that
  `validate rules` reads subdirectories.

## v0.6.0 - 2026-10-05

### Added

- `APPSEC-PWSTORE-001`: password-storage guidance, with examples and framework
  mappings. The baseline now contains 20 rules. Its pack version is 0.6.0 because
  this release adds a rule, in addition to changing existing content.
- A mapping-rationale table for every baseline rule, an offline ASVS 5.0.0 ID
  snapshot from the official release tag, and tests checking mapped IDs.
- Proposed ADR-0008 records the practice-level SSDF mapping convention.
- A 1.0 readiness proposal covering the contract freeze, migration policy,
  acceptance criteria, and owner-pending external feedback. Saved JSON v1 report
  fixtures and compatibility tests treat existing fields and types as a floor.
- Landing-page tests compare rule, framework, export, category, and version
  figures with repository data.

### Changed

- `APPSEC-CONFIG-001` includes CORS guidance and ASVS V3.4 / CWE-942.
- `APPSEC-SECRETS-001` prohibits default or fallback secret values.
- Baseline SSDF mappings follow the subject of each rule at practice granularity.
  Multiple mappings are justified only for distinct subjects; intentional
  omissions remain recorded in `docs/mapping-rationale.md`.
- Review documentation explains the advisory baseline, severity-based gates,
  and optional evidence locating a `not-met` result. The worked logging result
  now identifies the failing code location.
- Landing-page copy describes pack validation and documented reviews; its
  fourth statistic reports rule categories.

### Fixes

- Corrected SSDF mappings that described executable testing or default
  configuration rather than the rule's design or coding subject.
- Removed API5:2023 from the object-authorization rule, whose scope is API1:2023.
- Removed the landing page's unmeasured validation-time claim.

### Release pipeline

- The hash-locked CycloneDX tool uses a temporary project manifest resolved
  from the installed wheel's version. Its existing model library supplies and
  validates the root purl through the public API.
- The SBOM inventory environment contains the wheel and runtime dependencies,
  with no pip, setuptools, or wheel components. A pre-upload gate rejects an
  incorrect root name, version, purl, or installer component, with regression
  tests and construction notes in `docs/release-sbom.md`.
- No new runtime or development dependency and no CLI, JSON, schema, issue-code,
  or exit-code contract change.

## v0.5.0 - 2026-10-05

### Added

- `appsec-rules review <pack> <record>` checks a review record, the per-rule outcome of
  reviewing one service against a pack, against the pack's policy: the record names the
  pack, every rule exists and appears once, `met` cites evidence, and each exception is
  allowed, has the fields the rule requires, has not expired, and fits in `max_days`.
  Enabled rules with no result show as `unreviewed`. `--format json` emits
  `appsec-rules-review/v1` with open rules counted by enforcement and severity; the exit
  code reflects only whether the record is valid ([ADR-0006](docs/adr/0006-review-records.md)).
  `--as-of` pins the date exceptions are checked against.
- `review-record.schema.json` and `review-report.schema.json`, shipped in the package.
- `appsec-rules init <file>` writes a starter pack that passes the strict gate; the same
  pack is `examples/minimal-pack.yaml` and the README example (#30).
- A worked review in `examples/review/`, a field reference with guidance on adapting the
  baseline (`docs/rule-fields.md`), and a downstream GitHub Actions template that verifies
  the pinned baseline's provenance, validates packs, checks review records, and gates on
  open rules, with a PowerShell version.
- The reference policy gate also checks the worked review record and blocks on open
  blocking or critical rules.

### Release pipeline

- The release workflow is split into three jobs. `verify` checks that the tag points at
  a commit on `main` and matches the package version, then runs lint, tests, and strict
  validation. `build` installs hash-pinned tools (`.github/release/requirements.txt`)
  with egress limited to GitHub and PyPI, builds with `--no-isolation`, and writes the
  SBOM. `release` holds the OIDC token, installs nothing, and attests and publishes the
  files it receives ([ADR-0007](docs/adr/0007-dependency-locking.md), #26).
- README and landing page now state which releases carry which evidence: v0.1.0 was
  published by hand with no attestation, and every asset is attested from v0.3.1.
- SECURITY.md names 0.5.x as the supported line.

### Tests

- Property-based harness for the loader, validator, CLI JSON report, and `review`
  (`tests/property/`, Hypothesis), with `dev`, `ci`, and `long` budgets and its own CI
  job (#32). It found that a YAML key such as `0` or `true` crashed `validate` once the
  `x-` extension keys were added earlier in this cycle; fixed before release, with
  regression tests.
- Mutation-driven tests: every semantic check is now tested with the flagged rule after
  the items it skips, the `max_days` boundaries, exact YAML error locations, and the
  exporters' enabled-only filter. 21 targeted mutants of the validator and exporters, and
  8 of `review`, are killed.

### Changed

- The README starter pack now includes `examples`, so it passes
  `--require-examples --fail-on-warnings`; it previously produced a warning. Its ASVS
  mapping moved from `V14.4` (ASVS 4.0 numbering) to `V16.5.1`.

### Contract

- The `validate --format json` report now carries `"schema": "appsec-rules-validation/v1"`,
  and each issue a stable `code` and the `rule_id` it belongs to. `summary.ok` is present
  even when no rule files are found, and paths use forward slashes on every platform. The
  report is described by `schemas/validation-report.schema.json`, shipped in the package.
- New `VERSIONING.md`: how the package, schema, and pack versions relate, what counts as a
  breaking change, the public surface, the deprecation policy, and the list of issue codes.
- Rule schema (now `$id` v0.5.0), all changes backward compatible:
  - rule ids accept any uppercase prefix (`PREFIX-AREA-NNN`), not only `APPSEC-`;
  - `owasp_api_top_10_2023` is optional, like `owasp_top_10_2025`;
  - keys starting with `x-` are allowed on the pack, on rules, and in `mappings`;
  - a pack may declare `pack.schema_version`; the validator refuses a pack that targets a
    newer schema than it supports.
- The released v0.2.0 and v0.4.0 baselines are kept as fixtures and must keep validating.

### Security

- Rules files are parsed with a restricted loader. YAML aliases are rejected: a 460-byte
  alias bomb used to take 71 s to validate and made `export index` write 815 MB, and a
  self-referencing alias crashed with a traceback. Duplicate mapping keys are rejected:
  PyYAML kept the last value silently, so a second `rules:` key could cut a pack from 19
  rules to 1 and still pass. Files larger than 10 MiB are refused before parsing.
- Raised the dependency floors to `typer>=0.16` and `click>=8.3.3`. With typer 0.12.x
  every command exited 0 without validating anything, and click below 8.3.3 carries a
  known advisory. A new `min-deps` CI job runs the suite on exactly these floors.
- Tracebacks no longer print local variables, which could echo rules-pack content,
  including secrets, into CI logs.
- Sensitive-value detection also covers mapping keys and common token formats (GitHub,
  Slack, Google API, Stripe live keys). Messages redact values that look like secrets.
  Inside rule examples, real key material (private keys, cloud and platform tokens) now
  raises a warning; demonstration passwords are still allowed there.

### Fixes

- An unquoted date that is not a real day, such as `2026-02-30`, made `validate`, the
  exports, and `review` exit with a Python traceback. It is now a `yaml-invalid` error
  with its line and column. The bug was present since the first release; the property
  harness found it.
- `required_fields` containing a non-string item, a non-scalar `severity` in the SARIF and
  Semgrep exports, and values JSON cannot represent (such as an unquoted YAML date) no
  longer crash with a traceback.
- `--output` refuses to overwrite one of the input rules files.
- `report coverage` no longer counts a rule without an `id` as covered.

## v0.4.1 - 2026-10-05

Patch release: documentation and repository changes only. The validator, the rule schema,
the JSON report, and the baseline pack (still pack version 0.4.0) are unchanged.

- The default branch is now `main`. GitHub redirects links and clones that still use
  `master`; update local clones with `git branch -m master main` and
  `git branch -u origin/main main`.
- The landing page source moved to `site/` and deploys through the new `Pages` workflow;
  the separate `gh-pages` branch is gone.
- Rewrote the README around a quick start, a scope table, and a CLI reference. Links are
  absolute so they also work on the PyPI project page.
- The `IaC and Pipeline - Trivy` and `Secrets History - Gitleaks` jobs now allow the hosts
  their tool binaries download from, so they pass without a warm cache.

## v0.4.0 - 2026-10-05

- Each GitHub Release now carries the signed build-provenance bundle as
  `appsec-rules-pack-<tag>.intoto.jsonl`. The publish workflow verifies the bundle against
  the wheel before publishing, and consumers can verify any asset offline with
  `gh attestation verify --bundle`.
- The baseline pack version moves to 0.4.0 because rule content changed
  (`APPSEC-RATELIMIT-001` gained an OWASP Top 10:2025 mapping); the derived exports are
  regenerated. The rule schema is unchanged.

- Mapped `APPSEC-RATELIMIT-001` to OWASP Top 10:2025 `A10:2025`, whose prevention
  guidance explicitly calls for rate limits and resource quotas, and regenerated all three
  exports. `APPSEC-FILE-001` stays unmapped; both decisions and their sources are recorded
  in `STATUS.md`.
- Added README guidance on project scope, the derived Semgrep and SARIF exports, mapping
  coverage, and release-attestation verification, plus a reproducible recording of a
  passing and a failing validation.
- Corrected the roadmap and technical specification to separate what shipped through
  v0.3.1 from future work, and added the Python 3.13 classifier that CI already covers.
- Added an optional, hand-maintained Semgrep layer under `exports/semgrep-rules/` with two
  tested Python/Flask detections (`APPSEC-INJECT-001`, `APPSEC-SSRF-001`), positive and
  negative fixtures, a dedicated `semgrep --test` workflow, and ADR-0005. The validator and
  `export semgrep` are unchanged. CodeQL skips only the intentionally vulnerable fixtures.
- Added `examples/validation_gate.py`, a stdlib-only downstream gate that consumes
  `validate --format json` outside GitHub Actions (contributed by @LEKKALAGANESH, #35).
- The downstream examples and the pull request template now use the strict
  `--require-examples --fail-on-warnings` gate, with tests that run the documented
  commands; `CONTRIBUTING.md` states the automated test policy.
- Replaced the Markdown issue templates with issue forms and added a social-preview image.
- Bumped pinned GitHub Actions: `attest-build-provenance` 4.2.2, `gh-action-pypi-publish`
  1.14.2, `harden-runner` 2.21.0, `setup-python` 6.3.0, `actionlint` 0.1.13, and
  `scorecard-action` 2.4.4, later `harden-runner` 2.21.1 and the `codeql-action` group
  4.38.2.

## v0.3.1 - 2026-08-27

- The `Security CI/CD` pipeline passes. Two separate things were wrong and only one of
  them was a permission problem. Five SARIF-uploading jobs (Semgrep, both Trivy scans,
  KICS, Trivy secrets) were missing `actions: read`, which
  `github/codeql-action/upload-sarif` needs to read the workflow run, and the Gitleaks
  history job was missing `pull-requests: read`, so its `GET /pulls/{n}/commits` returned
  403 on pull requests. Both additions were necessary and are minimal and read-only. They
  were not, however, why the pipeline was red: every failing step reported "Code scanning
  is not enabled for this repository", because a private repository without GitHub
  Advanced Security has no code-scanning store to upload SARIF into. The scans themselves
  succeeded throughout — each failing job had already passed its own detection gate and
  died on the upload. The uploads are now conditioned on the repository being public, and
  the repository was made public on 2026-08-27. Neither failure was a security finding.
- Unreadable rule files now fail with an actionable error instead of a raw Python
  traceback, across every command. A file that is not valid UTF-8 (for example one
  saved as UTF-16 by legacy PowerShell) escaped as an uncaught `UnicodeDecodeError`
  from `validate`, `export index`, `export semgrep`, `export sarif`, and
  `report coverage`; a YAML parse failure and a pathologically deep nesting
  (`RecursionError`) did the same from the export and report commands. `validate`
  reports the problem as a normal per-file validation error; the derivation commands
  print `<Action> failed: could not decode/parse ... <path> ...` on stderr and exit 1.
- `report coverage --output` now writes the text report. Without `--format json` the
  `--output` option was silently ignored: the report went to stdout, the exit code
  stayed 0, and the named file was never created. The text report now lands in the
  file exactly like the JSON variant, with a `Wrote coverage report to <path>.`
  confirmation.
- The validation summary now pluralizes every count: `1 file, 1 rule, 0 errors,
  1 warning` instead of `1 rules`/`1 errors`/`1 warnings`. The file count was already
  handled; rules, errors, and warnings were not. Text output only — the JSON report
  is unchanged.

## v0.3.0 - 2026-08-05

- The baseline pack is now attached to every GitHub Release as `appsec-baseline.yaml`.
  The distribution ships the validator and the schema but no rules, so this gives
  consumers a version-pinned copy without cloning the repository.
- `APPSEC-SSRF-001` now maps to `A01:2025`. The OWASP Top 10:2025 introduction states that
  SSRF has been rolled into Broken Access Control, and CWE-918 is listed among that
  category's mapped CWEs. `APPSEC-FILE-001` and `APPSEC-RATELIMIT-001` remain unmapped
  pending a written rule for how this field is assigned — the pack maps by topic rather
  than by CWE membership, and that convention has never been documented.
- Raised the coverage gate from 90% to 95% (actual is 97.46%). A gate far below the real
  number permits a silent regression the size of the gap.
- CI now exercises Python 3.13 in a dedicated job. `requires-python = ">=3.12"` has always
  admitted 3.13, and nothing tested it.

- An unwritable `--output` now reports an actionable error instead of a traceback.
  Pointing it at an existing directory escaped as a raw `PermissionError` (Windows) or
  `IsADirectoryError` (POSIX); the CLI now prints `Write failed: cannot write to <path>:
  <reason>.` and exits 1. Covers `export index`, `export semgrep`, `export sarif`, and
  `report coverage --output`.
- Identical schema errors are no longer reported more than once. jsonschema raises one
  error per missing required property while the rendered message names every missing
  field, so a rule with an empty `match` block printed
  `missing required fields: 'type', 'includes', 'excludes'` three times and counted three
  errors. The same message at the same path is now reported once; distinct locations are
  unaffected.
- README: added a complete minimal rules pack that a new user can copy and validate, and
  stated plainly that the distribution ships the validator and schema but no rules pack —
  the baseline of 19 rules lives in the repository. The documented usage examples assume a
  checkout, which was not said before, so the first command a new PyPI user ran failed with
  "path does not exist". The example is validated by `tests/test_readme_example.py`, so it
  cannot drift out of sync with the schema.

- Derived artifacts written with `--output` now use LF line endings on every platform.
  `Path.write_text` translates `\n` to the platform separator, so `export index`,
  `export semgrep`, `export sarif`, and `report coverage --output` produced entirely
  CRLF files on Windows while the repository stores LF. The same command now yields
  byte-identical output regardless of platform, which matters for anything that hashes
  or diffs the generated evidence. Content is unchanged.
- `report coverage` now warns on stderr when the pack yields zero rules. The report is
  derived without schema validation, so a pack whose `rules` key is missing or malformed
  produced a clean-looking `0/0` report with no signal. The exit code is deliberately
  unchanged (still 0): judging pack structure is `validate`'s job.
- Pinned down how the semantic checks behave on payloads the schema already rejected.
  Schema validation and the semantic checks run over the same payload, so every semantic
  check sees malformed input whenever a pack is invalid; each one skips what it cannot
  read, which is what lets a single `validate` run report all the schema errors at once
  instead of dying on the first malformed rule. Suite is now 121 tests at 97.42% coverage.
- Pinned down two previously untested behaviours. Directory validation now has tests
  proving that one unparseable YAML file does not abort the scan: the other files are
  still validated and their rules still counted, so a single broken file cannot silently
  hide the rest of a report. The derivation-only exports (`export sarif`, `export semgrep`,
  `report coverage`) now have tests for malformed or partial packs — they run without
  schema validation, so their degradation behaviour is a contract: skip what cannot be
  read, fall back to documented defaults, never raise or invent content.
- Added tests for the CLI `--output` write path of every export. `export semgrep --output`
  and `export sarif --output` had no test: the drift tests compare the committed artifact
  against the in-memory builder, so a break in the file-writing path would not have failed
  them. The new tests compare raw bytes against the committed artifacts.
- Fixed a portability defect in the test suite. Subprocess output was decoded with the
  platform's locale encoding, so the CLI entry-point test failed on Windows (cp1252)
  whenever the child process emitted UTF-8; `subprocess.run` swallowed the decode error
  and left `stdout` as `None`, which surfaced as a misleading `TypeError`. Both ends are
  now pinned to UTF-8 through a shared `tests/helpers.py`, with regression tests. No
  runtime or packaging behaviour changed.
- Added a `cross-platform` CI job running the suite on Ubuntu and Windows, so
  platform-dependent defects fail in CI instead of only on a maintainer's machine. The
  existing `Lint, test, and validate rules` job (and therefore the required status check
  used by branch protection) is unchanged.

## v0.2.0 - 2026-06-03

- Added derivation-only export and reporting commands (engine-agnostic, see ADR-0001):
  `report coverage` (framework-mapping coverage as text/JSON), `export semgrep` (a clearly
  labeled NON-runnable Semgrep scaffold), and `export sarif` (a SARIF 2.1.0 rule catalog
  with empty results). Checked-in `exports/` artifacts are drift-tested.
- Added reference CI workflows: `policy-gate.yml` (a separate gate that consumes the
  validator JSON, per ADR-0004) and `publish-pypi.yml` (build + CycloneDX SBOM + SLSA build
  provenance attestation + PyPI Trusted Publishing via OIDC; the PyPI publisher config is
  an owner handoff).
- Expanded the baseline pack from 12 to 19 rules: `APPSEC-CSRF-001` (CSRF),
  `APPSEC-ENUM-001` (user enumeration), `APPSEC-MSGAUTH-001` (webhook/message authenticity),
  `APPSEC-DATAEXPO-001` (excessive data exposure), `APPSEC-MASSASSIGN-001` (mass assignment),
  `APPSEC-REDIRECT-001` (open redirect), and `APPSEC-RATELIMIT-001` (rate limiting). Each
  ships compliant and violating examples and ASVS 5.0 / API Top 10 / CWE / NIST SSDF mappings.
- Added an optional `owasp_top_10_2025` mapping field (OWASP Top 10:2025, for example
  `A01:2025`), populated where a 2025 category maps cleanly. Backward-compatible.
- Added rule-lifecycle support: a `deprecated` status and an optional `deprecation` block
  (reason, replaced_by, since), with validator consistency warnings.
- Extended the `category` vocabulary with `csrf`, `integrity`, `data-exposure`,
  `open-redirect`, and `rate-limiting` (additive; existing rules unaffected).
- Migrated all baseline rule `owasp_asvs` mappings to OWASP ASVS 5.0.0. The 5.0
  reorganization renumbered the standard into 17 chapters (V1-V17), so identifiers were
  assigned by topic to the 5.0.0 chapters and verified against the 5.0.0 chapter/section
  structure and the official v5.0.0-to-v4.0.3 mapping
  (`5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml`) — for example authorization
  `V4.1`->`V8.2`, authentication/session `V2.1,V3.2`->`V6.3,V7.2`, injection (incl. XSS,
  which 5.0 folds into Injection Prevention) `V5.3`->`V1.2`, logging
  `V7.1`->`V16.2,V16.3`, configuration/secrets `V14.1,V14.8`->`V13.4,V13.3`, dependencies
  `V14.2`->`V15.2`, files `V12.1`->`V5.2,V5.3`, SSRF `V12.6`->`V1.3` (Sanitization, 1.3.6).
  Mappings remain evidence aids, not a conformance claim.
- Added two baseline rules, raising the pack to 12 rules: `APPSEC-SESSION-001`
  (session cookie and lifecycle hardening) and `APPSEC-XSS-001` (output encoding /
  cross-site scripting). Both ship compliant and violating examples and were prioritised
  from coverage gaps observed against a vulnerable-app test suite.
- Added an `export index` CLI subcommand that derives a machine-readable JSON rule
  index (pack id/name/version plus per-rule id, title, severity, category, status,
  enforcement, targets, and mappings). Derivation only — it never executes rules,
  preserving the engine-agnostic boundary.
- Added a checked-in derived index at `exports/appsec-baseline.index.json` with a
  drift test that keeps it in sync with the pack.
- Replaced the schema `$id` placeholder (`example.invalid`) with a canonical,
  tag-versioned URL and documented the versioning policy via a schema `$comment`.
- Added an optional `examples` field to the rule schema: each rule may declare a
  `compliant` and a `violating` example with `language`, `snippet`, and `explanation`.
  The schema enforces the shape when present.
- Populated all 10 baseline rules with explicit compliant and violating examples.
- Added a `--require-examples` CLI flag that warns when an enabled rule ships no
  examples; the CI baseline validation now runs with it.
- Excluded rule `examples` from sensitive-value detection, since violating examples
  intentionally demonstrate insecure anti-patterns.

## v0.1.0 - 2026-05-25

- Initialized the standalone repository and prepared the first local `v0.1.0`
  release candidate.
- Added a `.gitleaks.toml` that allowlists the intentional fake-secret fixtures in
  `tests/test_validator_paths.py`, clearing a Gitleaks false positive while keeping
  secret scanning active everywhere else.
- Added a packaging metadata pass for PyPI (license, classifiers, keywords, and
  project URLs).
- Added a security pipeline (Semgrep, CodeQL, Bandit, Trivy, KICS, pip-audit,
  Gitleaks, Dependency Review, actionlint), OpenSSF Scorecard analysis,
  Dependabot, and CODEOWNERS.
- Added community-health files: a code of conduct, issue templates, a pull
  request template, and a CI integration template under `examples/`.
- Added technical specification, AppSec rule schema, initial baseline rules,
  validator CLI, documentation, and tests.
- Added baseline security reporting documentation.
- Added pass/fail validation fixtures, directory validation support, clearer schema
  validation messages, and CLI coverage for file and directory inputs.
- Added negative fixtures for enum, type, additionalProperties, and duplicate rule
  ID validation.
- Added cross-file duplicate rule ID validation for directory inputs.
- Added warning fixtures, `--fail-on-warnings` coverage, and packaging build tests.
- Expanded test coverage for loader errors, schema message branches, sensitive-value
  patterns, and CLI edge cases, with a 90% coverage gate.
- Single-sourced the package version and added a `--version` CLI flag.
- Added exception-policy consistency checks (disallowed exceptions that still declare
  a window or fields are errors; allowed exceptions missing core fields warn).
- Added framework mapping identifier format validation for CWE, OWASP API Top 10 2023,
  OWASP ASVS, and NIST SSDF.
- Added `--format json` machine-readable validation output for CI.
- Added four baseline rules covering authentication, logging, dependency risk, and
  configuration, bringing the pack to 10 rules across all schema categories.
- Added a hardened GitHub Actions CI workflow with least-privilege permissions and
  SHA-pinned actions.
