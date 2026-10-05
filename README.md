# AppSec Rules Pack

[![CI](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/ci.yml/badge.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/ci.yml)
[![Security CI/CD](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/security-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/actions/workflows/security-ci-cd.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lucashgrifoni/AppSec-Rules-Pack/badge)](https://scorecard.dev/viewer/?uri=github.com/lucashgrifoni/AppSec-Rules-Pack)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15240/badge)](https://www.bestpractices.dev/projects/15240)
[![PyPI](https://img.shields.io/pypi/v/appsec-rules-pack.svg)](https://pypi.org/project/appsec-rules-pack/)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/pyproject.toml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/LICENSE)

A versioned AppSec rules pack and the validator that keeps it honest. Each rule states
what to review, what evidence proves it, how to fix it, and how long an exception may
last, with mappings to OWASP ASVS 5.0, the OWASP API Security Top 10, OWASP Top 10:2025,
CWE, and NIST SSDF. The `appsec-rules` CLI validates packs against a JSON Schema contract
and semantic checks, and checks review records, the per-service outcome of a review,
against the pack's own exception policy. A CI gate reads both reports.

![Recorded CLI demo: successful baseline validation followed by a missing-title error](https://raw.githubusercontent.com/lucashgrifoni/AppSec-Rules-Pack/main/docs/assets/cli-demo.svg)

The demo is real CLI output. [Recreate it](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/assets/record-cli-demo.py) from a source
checkout with `python docs/assets/record-cli-demo.py`.

## Contents

- [Scope](#scope)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Verify a release](#verify-a-release)
- [CLI reference](#cli-reference)
- [Writing a rules pack](#writing-a-rules-pack)
- [Recording a review](#recording-a-review)
- [Use it in CI](#use-it-in-ci)
- [Optional executable Semgrep rules](#optional-executable-semgrep-rules)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Contributing, security, and license](#contributing-security-and-license)

## Scope

| It does | It does not |
| --- | --- |
| Define a JSON Schema contract for AppSec review rules | Scan application code or execute rules |
| Ship a generic baseline of 20 rules, each with a compliant and a violating example | Claim compliance: mappings are review aids, not conformance |
| Validate packs: schema, duplicate IDs, exception windows and policy, mapping formats, rule lifecycle, sensitive values | Embed enforcement: CI consumes the JSON report and decides ([ADR-0004](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/0004-ci-gate-consumes-json.md)) |
| Derive a rule index, a Semgrep metadata scaffold, a SARIF rule catalog, and a mapping coverage report | Turn the derived scaffold into detections: its patterns are placeholders ([ADR-0001](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/0001-engine-agnostic-validator.md)) |
| Check a review record against the pack: every rule accounted for, evidence for `met`, exceptions allowed, complete, unexpired, and inside the window | Confirm the evidence is true, or decide what may stay open: the record is self-declared and the gate decides ([ADR-0006](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/0006-review-records.md)) |

The baseline covers authentication, password storage, authorization, input validation,
injection and XSS, SSRF, secrets, file handling, logging, dependency risk, configuration
including CORS, session hardening,
CSRF, webhook integrity, excessive data exposure, mass assignment, open redirect, and rate
limiting. It contains no product names, tenant identifiers, customer data, secrets, or
environment-specific configuration.

Mapping coverage of the baseline: ASVS 5.0, CWE, and NIST SSDF on 20 of 20 rules; the
optional OWASP API Top 10 2023 and OWASP Top 10:2025 fields on 19 of 20 each.

## Quick start

```bash
pip install "appsec-rules-pack==0.6.0"
curl -LO https://github.com/lucashgrifoni/AppSec-Rules-Pack/releases/download/v0.6.0/appsec-baseline.yaml
appsec-rules validate appsec-baseline.yaml --require-examples --fail-on-warnings
```

Expected output: `Validation passed: 1 file, 20 rules, 0 errors, 0 warnings.`

## Installation

```bash
pip install "appsec-rules-pack==0.6.0"
```

This installs the `appsec-rules` console script and requires Python 3.12 or newer. Pin a
reviewed version, such as `appsec-rules-pack==0.6.0`, when the CLI runs
as a quality gate.

The distribution contains the validator, the CLI, and the JSON Schema. It does not contain
a rules pack. Take the baseline from the assets of the
[release](https://github.com/lucashgrifoni/AppSec-Rules-Pack/releases) you pin, copy
[`rules/appsec-baseline.yaml`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/rules/appsec-baseline.yaml), or write your own pack.

To work from source:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"     # Windows: .venv\Scripts\python
```

## Verify a release

Releases from v0.2.0 on are built and published by
[`publish-pypi.yml`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/.github/workflows/publish-pypi.yml) through PyPI Trusted Publishing,
with no long-lived token. From v0.3.1, each GitHub Release carries the wheel, the sdist, a
CycloneDX SBOM (`sbom.cdx.json`), and the baseline pack, all four with a SLSA
build-provenance attestation; from v0.4.0 it also carries the signed provenance bundle
(`appsec-rules-pack-<tag>.intoto.jsonl`). From v0.5.0, a release is published only from a
tag on `main` that matches the package version and passes the tests, and the files are
built with hash-pinned tools in a job that cannot publish. v0.1.0 was published by hand and
has no attestation. All release tags are signed.

Verify a downloaded asset with a current [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify):

```bash
gh attestation verify appsec-baseline.yaml \
  --repo lucashgrifoni/AppSec-Rules-Pack \
  --signer-workflow lucashgrifoni/AppSec-Rules-Pack/.github/workflows/publish-pypi.yml \
  --source-ref refs/tags/v0.6.0
```

Or offline, against the bundle attached to the release:

```bash
gh attestation verify appsec-baseline.yaml \
  --repo lucashgrifoni/AppSec-Rules-Pack \
  --bundle appsec-rules-pack-v0.6.0.intoto.jsonl
```

The same commands work for the wheel, the sdist, and `sbom.cdx.json`. A passing check proves
the artifact came from this repository's release workflow at that tag. It does not prove the
rule guidance is complete or that an application is secure. Treat a failed or unavailable
check as unverified provenance. [ADR-0003](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/0003-release-provenance.md) explains the
release design.

## CLI reference

| Command | Purpose |
| --- | --- |
| `appsec-rules init <file>` | Write a starter pack that passes the strict gate |
| `appsec-rules validate <file-or-dir>` | Validate one pack or every `.yaml`/`.yml` pack in a directory |
| `appsec-rules review <pack> <record>` | Check a review record against a pack; `--as-of`, `--fail-on-warnings`, `--format json` |
| `appsec-rules export index <pack> [-o file]` | Derive a machine-readable rule index (JSON) |
| `appsec-rules export semgrep <pack> [-o file]` | Derive a Semgrep scaffold with rule metadata and placeholder patterns |
| `appsec-rules export sarif <pack> [-o file]` | Derive a SARIF 2.1.0 rule catalog with an empty `results` array |
| `appsec-rules report coverage <pack> [-f json] [-o file]` | Count framework mappings per rule and AppSec category |
| `appsec-rules --version` | Print the installed version |

`validate` options:

| Option | Effect |
| --- | --- |
| `--fail-on-warnings` | Exit non-zero on warnings as well as errors |
| `--require-examples` | Warn when an enabled rule has no compliant/violating example |
| `--format json` | Emit a JSON report for CI |

The JSON report is identified by `"schema": "appsec-rules-validation/v1"` and described by
[`validation-report.schema.json`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/src/appsec_rules_pack/schemas/validation-report.schema.json).
It has a `summary` object (`files`, `rules`, `errors`, `warnings`, `ok`) and a `files` array
of per-file issues. Each issue has a `level`, a stable `code`, the `rule_id` it belongs to
(or `null`), a `path` inside the pack, and a `message`. Match on `code`, not on the message
text, which may be reworded. Validation exits `0` on a passing pack, `1` on a failing one,
and `2` on a usage error such as a missing path. [`VERSIONING.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/VERSIONING.md) lists
the codes and what counts as a breaking change.

The export and coverage commands only derive metadata; they do not validate first. Run
`validate --require-examples --fail-on-warnings` as the gate. From a source checkout,
`python -m appsec_rules_pack` works in place of `appsec-rules`.

## Writing a rules pack

A pack is a `pack` block plus one or more `rules`. This minimal pack is complete and passes
the strict gate. `appsec-rules init my-pack.yaml` writes it for you; then validate it and
grow it. Every field shown is required except `schema_version` and `examples`, which the
strict gate (`--require-examples`) expects anyway. The full contract is
[`appsec-rule.schema.json`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/src/appsec_rules_pack/schemas/appsec-rule.schema.json), and the
20 rules in [`rules/appsec-baseline.yaml`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/rules/appsec-baseline.yaml) are worked examples.

<!-- readme-example:minimal-pack (validated by tests/test_readme_example.py) -->

```yaml
pack:
  id: my-pack
  name: My Rules Pack
  version: 0.1.0
  schema_version: "0.5"
  mode: advisory
  owner: appsec
  description: A minimal rules pack to start from.

rules:
  - id: MYPACK-ERRORS-001
    title: Require controlled error handling
    description: Verify that invalid user input returns controlled errors without stack traces.
    severity: medium
    category: configuration
    status: enabled
    enforcement: advisory
    targets:
      - api
    mappings:
      owasp_asvs:
        - V16.5.1
      cwe:
        - CWE-209
      nist_ssdf:
        - PW.7
    evidence:
      required:
        - Error handling path returns a documented response shape.
      signals:
        - Negative tests assert controlled error messages for invalid input.
    match:
      type: review
      includes:
        - API handlers that process untrusted input.
      excludes:
        - Local developer-only scripts that are not shipped.
    remediation:
      guidance: Replace raw exception output with a controlled error contract.
      validation:
        - Run negative tests for invalid input and malformed requests.
    exceptions:
      allowed: true
      max_days: 30
      required_fields:
        - owner
        - justification
        - expires_at
    examples:
      compliant:
        language: python
        snippet: |
          except ValueError:
              log.exception("order parse failed")
              return {"error": "invalid order"}, 400
        explanation: The client gets a fixed message; the detail stays in server logs.
      violating:
        language: python
        snippet: |
          except ValueError as error:
              return {"error": repr(error)}, 500
        explanation: The raw exception reaches the client and can expose internal details.
```

Rules files must be UTF-8 YAML without aliases or duplicate keys, and no larger than
10 MiB; the validator rejects anything else before checking the schema.

[`docs/rule-fields.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/rule-fields.md) lists every field, its limits and allowed
values, and how to adapt the baseline: keep it as published next to your own pack, or
fork it. Shapes that are easy to get wrong: `evidence` and `match` are objects, not lists;
`remediation` needs `guidance`; `required_fields` accepts only `owner`, `justification`,
`expires_at`, `compensating_control`, and `validation_plan`.

Rule ids follow `PREFIX-AREA-NNN`, so an organisation can use its own prefix (`ACME-AUTH-001`)
next to the baseline's `APPSEC-` rules. The `owasp_top_10_2025` and `owasp_api_top_10_2023`
mappings are optional; ASVS, CWE, and NIST SSDF are required. Keys starting with `x-` are
allowed on the pack, on each rule, and inside `mappings` for your own metadata. A pack may
declare the schema it targets with `pack.schema_version: "0.5"`.

Rules are advisory by default. Each one carries a stable ID and severity, a target surface
and category, framework mappings, expected evidence and review signals, match guidance,
remediation and validation steps, exception requirements, a lifecycle status
(`deprecated` rules carry a `deprecation` block), and a compliant and a violating example.
`pack.mode` and each rule's `enforcement` (`advisory`, `audit`, `blocking`) are policy
metadata for whoever consumes the pack. They never change the exit code of `validate`, which
only judges whether the pack itself is well formed.
[`CONTRIBUTING.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/CONTRIBUTING.md) describes the severity model and the topic-based
mapping convention.

## Recording a review

A pack states a policy. A review record states what one review found against it: for one
subject (a service, a repository, a release), each rule is `met`, `not-met`,
`not-applicable`, or `excepted`.

<!-- readme-example:review-record (checked by tests/test_review.py) -->

```yaml
review:
  pack: appsec-baseline
  pack_version: 0.6.0
  subject: payments-api
  reviewer: appsec-team
  date: 2026-10-01

results:
  - rule: APPSEC-AUTHZ-001
    status: met
    evidence:
      - tests/test_authz.py::test_other_tenant_payment_returns_404
  - rule: APPSEC-LOG-001
    status: not-met
    notes: Refund failures log the card holder name.
  - rule: APPSEC-RATELIMIT-001
    status: excepted
    exception:
      owner: payments-team
      justification: Per-client quotas need a new store; planned for 3.3.
      expires_at: 2026-12-15
      compensating_control: Gateway limit and an alert on 429 spikes.
```

```bash
appsec-rules review appsec-baseline.yaml payments-api-review.yaml --format json
```

`review` checks the record against the pack: the record names the right pack, each rule
exists and appears once, `met` cites evidence, and each exception is allowed by the rule,
has the fields the rule requires, has not expired, and fits in the rule's `max_days`.
Enabled rules with no result are reported as `unreviewed`.

For `not-met`, `evidence` is optional. Use it to point to the failing code, test,
or observation so another reviewer can locate the defect. It does not change the status.

The exit code says whether the record is valid, nothing more. A valid record can still
have open rules. The JSON report (`"schema": "appsec-rules-review/v1"`, described by
[`review-report.schema.json`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/src/appsec_rules_pack/schemas/review-report.schema.json))
lists every rule with its severity, enforcement, and status, and counts open rules by
both, so the gate can apply your policy. The record format is
[`review-record.schema.json`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/src/appsec_rules_pack/schemas/review-record.schema.json).
[`examples/review/`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/examples/review/README.md) has a complete record against the
baseline.

All 20 baseline rules have `enforcement: advisory`. A gate that checks only
`summary.open_by_enforcement.blocking` would allow every open baseline rule.
Gate on `summary.open_by_severity` instead, with the severity threshold your team
requires. For example, reject a report when its `critical` or `high` count is non-zero,
after checking that the command exited 0 and `summary.ok` is true. The worked review
has one open `medium` rule. To gate by enforcement, fork the pack and raise selected
rules to `blocking`; [the field reference](docs/rule-fields.md#rules) explains the field
and [adapting the baseline](docs/rule-fields.md#adapting-the-baseline) explains the fork.
Count maps omit zero entries; in Python, read a missing severity with
`summary["open_by_severity"].get("high", 0)`.

## Use it in CI

- [`examples/README.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/examples/README.md) has a GitHub Actions job that installs a pinned
  release, downloads and verifies the baseline, validates your packs, checks your review
  records, and gates on open rules, plus a PowerShell version.
- [`examples/validation_gate.py`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/examples/validation_gate.py) is a stdlib-only gate for any
  other CI system. It passes only when the CLI exits `0` and the report says `ok: true`.
- [`.github/workflows/policy-gate.yml`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/.github/workflows/policy-gate.yml) is this
  repository's reference gate that consumes the JSON report.

## Optional executable Semgrep rules

[`exports/semgrep-rules/`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/exports/semgrep-rules/README.md) holds two hand-maintained,
tested Semgrep rules, kept separate from the validator
([ADR-0005](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/0005-executable-semgrep-subset.md)):

| Baseline rule | Detection |
| --- | --- |
| `APPSEC-INJECT-001` | Flask query/form values reaching SQL arguments on locally created sqlite3 connections and cursors |
| `APPSEC-SSRF-001` | Flask query/form values reaching the URL argument of module-level Requests calls |

The other 18 baseline rules have no executable detection, and these two cover only their
documented source and sink combinations. The layer README lists the known false positives
and false negatives. Run the fixture suite with a separately installed engine:

```bash
python -m pip install "semgrep==1.179.0"
semgrep --test --strict --metrics=off --config exports/semgrep-rules/rules exports/semgrep-rules/tests
```

CI runs this on Linux. Use Linux, macOS, or WSL: on native Windows, `semgrep --test` did
not run these fixtures in a check on 2026-10-05.

The `appsec-rules` CLI never invokes Semgrep, and `export semgrep` still emits only the
metadata scaffold.

## Project layout

```text
.github/            CI, security, policy-gate, Scorecard, Pages, and release workflows
docs/adr/           Architecture decision records
docs/assets/        CLI demo and social preview
examples/           Starter pack, worked review, and CI integration examples
exports/            Derived artifacts and the optional executable Semgrep rules
rules/              The baseline rules pack
site/               Source of the project landing page
src/appsec_rules_pack/
                    Validator, review checker, CLI, exporters, schemas, starter pack
tests/              Test suite and pass, fail, and warning fixtures
```

## Documentation

| Document | Contents |
| --- | --- |
| [`CHANGELOG.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/CHANGELOG.md) | Changes per release |
| [`VERSIONING.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/VERSIONING.md) | Version numbers, compatibility rules, public surface, issue codes |
| [`STATUS.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/STATUS.md) | Current state, dated verification results, risks and limits |
| [`ROADMAP.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/ROADMAP.md) | What shipped and what comes next |
| [`TECHNICAL_SPEC.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/TECHNICAL_SPEC.md) | Rule contract and validation design |
| [`docs/rule-fields.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/rule-fields.md) | Every pack and rule field, and how to adapt the baseline |
| [`docs/v1-readiness.md`](docs/v1-readiness.md) | Proposed 1.0 contract freeze, migration policy, and pending acceptance criteria |
| [`docs/adr/`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/docs/adr/README.md) | Architecture decisions |

## Contributing, security, and license

Contributions are welcome. Read [`CONTRIBUTING.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/CONTRIBUTING.md) for rule authoring
principles, the severity and exception models, and the required checks:

```bash
python -m ruff check .
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings
python -m build
```

Participation follows the [Code of Conduct](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/CODE_OF_CONDUCT.md). Report vulnerabilities
privately as described in [`SECURITY.md`](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/SECURITY.md); do not open a public issue.

Licensed under the [Apache License 2.0](https://github.com/lucashgrifoni/AppSec-Rules-Pack/blob/main/LICENSE).
