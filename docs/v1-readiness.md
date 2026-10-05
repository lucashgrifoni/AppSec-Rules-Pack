# Readiness for 1.0

This document defines proposed acceptance criteria for 1.0. It does not declare
the project ready for 1.0 or authorize a tag. The current compatibility policy
remains in [VERSIONING.md](../VERSIONING.md).

## Contracts to freeze

At 1.0, preserve the public surfaces below throughout the 1.x series. Additions
remain allowed when existing inputs, consumers, and meanings continue to work.

| Surface | Contract and source |
| --- | --- |
| CLI commands | `validate`, `review`, `init`, `export index`, `export semgrep`, `export sarif`, and `report coverage`; the `export` and `report` groups; `--help` on every command |
| Global options | `--version`, `--install-completion`, and `--show-completion` |
| Validation options | `--fail-on-warnings`, `--require-examples`, and `--format` / `-f` |
| Review options | `--as-of`, `--fail-on-warnings`, and `--format` / `-f` |
| Starter option | `init --force` |
| Export options | `export index --format` / `-f`; all three exports' `--output` / `-o` |
| Coverage options | `report coverage --format` / `-f` and `--output` / `-o` |
| Arguments and defaults | Positional arguments, accepted values, defaults, and output destinations documented by command help and [README.md](../README.md) |
| Exit codes | `0` for success, `1` for validation or operation failure, `2` for usage error; usage errors produce no JSON report |
| Validation JSON v1 | `appsec-rules-validation/v1`, its fields, types, and meanings; [validation report schema](../src/appsec_rules_pack/schemas/validation-report.schema.json) |
| Review JSON v1 | `appsec-rules-review/v1`, its fields, types, and meanings; [review report schema](../src/appsec_rules_pack/schemas/review-report.schema.json) |
| Rule schema | [appsec-rule.schema.json](../src/appsec_rules_pack/schemas/appsec-rule.schema.json): fields, types, enums, patterns, requiredness, and extension-field behavior |
| Review record schema | [review-record.schema.json](../src/appsec_rules_pack/schemas/review-record.schema.json): status, evidence, exceptions, and supported extension fields |
| Issue codes | Validation and review codes listed in [VERSIONING.md](../VERSIONING.md#issue-codes); callers match `code`, not message wording |

The index and coverage JSON markers are also public under VERSIONING.md and
retain that policy. Python modules remain internal. Rule content and the baseline
pack have their own version; a package release need not change the pack version.

## Migration and deprecation

After 1.0, announce a deprecation in documentation and the changelog at least one
minor release before removal. Keep the old contract working during that window,
name the replacement, and include an input/output or command migration example.
Removal or another breaking change happens only in a major release, even when
the notice window has elapsed. Do not reuse retired rule IDs or issue codes.

A breaking JSON report change requires a new format marker, such as `/v2`, with
a documented migration path. Removing or renaming fields, changing their types
or meanings, tightening accepted inputs, or changing an exit code counts as
breaking. Adding optional fields or commands does not. Consumers should ignore
unknown report fields and handle unknown issue codes without assuming success.

Before 1.0, the existing policy permits a documented breaking minor release with
a migration step. This readiness proposal does not change that policy.

## Acceptance criteria and pending decisions

| Criterion | Evidence required before a 1.0 decision | Current state |
| --- | --- | --- |
| Contract inventory | Compare all command help, schema files, issue-code tables, and published examples; settle any mismatch | Inventory above; final 1.0 review pending |
| Backward compatibility | Published baselines still pass; validation and review reports retain the fixture field/type floor; additive-field probe passes | Automated tests exist; rerun for the proposed 1.0 head |
| Quality gates | Full tests pass with at least 95% branch coverage, CI property profile passes, strict pack validation and export drift checks pass | Repositories' existing gates; fresh 1.0 evidence pending |
| Packaging and release evidence | Wheel and sdist build and metadata checks pass; SBOM root and runtime inventory pass; attestations can be verified for release artifacts | Workflow checks exist; proposed 1.0 artifacts pending |
| Security review | Required security checks pass on the proposed head and findings are reviewed with their scope and residual risk recorded | Fresh 1.0 review pending; a green scan alone is not a safety claim |
| External feedback | At least **3 external users** complete installation, pack validation, and a review-record workflow, with feedback recorded and material problems addressed | **Owner pending:** recruit users, collect evidence, and confirm this proposed threshold; no such feedback is asserted here |
| Owner decision | Review the evidence, unresolved feedback, migration notes, and release checklist before authorizing a 1.0 tag | **Owner pending** |

Three users is a proposed small pilot threshold, not a measured adoption count.
Feedback remains an owner task under issue #29. This preparation references that
issue and does not close it.

## Report fixtures

`tests/fixtures/compat/reports/validation-v1.json` and `review-v1.json` were
captured from the current CLI with deterministic inputs and `--format json`.
The validation input is the existing invalid-enum fixture. The review input is
the worked payments example with the first `met` result's evidence removed;
`--as-of 2026-10-05` fixes the exception date. Both deliberately fail validation
so their issue objects are present. The review also includes evidence, notes,
and an exception object.

`tests/test_report_compat.py` runs the same commands, validates the emitted
reports against their schemas, and compares nested field presence and exact
JSON value types against the saved fixtures. Array entries are compared by
shape, not order or count. A new field is accepted; removing a fixture field or
changing its type fails. This floor covers fields exercised by those inputs;
existing schema, exit-code, and invalid-input tests cover other cases. Do not
refresh a fixture just to make a breaking change pass.
