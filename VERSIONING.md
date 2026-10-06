# Versioning and compatibility

This project ships three things that carry a version. They move independently, and each
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the rules below.
Until 1.0, a minor release (0.x.0) may break compatibility; when it does, the changelog
says so under "Breaking changes" and gives a migration step.

| Version | Where it lives | Bumped when |
| --- | --- | --- |
| Package (`appsec-rules-pack`) | `src/appsec_rules_pack/__init__.py`, PyPI, git tags `vX.Y.Z` | Any release of the CLI, the schemas, or the reports |
| Schemas | `$id` of each file under `src/appsec_rules_pack/schemas/`, pinned to the tag that last changed it | That contract changes |
| Baseline pack | `pack.version` in `rules/appsec-baseline.yaml` | Rule content changes: a rule, its text, or its mappings |

The baseline pack version can lag the package version. v0.4.1, for example, shipped pack
version 0.4.0 because no rule changed.

The proposed 1.0 contract freeze, migration policy, and acceptance criteria are
recorded in [docs/v1-readiness.md](docs/v1-readiness.md). External feedback and the
1.0 release decision remain pending with the owner.

## Public surface

These are the parts other tools can rely on:

- the `appsec-rules` command line: commands, options, and exit codes (`0` pass, `1` fail,
  `2` usage error, after which no JSON report is printed);
- the JSON reports, identified by their `schema` field: `appsec-rules-validation/v1`
  (`validate --format json`, described by
  [`validation-report.schema.json`](src/appsec_rules_pack/schemas/validation-report.schema.json)),
  `appsec-rules-review/v1` (`review --format json`, described by
  [`review-report.schema.json`](src/appsec_rules_pack/schemas/review-report.schema.json)),
  `appsec-rules-index/v1` (`export index`), and `appsec-rules-coverage/v1` (`report coverage --format json`);
- the issue `code` values listed below;
- the rule schema and the review record schema
  ([`review-record.schema.json`](src/appsec_rules_pack/schemas/review-record.schema.json))
  under `src/appsec_rules_pack/schemas/`;
- the starter pack written by `init`, which always passes the strict gate. Its content
  may change in any release.

The Python modules are internal. Import them at your own risk; they can change in any
release.

## What counts as a breaking change

Breaking, so it needs a new major version (or, before 1.0, a minor version marked as
breaking):

- removing or renaming a schema field, or making an optional field required;
- removing an enum value (a category, severity, status, target, or example language);
- tightening a pattern so that a previously valid pack fails;
- removing or renaming a JSON report field, or changing its type or meaning;
- removing or renaming an issue `code`;
- changing an exit code for the same input;
- removing or renaming a CLI command or option.

Not breaking, so a minor or patch release is enough:

- adding an optional schema field, an enum value, or a JSON report field;
- relaxing a pattern or making a required field optional;
- adding an issue `code` or a new warning;
- rewording a `message` (match on `code`, never on message text);
- adding a CLI command or option.

## Declaring the schema a pack targets

A pack may set `pack.schema_version` (for example `"0.5"`). The validator accepts any
version up to the one it supports and refuses a pack that targets a newer one, with the
issue code `schema-version-unsupported`. Packs that omit the field are validated against
the installed schema, as before.

Schema version 0.7 (package 0.7.0) adds the optional `owasp_llm_top_10_2025` mapping and
makes `owasp_asvs` optional. The baseline declares `schema_version: "0.7"` from pack
version 0.7.0. An older validator refuses it, and its report includes
`schema-version-unsupported`, which names the cause, next to the schema errors for the new
mapping. Validate baseline 0.7.0 with package 0.7.0 or later.

## Extension fields

Keys starting with `x-` are allowed on the `pack` object, on each rule, and inside
`mappings` (where they must hold a non-empty list of strings, for example
`x-pci-dss: ["6.2.4"]`). The validator never interprets them and never reports them as
unexpected. Use them for organisation-specific metadata instead of forking the schema.

## Rule lifecycle and ids

- A rule id is never reused, even after the rule is removed. Ids follow
  `PREFIX-AREA-NNN` (for example `APPSEC-AUTHZ-001` or `ACME-AUTH-002`).
- A rule is retired by setting `status: deprecated` and a `deprecation` block with a
  `reason`, and, when there is one, `replaced_by` and `since`.
- A deprecated rule stays in the baseline for at least one minor release before it is
  removed, and its removal bumps the pack's minor version.

## Issue codes

Every issue in the validation report carries one of these codes. The review report uses
the file, YAML, schema, and `sensitive-value` codes for the record, plus the review codes
in the next section.

| Code | Level | Meaning |
| --- | --- | --- |
| `file-unreadable` | error | The file could not be read |
| `file-not-utf8` | error | The file is not valid UTF-8 |
| `file-too-large` | error | The file is larger than 10 MiB |
| `yaml-invalid` | error | The YAML does not parse, uses an alias, repeats a key, or has an unquoted date that is not a real day |
| `yaml-too-deep` | error | The YAML nests deeper than the parser supports |
| `schema-missing-field` | error | A required field is missing |
| `schema-unexpected-field` | error | A field is not part of the schema |
| `schema-enum` | error | A value is not one of the allowed values |
| `schema-type` | error | A value has the wrong type |
| `schema-pattern` | error | A value does not match the required pattern |
| `schema-length` | error | A string is too short or too long |
| `schema-min-items` | error | A list has too few items |
| `schema-unique-items` | error | A list repeats an item |
| `schema-range` | error | A number is out of range |
| `schema-invalid` | error | Any other schema violation |
| `schema-version-unsupported` | error | `pack.schema_version` is newer than this validator supports |
| `duplicate-rule-id` | error | A rule id appears twice, in one file or across files |
| `exception-disallowed-window` | error | `allowed: false` with a non-zero `max_days` |
| `exception-disallowed-fields` | error | `allowed: false` with `required_fields` |
| `sensitive-value` | error | Rule content looks like it contains a secret |
| `exception-window-too-long` | warning | `max_days` is above the 90-day review default |
| `exception-missing-fields` | warning | An allowed exception does not require owner, justification, and expiry |
| `exception-zero-window` | warning | An allowed exception has `max_days: 0` |
| `mapping-id-malformed` | warning | A framework mapping id has the wrong format |
| `deprecation-missing` | warning | A deprecated rule has no `deprecation` block |
| `deprecation-status-mismatch` | warning | A `deprecation` block on a rule that is not deprecated |
| `examples-missing` | warning | An enabled rule has no examples (`--require-examples`) |
| `example-key-material` | warning | A rule example contains what looks like real key material |

### Review codes

`appsec-rules review` checks a review record against a pack (see
[ADR-0006](docs/adr/0006-review-records.md)). None of these codes depend on whether a rule
is open: a record can be valid and still have every rule `not-met`.

| Code | Level | Meaning |
| --- | --- | --- |
| `review-pack-invalid` | error | The rules pack does not load or does not validate, so the record cannot be checked |
| `review-pack-mismatch` | error | `review.pack` is not the `pack.id` of the rules pack |
| `review-pack-version-mismatch` | warning | `review.pack_version` is not the pack's current version |
| `review-unknown-rule` | error | A result names a rule the pack does not have |
| `review-duplicate-result` | error | A rule has more than one result |
| `review-rule-not-enabled` | warning | A result is for a rule that is disabled, draft, or deprecated |
| `review-missing-result` | warning | An enabled rule has no result; it is reported as `unreviewed` |
| `review-evidence-missing` | error | A `met` result cites no evidence |
| `review-justification-missing` | warning | A `not-met` or `not-applicable` result has no `notes` saying why |
| `review-exception-unexpected` | error | A result has an `exception` block but is not `excepted` |
| `review-exception-missing` | error | An `excepted` result has no `exception` block |
| `review-date-invalid` | error | A quoted date has the right shape but is not a real day, such as "2026-02-30" (unquoted, it is `yaml-invalid`) |
| `exception-not-allowed` | error | The pack sets `exceptions.allowed: false` for that rule |
| `exception-field-missing` | error | The exception lacks a field listed in the rule's `required_fields` |
| `exception-expired` | error | `expires_at` is on or before the `--as-of` date (today by default) |
| `exception-window-exceeded` | error | The exception runs longer than the rule's `max_days`, counted from `granted_at` or the review date |
| `exception-dates-invalid` | error | The exception expires on or before the day it was granted |
