# Versioning and compatibility

This project ships three things that carry a version. They move independently, and each
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the rules below.
Until 1.0, a minor release (0.x.0) may break compatibility; when it does, the changelog
says so under "Breaking changes" and gives a migration step.

| Version | Where it lives | Bumped when |
| --- | --- | --- |
| Package (`appsec-rules-pack`) | `src/appsec_rules_pack/__init__.py`, PyPI, git tags `vX.Y.Z` | Any release of the CLI, the schemas, or the reports |
| Rule schema | `$id` of `appsec-rule.schema.json`, pinned to the tag that last changed it | The rule contract changes |
| Baseline pack | `pack.version` in `rules/appsec-baseline.yaml` | Rule content changes: a rule, its text, or its mappings |

The baseline pack version can lag the package version. v0.4.1, for example, shipped pack
version 0.4.0 because no rule changed.

## Public surface

These are the parts other tools can rely on:

- the `appsec-rules` command line: commands, options, and exit codes (`0` pass, `1` fail,
  `2` usage error, after which no JSON report is printed);
- the JSON reports, identified by their `schema` field: `appsec-rules-validation/v1`
  (`validate --format json`, described by
  [`validation-report.schema.json`](src/appsec_rules_pack/schemas/validation-report.schema.json)),
  `appsec-rules-index/v1` (`export index`), and `appsec-rules-coverage/v1` (`report coverage --format json`);
- the issue `code` values listed below;
- the rule schema under `src/appsec_rules_pack/schemas/`.

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

Every issue in the validation report carries one of these codes.

| Code | Level | Meaning |
| --- | --- | --- |
| `file-unreadable` | error | The file could not be read |
| `file-not-utf8` | error | The file is not valid UTF-8 |
| `file-too-large` | error | The file is larger than 10 MiB |
| `yaml-invalid` | error | The YAML does not parse, uses an alias, or repeats a key |
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
