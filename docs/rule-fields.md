# Rules pack field reference

Every field of a rules pack, as the schema
([`appsec-rule.schema.json`](../src/appsec_rules_pack/schemas/appsec-rule.schema.json))
defines it. `tests/test_docs_fields.py` fails if a schema field is missing from this page.
The quickest way to start is `appsec-rules init my-pack.yaml`, which writes a pack that
already passes the strict gate.

Lengths are in characters. A "string list" is a non-empty list of strings of 1 to 240
characters each.

## `pack`

| Field | Required | Type and limits | Meaning |
| --- | --- | --- | --- |
| `id` | yes | lowercase letters, digits, and `-`; starts with a letter or digit | Stable identifier. Review records name the pack by it |
| `name` | yes | 3 to 120 | Human-readable name |
| `version` | yes | `MAJOR.MINOR.PATCH` | Version of the rule content (see [VERSIONING.md](../VERSIONING.md)) |
| `schema_version` | no | `MAJOR.MINOR`, such as `"0.5"` (quote it) | Schema the pack targets; a newer one than the validator supports is refused |
| `mode` | yes | `advisory`, `audit`, `blocking` | How the pack is meant to be used. Metadata for the gate; `validate` ignores it |
| `owner` | yes | 2 to 80 | Team that owns the pack |
| `description` | yes | 10 to 240 | What the pack covers |
| `x-...` | no | anything | Your own metadata; never interpreted |

## `rules[]`

| Field | Required | Type and limits | Meaning |
| --- | --- | --- | --- |
| `id` | yes | `PREFIX-AREA-NNN`, uppercase, such as `ACME-AUTH-001` | Stable rule id, never reused |
| `title` | yes | 8 to 120 | Short imperative statement |
| `description` | yes | 20 to 360 | What a reviewer verifies |
| `severity` | yes | `critical`, `high`, `medium`, `low` | Impact if the rule is not met. [CONTRIBUTING.md](../CONTRIBUTING.md) has the severity model |
| `category` | yes | `authentication`, `authorization`, `input-validation`, `injection`, `ssrf`, `secrets`, `file-handling`, `logging`, `dependency-risk`, `configuration`, `csrf`, `integrity`, `data-exposure`, `open-redirect`, `rate-limiting` | AppSec area |
| `status` | yes | `enabled`, `disabled`, `draft`, `deprecated` | Lifecycle. Only `enabled` rules go into the Semgrep and SARIF exports, need examples under `--require-examples`, and are expected in a review |
| `enforcement` | yes | `advisory`, `audit`, `blocking` | What the gate should do when the rule is open. Metadata; no command enforces it |
| `targets` | yes | unique list of `api`, `backend`, `frontend`, `mobile`, `ci`, `iac`, `data`, `dependencies`, `general` | Surfaces the rule applies to |
| `mappings` | yes | object, see below | Framework references |
| `evidence` | yes | object with `required` and `signals`, both string lists | What proves the rule is met, and what to look for |
| `match` | yes | object with `type`, `includes`, `excludes` | Where the rule applies |
| `remediation` | yes | object with `guidance` (20 to 480) and `validation` (string list) | How to fix it and how to confirm the fix |
| `exceptions` | yes | object with `allowed`, `max_days`, `required_fields` | Exception policy, checked by `review` |
| `examples` | no; the strict gate expects it on enabled rules | object with `compliant` and `violating` | One example of each |
| `deprecation` | no; expected when `status` is `deprecated` | object with `reason`, optional `replaced_by` and `since` | Why the rule was retired |
| `x-...` | no | anything | Your own metadata |

### `mappings`

| Field | Required | Format |
| --- | --- | --- |
| `owasp_asvs` | yes | ASVS 5.0 V-notation, such as `V8.2` or `V16.5.1` |
| `cwe` | yes | `CWE-<number>` |
| `nist_ssdf` | yes | SSDF practice or task, such as `PW.7` or `PW.7.2` |
| `owasp_api_top_10_2023` | no | `API1:2023` to `API10:2023` |
| `owasp_top_10_2025` | no | `A01:2025` to `A10:2025` |
| `x-...` | no | string list, such as `x-pci-dss: ["6.2.4"]` |

All mapping values are string lists. A malformed identifier is a warning, not an error.

### `match`

| Field | Required | Format |
| --- | --- | --- |
| `type` | yes | `review`, `static-analysis`, `configuration`, `schema` |
| `includes` | yes | string list: code or artefacts in scope |
| `excludes` | yes | string list: what is deliberately out of scope |

### `exceptions`

| Field | Required | Format |
| --- | --- | --- |
| `allowed` | yes | `true` or `false` |
| `max_days` | yes | integer, 0 to 365. Above 90 is a warning; `0` with `allowed: true` is a warning |
| `required_fields` | yes | unique list of `owner`, `justification`, `expires_at`, `compensating_control`, `validation_plan`. Must be empty when `allowed` is `false` |

### `examples.compliant` and `examples.violating`

| Field | Required | Format |
| --- | --- | --- |
| `language` | yes | `python`, `javascript`, `typescript`, `go`, `java`, `csharp`, `ruby`, `php`, `bash`, `yaml`, `json`, `toml`, `hcl`, `sql`, `text` |
| `snippet` | yes | 1 to 2000 |
| `explanation` | yes | 10 to 480 |

### `deprecation`

| Field | Required | Format |
| --- | --- | --- |
| `reason` | yes | 10 to 240 |
| `replaced_by` | no | a rule id |
| `since` | no | `YYYY-MM-DD` |

## Adapting the baseline

The baseline is generic on purpose. There are two ways to make it yours; pick one.

**Keep the baseline as published and add your own pack next to it.** Download
`appsec-baseline.yaml` from a pinned release and verify it (see the README), then put your
rules in a second file with your own id prefix (`ACME-...`). Validate the directory that
holds both: `validate` checks rule ids across files. To upgrade, re-pin a newer release.
Use this when you want the baseline's changes without merging them. Review records are
made per pack, so you keep one record per pack and subject.

**Fork the baseline.** Copy it, change `pack.id` (so a record made against your copy can
never be confused with one made against the original), and edit it freely: disable rules
with `status: disabled`, tighten `max_days`, or raise `enforcement` to `blocking` for the
rules your gate should stop on. Keep the original rule ids for rules you keep, so
mappings and history still line up, and never reuse an id for a different rule. Use this
when your policy differs from the baseline in more than a few places; you merge upstream
changes by hand.

In both cases, run `validate --require-examples --fail-on-warnings` on every change.
