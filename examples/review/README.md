# Worked review: payments-api

[`payments-api-review.yaml`](payments-api-review.yaml) is the review record of a fictional
service, `payments-api`, against the 29 rules of the baseline pack. It shows each status
a rule can have:

| Status | Rules | What the record must carry |
| --- | --- | --- |
| `met` | 18, such as `APPSEC-AUTHZ-001` | At least one `evidence` entry |
| `not-applicable` | 9, such as `APPSEC-XSS-001` (the service renders no HTML) | `notes` saying why; without it, `review-justification-missing` warns |
| `not-met` | `APPSEC-LOG-001` (refund failures log the card holder name) | `notes` describing the finding; optional `evidence` locates the defect |
| `excepted` | `APPSEC-RATELIMIT-001` | An `exception` that the pack allows, with the fields the pack requires, inside its window |

The evidence entries point into the fictional service's repository. In a real record they
are whatever lets a second reviewer check the claim: a test, a file, a scanner run, a
ticket.

For `not-met`, `evidence` is optional and points to where the rule fails. The
`APPSEC-LOG-001` entry points to the refund error path that logs the processor response.
An evidence reference does not make the result `met`.

## Check it

From a source checkout:

```bash
appsec-rules review rules/appsec-baseline.yaml examples/review/payments-api-review.yaml --as-of 2026-10-05
```

```text
APPSEC-AUTHZ-001         high      advisory  met
...
APPSEC-LOG-001           medium    advisory  not-met
...
APPSEC-RATELIMIT-001     medium    advisory  excepted
Review passed: 29 rules; 18 met, 1 not met, 9 not applicable, 1 excepted, 0 unreviewed; 1 open; 0 errors, 0 warnings.
```

"Review passed" means the record is consistent with the pack. It does not mean the service
passed: `APPSEC-LOG-001` is still open. Deciding what may stay open is the gate's job,
with the JSON report (`--format json`). The report counts open rules by enforcement and by
severity; [`examples/README.md`](../README.md#github-actions-template) has a gate that
reads it.

All 29 baseline rules are `advisory`, so
`summary.open_by_enforcement.blocking` is zero even when baseline rules are open.
Use `summary.open_by_severity` for a severity gate, after checking the command's
exit code and `summary.ok`. This record has `medium: 1`; `critical`, `high`, and
`low` are zero. A policy that rejects open medium rules rejects this service while
the record still passes validation. Alternatively, fork the baseline and raise
selected rules' `enforcement` to `blocking`, following
[`docs/rule-fields.md`](../../docs/rule-fields.md#adapting-the-baseline).
The count maps omit zero entries. Treat missing keys as zero, for example with
`summary["open_by_severity"].get("medium", 0)` in Python.

`--as-of` pins the date that exceptions are checked against, so this example keeps
passing. Without it, `review` uses today's date, and the exception, which expires on
2026-12-15, fails the record from that day on.

## What the command rejects

Change the record and run it again to see each check:

| Change | Result |
| --- | --- |
| Remove the `evidence` of a `met` rule | `review-evidence-missing` |
| Set `APPSEC-INJECT-001` to `excepted` | `exception-not-allowed`: the pack forbids exceptions to it |
| Remove `compensating_control` from the exception | `exception-field-missing`: the pack requires it for `APPSEC-RATELIMIT-001` |
| Move `expires_at` to 2027-01-15 | `exception-window-exceeded`: 106 days, the pack allows 90 |
| Run without `--as-of` after 2026-12-15 | `exception-expired` |
| Delete a result | `review-missing-result` (a warning; the rule shows as `unreviewed`) |
| Remove the `notes` of a `not-applicable` rule | `review-justification-missing` (a warning) |

[VERSIONING.md](../../VERSIONING.md#review-codes) lists every code, and
[ADR-0006](../../docs/adr/0006-review-records.md) explains the design.
