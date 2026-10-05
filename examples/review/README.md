# Worked review: payments-api

[`payments-api-review.yaml`](payments-api-review.yaml) is the review record of a fictional
service, `payments-api`, against the 19 rules of the baseline pack. It shows each status
a rule can have:

| Status | Rules | What the record must carry |
| --- | --- | --- |
| `met` | 12, such as `APPSEC-AUTHZ-001` | At least one `evidence` entry |
| `not-applicable` | 5, such as `APPSEC-XSS-001` (the service renders no HTML) | Nothing; `notes` says why |
| `not-met` | `APPSEC-LOG-001` (refund failures log the card holder name) | Nothing; `notes` says what is wrong |
| `excepted` | `APPSEC-RATELIMIT-001` | An `exception` that the pack allows, with the fields the pack requires, inside its window |

The evidence entries point into the fictional service's repository. In a real record they
are whatever lets a second reviewer check the claim: a test, a file, a scanner run, a
ticket.

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
Review passed: 19 rules; 12 met, 1 not met, 5 not applicable, 1 excepted, 0 unreviewed; 1 open; 0 errors, 0 warnings.
```

"Review passed" means the record is consistent with the pack. It does not mean the service
passed: `APPSEC-LOG-001` is still open. Deciding what may stay open is the gate's job,
with the JSON report (`--format json`). The report counts open rules by enforcement and by
severity; [`examples/README.md`](../README.md#github-actions-template) has a gate that
reads it.

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

[VERSIONING.md](../../VERSIONING.md#review-codes) lists every code, and
[ADR-0006](../../docs/adr/0006-review-records.md) explains the design.
