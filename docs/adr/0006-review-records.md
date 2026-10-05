# ADR-0006: Record reviews against a pack, and check the record, not the code

- **Status:** Accepted
- **Date:** 2026-10-05
- **Related:** [ADR-0001](0001-engine-agnostic-validator.md),
  [ADR-0004](0004-ci-gate-consumes-json.md)

## Context

A rule in a pack states a policy: a severity, an enforcement level, the evidence a
reviewer needs, and whether an exception may be granted, for how long, and with which
fields. Until v0.5.0 nothing in the project consumed that policy. `validate` judges only
whether the pack file is well formed, so a team could adopt the baseline, pass
`validate`, and still have no way to say which rules a given service meets, which it does
not, and which exceptions it holds.

Three findings in the 2026-10-05 maturity review reached this gap on their own. It is the
step between "we have a policy" and "we can gate on it".

## Decision

Add a review record and a `review` command.

- A **review record** is a YAML file, described by `review-record.schema.json`, that
  states the outcome of reviewing one subject (a service, repository, or release) against
  one pack: a result per rule (`met`, `not-met`, `not-applicable`, `excepted`), the
  evidence for `met`, and the exception for `excepted`.
- `appsec-rules review <pack> <record>` checks the record against the pack's policy: the
  record names the right pack, every rule exists and appears once, `met` cites evidence,
  and each exception is allowed, carries the fields the pack requires, has not expired,
  and fits inside `max_days`. Enabled rules with no result are reported as `unreviewed`.
- The JSON report (`appsec-rules-review/v1`) lists every rule with its severity,
  enforcement, and status, and counts open rules (`not-met` or `unreviewed`) by
  enforcement and by severity.
- The exit code says only whether the **record** is valid. How many open rules are
  acceptable is a policy decision, made by the gate that reads the report, as ADR-0004
  already does for validation.

## Alternatives considered

- **Scan the code to decide the status.** Rejected: it contradicts ADR-0001 and would
  turn the project into a scanner. The record takes evidence from whatever produced it,
  including scanners and people.
- **Fail the command when a `blocking` rule is open.** Rejected for the same reason as
  enforcement in `validate` (ADR-0004): it fixes one organisation's policy in the tool.
  The report carries `enforcement` and `severity` so the gate can apply its own.
- **Put exceptions in a separate register file.** Rejected for now: an exception only
  means something next to the result it excuses, and one file per review keeps the
  record reviewable in a pull request.

## Consequences

- **Positive:** the pack's exception policy is checked for the first time. An expired or
  over-long exception, or one to a rule that forbids them, now fails a check instead of
  sitting unnoticed. A team gets a reviewable artefact per service and a report a gate can
  read.
- **Negative:** the record is self-declared. The command checks consistency with the
  pack, not the truth of the evidence; that still needs a reviewer. Exception expiry
  depends on the date, so the same record can pass today and fail later. That is
  intended, and `--as-of` makes a run reproducible.
- **Contract:** the record schema and the report are new public surface. They get a 0.x
  cycle before 1.0 freezes them (VERSIONING.md).
