# ADR-0009: Record an assessed severity per result; do not derive not-applicable from a subject type

- **Status:** Accepted
- **Date:** 2026-10-07
- **Deciders:** maintainer
- **Related:** [ADR-0004](0004-ci-gate-consumes-json.md),
  [ADR-0006](0006-review-records.md)

## Context

The internal review of seven test labs and one real tool against the 0.6.0 baseline
(2026-10-05) raised two requests about review records.

**Severity is the rule's, not the finding's.** The report counts open rules by the
severity the pack gives each rule. Two records showed that this count can be wrong in
both directions:

- In the oss-policy-kit record, the only `critical` rule (`APPSEC-INJECT-001`) was open
  because of a finding the reviewer assessed as high and reachable only through an
  opt-in flag. A gate that stops on open critical rules stopped for the wrong reason.
- In the identity lab, a login callback that accepts any email without a signature
  gives a full authentication bypass, including admin. It counted as `high`, the
  severity of `APPSEC-AUTHN-001`, the same as a missing session rotation.

Reviewers wrote the real assessment in `notes`, where no gate can read it.

**Many rules are ruled out by hand.** Records for subjects that are not web services
justified most rules as `not-applicable` one by one: 11 of 20 in the oss-policy-kit
record and 17 of 20 in the policy-fixtures lab. The proposal was a record-level subject
type (a CLI, a GitHub Action, fixtures) from which the tool would mark non-matching
rules `not-applicable`.

The data does not support that proposal. Every one of the 24 baseline rules lists `api`
or `backend` in `targets`, so no subject type separates them. Within one record,
rules with the same targets got opposite decisions:

- oss-policy-kit, a CLI: `APPSEC-AUTHZ-001` (`api`, `backend`) is not applicable, while
  `APPSEC-SSRF-001` (`api`, `backend`) applies, because the collectors call remote APIs.
- AI lab: `APPSEC-INJECT-001` (`api`, `backend`, `ci`) is not applicable, while
  `APPSEC-AUTHZ-001` (`api`, `backend`) applies.

The reviewer's reason in each case depends on what the subject does, which the target
list does not say.

## Decision

1. **Add an optional `assessed_severity` to a result.** It takes the rule severity values
   (`critical`, `high`, `medium`, `low`) and is allowed only on `not-met` and `excepted`
   results, where there is a finding to assess. On `met` or `not-applicable` it is an
   error, `review-assessed-severity-unexpected`.
2. **The report keeps the rule's view and adds the assessed one.** Each result gains
   `effective_severity`: the assessed severity when present, otherwise the rule
   severity. The summary gains `open_by_effective_severity`. The existing `severity` per
   result and `summary.open_by_severity` keep their meaning, the rule's severity, so
   current gates read the same numbers as before.
3. **No record-level subject type.** `not-applicable` stays a per-rule judgment with
   `notes`, as `review-justification-missing` requires since 0.7.0.

The documented gate in `examples/README.md` keeps reading `open_by_severity`. A team
that reviews severity changes in pull requests can gate on
`open_by_effective_severity` instead; that choice belongs to the gate (ADR-0004).

## Alternatives considered

- **Overwrite `severity` and `open_by_severity` with the assessed value.** Rejected: it
  changes the meaning of existing report fields (a breaking change under VERSIONING.md)
  and lets a record lower what every current gate sees with no trace in the report.
- **Warn when the assessed severity is lower than the rule's.** Rejected: a justified
  downgrade, such as the oss-policy-kit case, would fail every run with
  `--fail-on-warnings`, which pushes teams to drop the field instead of using it. The
  report shows both values, so a reviewer or gate can still see every downgrade.
- **Require `notes` with an assessed severity.** Not needed: `not-met` results already
  warn without `notes`, and an `excepted` result carries a justification in its
  exception.
- **Subject type that marks rules not-applicable.** Rejected for the reasons in Context.
  A finer target vocabulary per rule (for example "makes outbound requests" or "has
  user accounts") might discriminate, but it would be a new taxonomy for every pack, and
  no record so far shows which one would hold. It can be revisited with evidence from
  external users.
- **A shared default note for many not-applicable rules.** Rejected: it would bring back
  the unjustified `not-applicable` that 0.7.0 started to warn about.

## Consequences

- **Positive:** the reviewer's assessment reaches the report in a field a gate can read,
  in both directions. Existing gates and reports keep their numbers.
- **Negative:** a record can now lower the severity a gate sees, if that gate opts into
  `open_by_effective_severity`. The mitigation is visibility: every result shows both
  `severity` and `effective_severity`, and the change is in the record, reviewed in the
  same pull request as the code.
- **Unchanged:** records for non-service subjects still need one `notes` per
  not-applicable rule.
- **Contract:** `assessed_severity`, `effective_severity`,
  `open_by_effective_severity`, and the new issue code are additions, so they ship in a
  minor release without a migration step (VERSIONING.md).

## Validation

- Tests: `assessed_severity` accepted on `not-met` and `excepted`, rejected on `met` and
  `not-applicable`, and reflected in `effective_severity` and
  `open_by_effective_severity`; `open_by_severity` unchanged by it.
- The worked example and the published report schema cover the new fields.
