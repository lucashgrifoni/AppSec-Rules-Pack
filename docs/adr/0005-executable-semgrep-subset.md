# ADR-0005: Keep executable Semgrep references outside the validator

- **Status:** Accepted
- **Date:** 2026-10-04
- **Related:** [ADR-0001](0001-engine-agnostic-validator.md),
  [ADR-0004](0004-ci-gate-consumes-json.md)

## Context

The generated Semgrep scaffold describes baseline rules but cannot detect code
issues. A small runnable reference subset helps consumers test adoption without
suggesting that all 19 review rules are statically detectable. The validator's
engine-agnostic contract must remain intact.

## Decision

Add two hand-maintained Python taint rules under `exports/semgrep-rules/`, linked
by `metadata.baseline_id` to `APPSEC-INJECT-001` and `APPSEC-SSRF-001`. They cover
only recognized Flask query/form values reaching local sqlite3 SQL arguments or
module-level Requests URL arguments. The layer documents unsupported APIs,
false-positive cases, and known detection gaps.

An independently installed Semgrep Community Edition engine runs these files.
The validator never imports, invokes, installs, or depends on that engine. CLI
commands, the rule schema, the baseline, generated exports, and PyPI package
contents are unchanged. `export semgrep` continues to produce only its labeled
non-runnable scaffold; SARIF export remains a catalog with no results.

This extends ADR-0001's generated-artifact policy only for this separate,
hand-maintained reference directory. Its engine boundary remains unchanged.
Generated exports remain drift-tested; executable references use baseline-link
checks and positive/negative behavioral fixtures instead of bytewise derivation.
No rule can claim broader detection coverage than its documented tested subset.

## Verification and containment

The dedicated CI workflow pins Semgrep 1.179.0 and runs `semgrep --test --strict`
against real `ruleid:`/`ok:` fixture annotations. It uses the same existing
read-only permissions and blocked-egress runner pattern, fetching the engine
from PyPI; it needs no Registry configuration or credentials. Unit tests enforce
the baseline links and fixture inventory without making Semgrep a development
dependency for the validator test suite.

Intentionally insecure code stays in the two named static fixture files, never
under `src/`. The exact paths are excluded from general Semgrep repository
scans and explicitly included in rule tests. Existing scanner workflows and
their gates are unchanged. No broad directory or application-code exclusion is
introduced.

## Alternatives

- Embed an engine or emit findings through the validator: rejected because it
  changes the existing contract and adds an engine runtime dependency.
- Relabel the scaffold as detection: rejected because placeholders do not
  implement the review rules.
- Implement a broad multi-framework pack immediately: deferred until each
  additional source and sink has tested behavior and documented limitations.

## Consequences

Consumers get a runnable, reviewable starting point for two baseline topics.
The remaining 17 rules still have no executable detection. Even the two covered
topics retain substantial manual-review scope. The cost is maintaining an
additional engine-version pin and fixture suite; cross-function behavior,
allowlist proof, DNS, and runtime network controls remain outside this layer.

Update 2026-10-07 (v0.9.0): a third rule, for `APPSEC-DESER-001`, follows the same
constraints: taint mode, exact Flask sources, and a fixture with positive and negative
cases. The decision itself is unchanged.

The [layer README](../../exports/semgrep-rules/README.md) contains the supported
API inventory, commands, full baseline coverage list, and links to Semgrep's
official testing and taint-analysis documentation.
