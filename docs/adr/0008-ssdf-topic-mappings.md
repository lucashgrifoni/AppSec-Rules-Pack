# ADR-0008: Map SSDF topics consistently at practice level

- **Status:** Proposed; awaiting the v0.6.0 pull request review
- **Date:** 2026-10-05
- **Related:** [ADR-0002](0002-asvs-5-0-mappings.md), issue #28

## Context

The baseline maps rule subjects to frameworks as review aids. Several SSDF entries
instead named an activity used to verify the rule. Injection and XSS were mapped
to PW.9 (default settings), while authorization and SSRF used PW.8 (executable
testing). Those activities do not describe the rule subjects.

[NIST SP 800-218, SSDF v1.1, Table 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)
distinguishes security design (PW.1), secured component reuse (PW.4), secure coding
(PW.5), code analysis (PW.7), executable testing (PW.8), default settings (PW.9),
and vulnerability discovery (RV.1). PW.5.1 includes input validation and output encoding.

## Decision

Use one **practice-level** SSDF ID per baseline rule, such as `PW.5`.
Choose the practice that describes the control's subject and intended outcome.
Do not map to testing or code analysis solely because tests or reviews are listed
as evidence. A second practice needs two distinct subjects and a written rationale.

Tasks, such as PW.5.1, may be cited in the rationale without appearing as a second
mapping. Preserve topic-based design mappings where the rule specifies a security
boundary or policy, rather than assigning every application control to secure coding.
The schema continues to accept practice and task IDs for custom packs.

[The mapping table](../mapping-rationale.md) records the final ASVS and SSDF entries
for all 20 rules, including unchanged entries and intentional omissions.

## Alternatives considered

- Use tasks everywhere. More precise when a rule addresses a specific task, but
  several rules specify an outcome that spans tasks. This would imply unsupported precision.
- Mix practices and tasks. Valid under the schema, but inconsistent for this baseline.
- Map every reviewable rule to PW.7 or PW.8. This confuses the verification method
  with the subject and hides distinctions between design, coding, and settings.

## Consequences and validation

The baseline changes mapping metadata and regenerated exports only. The CLI, report
contracts, schema patterns, rule IDs, and enforcement remain unchanged.
Run the strict validator, mapping-source test, coverage report, and all three export
drift checks. The ASVS snapshot verifies identifier existence offline; it cannot
prove semantic coverage. Reversing this decision requires a reviewed content change
and regeneration of the exports, without a runtime migration.
