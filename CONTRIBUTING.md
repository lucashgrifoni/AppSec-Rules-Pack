# Contributing

## Rule Authoring Principles

- Keep rules generic and reusable.
- Do not add secrets, tokens, credentials, customer data, tenant IDs, internal hostnames,
  private URLs, screenshots, logs, or environment-specific names.
- Prefer precise, reviewable guidance over broad checklist language.
- Add only rules that can be validated with evidence.
- Include remediation and validation steps that another engineer can execute.

## Adding A Rule

1. Choose a stable ID using the pattern `APPSEC-AREA-###`.
2. Add the rule to `rules/appsec-baseline.yaml`.
3. Map the rule to relevant frameworks only.
4. Add expected evidence and review signals.
5. Define the exception requirement and maximum exception duration.
6. Run validation and tests.

## Framework Mapping Convention

Mappings are assigned **by topic**, not by CWE membership. A rule maps to the category
whose subject matter it addresses, even when one of its CWEs is listed under a different
category in that framework's own CWE table. For example `APPSEC-SESSION-001` maps to
`A07:2025` although CWE-614 appears under `A02:2025`.

Consequences worth knowing before you add a mapping:

- Prefer **one** category per framework. Reach for a second only when the rule genuinely
  covers two distinct subjects, not to capture every CWE's official home.
- `mappings.owasp_top_10_2025` and `mappings.owasp_api_top_10_2023` are **optional**. Leave a mapping out when no category matches the
  rule's topic without stretching. An absent mapping is honest; a stretched one is not.
- Mappings are evidence aids for review. They are not a claim of conformance to ASVS,
  the API Top 10, the Top 10, or NIST SSDF.

Editing `rules/appsec-baseline.yaml` invalidates the checked-in `exports/` artifacts.
Regenerate all three and commit them with the rule change, or the byte-comparison tests
in `tests/test_cli_export_output.py` will fail:

```powershell
python -m appsec_rules_pack export index rules/appsec-baseline.yaml --output exports/appsec-baseline.index.json
python -m appsec_rules_pack export semgrep rules/appsec-baseline.yaml --output exports/semgrep/appsec-baseline.semgrep.yaml
python -m appsec_rules_pack export sarif rules/appsec-baseline.yaml --output exports/sarif/appsec-baseline.sarif.json
```

## Severity Model

- `critical`: direct path to unauthorized privileged access, remote code execution, or
  broad sensitive-data compromise.
- `high`: realistic exploit path with meaningful confidentiality, integrity, or
  availability impact.
- `medium`: exploitable weakness with bounded impact or compensating controls.
- `low`: hardening, hygiene, or defense-in-depth guidance.

Severity must be based on a plausible AppSec abuse case, not only on framework mapping.

## Exception Requirements

Exceptions must include:

- accountable owner;
- business or technical justification;
- expiry date;
- compensating control when risk is medium or higher;
- validation plan for closure.

The default maximum exception duration is 90 days. Longer exceptions need explicit
review before being added to this pack.

## Automated Test Policy

Every major new capability must include automated tests for its supported behavior
and important failure cases. A bug fix must include a regression test that fails
without the fix, unless the pull request explains why that is not practical and
provides another reproducible verification method.

Rule and mapping changes must preserve the baseline examples and derived-export
checks. Keep the normal coverage gate enabled. Optional engine integrations need
their own behavioral fixtures; a passing catalog validator does not test a scanner.
Documentation commands that act as quality gates should have executable examples
that demonstrate both acceptance and rejection.

## Required Checks

```powershell
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings
python -m ruff check .
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
python -m build
```

These are the same commands CI runs. `--require-examples` matters: CI passes it, so a
rule without a compliant and violating example passes locally without the flag and then
fails the build.

Validation must report zero errors and zero warnings before a rule change is merged.
Framework mapping identifiers must use canonical formats (for example `CWE-79`,
`API1:2023`, `V1.2` (OWASP ASVS 5.0), `PW.4`); malformed identifiers are reported
as warnings. ASVS identifiers reference OWASP ASVS 5.0.0.

When validating multiple YAML packs in one directory, rule IDs must be unique across
all files, not only within a single file.

If a check cannot be run, document why and describe the residual risk before requesting
review.
