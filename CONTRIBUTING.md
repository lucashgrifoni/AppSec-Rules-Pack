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

## Required Checks

```powershell
python -m appsec_rules_pack validate rules --fail-on-warnings
python -m ruff check .
python -m pytest --cov=appsec_rules_pack --cov-report=term-missing
python -m build
```

Validation must report zero errors and zero warnings before a rule change is merged.
Framework mapping identifiers must use canonical formats (for example `CWE-79`,
`API1:2023`, `V5.3`, `PW.4`); malformed identifiers are reported as warnings.

When validating multiple YAML packs in one directory, rule IDs must be unique across
all files, not only within a single file.

If a check cannot be run, document why and describe the residual risk before requesting
review.
