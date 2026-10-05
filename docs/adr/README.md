# Architecture Decision Records

Decisions that shaped this project, with the alternatives that were rejected and why.
They are referenced from the source, the README, and the technical spec.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-engine-agnostic-validator.md) | The validator stays engine-agnostic; interoperability lives in a derived `exports/` layer | Accepted |
| [0002](0002-asvs-5-0-mappings.md) | Migrate framework mappings to OWASP ASVS 5.0 | Accepted |
| [0003](0003-release-provenance.md) | Trusted Publishing, build attestations, and an SBOM on every release | Accepted |
| [0004](0004-ci-gate-consumes-json.md) | The CI policy gate consumes the validator's JSON; enforcement is not built in | Accepted |
| [0005](0005-executable-semgrep-subset.md) | Hand-maintained executable Semgrep references run only in an external engine | Accepted |
| [0006](0006-review-records.md) | Record reviews against a pack and check the record against the pack's policy, not the code | Accepted |

ADR-0001 and ADR-0004 together define the project's central boundary: this is a rule
contract and a deterministic validator, not a scanner.

ADR-0005 adds a separately tested executable reference subset without adding an
engine to the validator or changing the generated scaffold.

ADR-0006 gives the pack's policy a consumer: a review record per subject, checked
against the pack, with the gate decision still outside the tool.
