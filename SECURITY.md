# Security Policy

## Supported Versions

`appsec-rules-pack` is published on PyPI. Security fixes target the current `0.3.x`
release line and `main`.

| Version | Supported |
| ------- | --------- |
| 0.3.x   | ✅        |
| 0.2.x   | ❌        |
| 0.1.x   | ❌        |

Earlier builds and pre-release commits are not maintained; upgrade to the latest
`0.3.x` release.

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories:

**https://github.com/lucashgrifoni/AppSec-Rules-Pack/security/advisories/new**

Private vulnerability reporting is enabled on this repository, so that form is open to
anyone. Include the affected version or commit, reproduction steps, and expected impact.

Expect an acknowledgement within 7 days. This is a single-maintainer project, so please
allow a reasonable disclosure window before publishing.

Do not include proprietary source code, private findings, credentials, customer
data, or exploit payloads from systems you do not own.

## Scope

In scope:

- Rule schema validation.
- Rule pack integrity and unsafe rule metadata.
- CLI behavior for local validation.

Out of scope:

- Claims that downstream code is secure because it maps to this rules pack.
