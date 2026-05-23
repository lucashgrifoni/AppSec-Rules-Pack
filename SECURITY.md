# Security Policy

## Supported Versions

Security fixes target the current `0.1.x` development line and `master` until the
first remote release is tagged. Older pre-release commits are not maintained.

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories
(the repository "Security" tab, "Report a vulnerability"). Include the affected
version or commit, reproduction steps, and expected impact.

Do not include proprietary source code, private findings, credentials, customer
data, or exploit payloads from systems you do not own.

## Scope

In scope:

- Rule schema validation.
- Rule pack integrity and unsafe rule metadata.
- CLI behavior for local validation.

Out of scope:

- Claims that downstream code is secure because it maps to this rules pack.
