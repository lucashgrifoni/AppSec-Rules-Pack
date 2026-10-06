# Baseline mapping rationale

Reviewed on 2026-10-05 for the first 20 rules in `rules/appsec-baseline.yaml`, and on
2026-10-06 for the four rules added in pack version 0.7.0.
Mappings connect a rule's topic to a framework section. They do not establish that
an application meets the section or that the rule covers the whole framework.

ASVS references below use **OWASP ASVS 5.0.0**. The supplied `v5.0.0` URL is a
release branch; the immutable release tag is `v5.0.0_release`, at
`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`. The offline ID snapshot in
`tests/fixtures/asvs-5.0.0-ids.json` was extracted from that tag's English chapter files.

SSDF references use **NIST SP 800-218, SSDF v1.1, Table 1**. Use practice-level
IDs consistently, as proposed in [ADR-0008](adr/0008-ssdf-topic-mappings.md).
PW.1 addresses security requirements and design risks; PW.4 addresses reuse of
secured components; PW.5 addresses secure source-code creation; PW.9 addresses
secure default settings. A rule's test or review evidence does not by itself make
its topic PW.7 (code analysis), PW.8 (executable testing), or RV.1 (vulnerability discovery).

| Rule | ASVS 5.0.0 and rationale | SSDF v1.1 and rationale |
| --- | --- | --- |
| APPSEC-AUTHZ-001 | [V8.2][asvs8]: trusted server-side object and tenant authorization. | [PW.1][ssdf1]: design the authorization boundary around trusted ownership and tenant context; replaces PW.8, which concerns testing an executable. |
| APPSEC-INPUT-001 | [V2.2][asvs2]: typed validation and input size, range, and format constraints. | [PW.5][ssdf5]: implement boundary validation; PW.5.1 explicitly includes input validation. Replaces PW.7, which concerns analyzing code. |
| APPSEC-INJECT-001 | [V1.2][asvs1]: parameterized APIs and safe interpreter boundaries. | [PW.5][ssdf5]: avoid unsafe query and command construction during coding; replaces PW.9, which concerns default configuration. |
| APPSEC-SSRF-001 | [V1.3][asvs1]: destination validation, including SSRF in requirement 1.3.6. | [PW.1][ssdf1]: design permitted outbound destinations and network trust boundaries; replaces PW.8, which concerns testing an executable. |
| APPSEC-AUTHN-001 | [V6.3][asvs6] and [V7.2][asvs7]: credential authentication and session validation are separate subjects in this rule. | [PW.1][ssdf1]: retain the design mapping for trusted authentication and session architecture. |
| APPSEC-SECRETS-001 | [V13.3][asvs13]: secret storage and access through controlled boundaries. | [PW.5][ssdf5]: avoid hard-coded credentials, fallback values, and sensitive log output in source; replaces PW.4, which concerns component reuse. |
| APPSEC-FILE-001 | [V5.2 and V5.3][asvs5]: file upload validation and storage/path isolation are separate subjects. | [PW.5][ssdf5]: implement type, size, filename, and traversal checks; replaces PW.7, which concerns code analysis. |
| APPSEC-LOG-001 | [V16.2 and V16.3][asvs16]: logging content/redaction and recording security events are separate subjects. | [PW.5][ssdf5]: implement security event output and redaction; replaces RV.1, which concerns discovering software vulnerabilities, not application event logging. |
| APPSEC-DEP-001 | [V15.2][asvs15]: dependency security and maintained components. | [PW.4][ssdf4]: retain the mapping for acquiring and maintaining secured components, including the PW.4.1 and PW.4.4 tasks. |
| APPSEC-CONFIG-001 | [V13.4][asvs13] and [V3.4][asvs3]: debug/information exposure and browser security headers, including CORS in 3.4.2, are separate subjects. | [PW.9][ssdf9]: retain the mapping for hardened default settings and configuration. |
| APPSEC-SESSION-001 | [V7.4][asvs7] and [V3.3][asvs3]: server-side session termination and browser cookie attributes are separate subjects. | [PW.1][ssdf1]: retain the design mapping for session lifetime, rotation, and revocation boundaries. |
| APPSEC-XSS-001 | [V1.2][asvs1]: context-aware output encoding and XSS prevention. | [PW.5][ssdf5]: PW.5.1 includes output validation and encoding; replaces PW.9, which concerns default configuration. |
| APPSEC-CSRF-001 | [V3.5 and V3.3][asvs3]: request origin/anti-forgery checks and the cookie SameSite policy are separate subjects. | [PW.1][ssdf1]: retain the design mapping for state changes that must not trust ambient cookie authority alone. |
| APPSEC-ENUM-001 | [V6.3][asvs6]: avoid revealing account existence during authentication flows. | [PW.1][ssdf1]: retain the design mapping for authentication responses and timing that preserve account privacy. |
| APPSEC-MSGAUTH-001 | [V11.4 and V11.6][asvs11]: hash-based authentication/MACs and public-key signatures are two supported authentication mechanisms. This does not claim complete replay coverage in those sections. | [PW.5][ssdf5]: implement signature/MAC verification and replay rejection before side effects; replaces PW.9, which concerns default configuration. |
| APPSEC-DATAEXPO-001 | [V14.2][asvs14]: minimize sensitive data exposure. | [PW.1][ssdf1]: retain the design mapping for response contracts and required data disclosure. |
| APPSEC-MASSASSIGN-001 | [V2.2][asvs2]: validate and allowlist input fields before object binding. | [PW.5][ssdf5]: implement field allowlists and trusted assignment of privileged attributes; replaces PW.7, which concerns code analysis. |
| APPSEC-REDIRECT-001 | [V3.7][asvs3]: validate redirects to trusted destinations. | [PW.5][ssdf5]: implement redirect allowlists and reject untrusted URLs; replaces PW.7, which concerns code analysis. |
| APPSEC-RATELIMIT-001 | [V2.4][asvs2]: anti-automation and resource-use limits. | [PW.1][ssdf1]: retain the design mapping for resource budgets, quotas, and abuse-resistant operation. |
| APPSEC-PWSTORE-001 | [V11.4][asvs11], requirement 11.4.2: computationally intensive password hashing with current parameters. | [PW.5][ssdf5]: retain the mapping for implementing password hashing without fast hashes or reversible storage. |
| APPSEC-AUTHZ-002 | [V8.2][asvs8], requirement 8.2.1: function-level access restricted to consumers with explicit permissions. | [PW.1][ssdf1]: design the permission each privileged function requires, with deny by default. |
| APPSEC-LLM-001 | None. ASVS 5.0.0 has no requirement for language-model prompts or model output; see the omissions below. | [PW.1][ssdf1]: design the trust boundary between system instructions and untrusted content. |
| APPSEC-LLM-002 | [V8.3][asvs8], requirements 8.3.1 and 8.3.3: authorization at a trusted service layer, based on the originating subject's permissions rather than an intermediary's. | [PW.1][ssdf1]: design tool scopes and authorization so the model acts with the end user's permissions. |
| APPSEC-LOG-002 | [V16.3 and V16.4][asvs16]: requirement 16.3.2 at L3 logs access to sensitive data, and V16.4 protects logs from modification. | [PW.5][ssdf5]: implement the audit events and their protected sink, like APPSEC-LOG-001. |

## Multiple mappings and intentional omissions

- `APPSEC-AUTHZ-001` keeps only API1:2023. Its subject is object authorization;
  it does not also specify the function-level authorization covered by API5:2023.
  See [OWASP API Top 10 2023, API1][api1] and [API5][api5].
- `APPSEC-FILE-001` retains API4:2023 for upload size/resource limits and API8:2023
  for storage configuration. These are separate subjects. See [API4][api4] and [API8][api8].
- Multiple CWE IDs describe distinct weaknesses addressed by the same rule,
  such as SQL and command injection (CWE-89/CWE-78), missing security events and
  sensitive log content (CWE-778/CWE-532), and weak password hashing and missing
  salts (CWE-916/CWE-759). CWE is a weakness taxonomy, so retaining those IDs does
  not add unrelated framework categories. Definitions are at
  [MITRE CWE](https://cwe.mitre.org/data/definitions.html).
- `APPSEC-FILE-001` has no OWASP Top 10:2025 mapping. No single category cleanly
  describes its combined file-handling subject under the topic convention.
- `APPSEC-PWSTORE-001` has no API Top 10:2023 mapping. Password storage has a
  direct ASVS/CWE mapping; a broad API authentication category would stretch it.
- `APPSEC-LLM-001` has no ASVS mapping. ASVS 5.0.0 has no chapter or requirement on
  language-model prompts, and stretching V1 (encoding and sanitization) would claim a
  coverage ASVS does not give. The rule maps to the [OWASP Top 10 for LLM Applications
  2025][llm]: LLM01 (prompt injection), LLM05 (improper output handling, for the output
  validation the rule requires), and LLM07 (system prompt leakage, for keeping secrets
  out of prompts). CWE-1427 is the CWE entry for neutralizing input used in LLM prompts.
- `APPSEC-LLM-002` maps to LLM06 (excessive agency) and LLM08 (vector and embedding
  weaknesses, for retrieval that ignores the caller's permissions). CWE-250 covers the
  unnecessary privilege and CWE-441 the confused deputy, where the model acts with the
  service's permissions instead of the user's.
- Neither LLM rule maps to the OWASP Top 10:2025 or the API Top 10:2023. The LLM Top 10
  is the specific list for these risks; the general lists would only fit by analogy.
- `APPSEC-AUTHZ-002` takes API5:2023 and CWE-285, the pair API5 itself cites.
  `APPSEC-AUTHZ-001` keeps API1:2023, so object-level and function-level authorization
  are reviewed as separate rules.
- `APPSEC-LOG-002` has no API Top 10:2023 mapping; no category there covers audit trails.
- The other Top 10:2025 mappings remain unchanged. Their categories can be read in
  the [official OWASP Top 10:2025](https://owasp.org/Top10/2025/).

Identifier existence is checked offline by `tests/test_mapping_sources.py`.
That test establishes valid IDs, not semantic correctness or framework conformance.

[asvs1]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x10-V1-Encoding-and-Sanitization.md
[asvs2]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x11-V2-Validation-and-Business-Logic.md
[asvs3]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x12-V3-Web-Frontend-Security.md
[asvs5]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x14-V5-File-Handling.md
[asvs6]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x15-V6-Authentication.md
[asvs7]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x16-V7-Session-Management.md
[asvs8]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md
[asvs11]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x20-V11-Cryptography.md
[asvs13]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x22-V13-Configuration.md
[asvs14]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x23-V14-Data-Protection.md
[asvs15]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
[asvs16]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
[ssdf1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf#page=20
[ssdf4]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf#page=21
[ssdf5]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf#page=22
[ssdf9]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf#page=25
[api1]: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
[api4]: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
[api5]: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
[api8]: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
[llm]: https://genai.owasp.org/llm-top-10/
