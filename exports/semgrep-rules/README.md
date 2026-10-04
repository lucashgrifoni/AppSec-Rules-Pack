# Executable Semgrep rules: a limited Python subset

These two hand-maintained rules can run in an external Semgrep Community Edition
engine. They detect specific source-to-sink flows, not all violations of their
baseline rules. Findings need human review; a clean scan does not demonstrate
compliance or absence of vulnerabilities.

The validator does not load or execute this layer. `appsec-rules export semgrep`
still emits the separate, **non-runnable scaffold** in `exports/semgrep/`. Do not
use that scaffold as a detection configuration. The validator's installation has
no Semgrep, Flask, or Requests dependency.

## Run the rules

From a repository clone, use an isolated environment with Python 3.12 and the
version exercised in CI:

```bash
python -m venv ../appsec-semgrep-venv
../appsec-semgrep-venv/bin/python -m pip install "semgrep==1.179.0"
../appsec-semgrep-venv/bin/semgrep scan \
  --config exports/semgrep-rules/rules \
  --metrics=off --disable-version-check --error /path/to/application
```

On Windows use `..\appsec-semgrep-venv\Scripts\python.exe` and
`..\appsec-semgrep-venv\Scripts\semgrep.exe`. Keep this optional environment
outside the application directory you scan. `--error` makes findings fail the
command; adapt that policy only after reviewing the noise in your application.
Rules and tests are repository artifacts, not bundled with the PyPI validator.
No account, Semgrep Registry configuration, or Pro engine is needed.

## What has executable detection

Both rules recognize Python `flask.request.args` and `flask.request.form`
subscript access and `.get(...)` calls, including the import aliases covered by
the fixtures. Sources use `exact: true`. Taint is followed within a function;
only the SQL/URL argument is a sink, not other arguments to the call.

| Baseline ID | Semgrep rule | Covered sink |
| --- | --- | --- |
| `APPSEC-INJECT-001` | `appsec-python-flask-sqlite-tainted-query` | SQL argument to `execute`, `executemany`, or `executescript` on a visible binding from `sqlite3.connect(...)` (or its `with ... as` binding), or a cursor assigned from that connection |
| `APPSEC-SSRF-001` | `appsec-python-flask-requests-tainted-url` | URL argument to module-level `requests.get`, `post`, `put`, `patch`, `delete`, `head`, `options`, or `request`, including positional and `url=` forms |

The SQL fixtures include f-strings, percent formatting, `.format()`,
concatenation, direct query input, and local import aliases. Binding parameters
to a static SQL statement is a negative case. Adding a parameter tuple does not
make an already interpolated statement safe.

The SSRF fixtures include assigned URLs and import aliases. A fixed URL with
user input confined to `params=` or `json=` is a negative case. Disabling
redirects alone is not a sanitizer: the initial destination may still be
attacker-controlled.

The remaining baseline IDs have **no executable detection in this layer**:

- `APPSEC-AUTHZ-001`, `APPSEC-INPUT-001`, `APPSEC-AUTHN-001`
- `APPSEC-SECRETS-001`, `APPSEC-FILE-001`, `APPSEC-LOG-001`
- `APPSEC-DEP-001`, `APPSEC-CONFIG-001`, `APPSEC-SESSION-001`
- `APPSEC-XSS-001`, `APPSEC-CSRF-001`, `APPSEC-ENUM-001`
- `APPSEC-MSGAUTH-001`, `APPSEC-DATAEXPO-001`, `APPSEC-MASSASSIGN-001`
- `APPSEC-REDIRECT-001`, `APPSEC-RATELIMIT-001`

## Limits and review expectations

- Python with Flask sources only. Other frameworks/languages, JSON bodies,
  headers, cookies, route parameters, and sources returned by helper functions
  are not modeled. A missing finding for these inputs is not a safety judgment.
- Community Edition is tested here, with no promised cross-function or
  cross-file analysis. Wrappers, dynamically selected callables, object aliases,
  injected database connections, globals, and `requests.Session` may be missed.
- SQL sinks use locally visible connection/cursor bindings, not a complete type
  analysis. Reassigning a receiver can confuse the match. Other databases,
  connection factories, chained `connect().execute()` calls, shell commands,
  NoSQL, and other interpreter boundaries are not covered.
- The rules define no sanitizers. Correct allowlists, numeric conversion,
  validation helpers, and branch guards can still produce findings. Semgrep
  conservatively propagates taint through opaque function calls. Review those
  cases rather than treating a sanitizer-like function name as proof of safety.
- SSRF detection does not distinguish the URL authority from a tainted path or
  query suffix. A fixed-host URL constructed with user input can be a false
  positive; a fixture records this behavior. The rule does not perform DNS,
  redirect, network-policy, or runtime destination analysis. A fixed initial
  destination can still have unsafe redirects without being reported.
- Tests establish the behavior of the examples below, not measured precision
  or recall on a representative external application corpus. Expanding the
  supported APIs needs corresponding positive and negative fixtures.

## Test and maintain

```bash
SEMGREP_ENABLE_VERSION_CHECK=0 ../appsec-semgrep-venv/bin/semgrep \
  --test --strict --metrics=off \
  --config exports/semgrep-rules/rules exports/semgrep-rules/tests
```

The `Executable Semgrep rules` workflow runs this command with Semgrep 1.179.0.
Each YAML rule has a same-basename Python fixture under `tests/`. The fixture
comments use real `ruleid:` and `ok:` assertions. Some explicitly labeled `ok:`
cases document an unsupported source or sink; they are known gaps, not secure
coding examples. There are no skipped `todoruleid:` or `todook:` assertions.
Fixtures are parsed as source; do not import or execute them as applications.

The root `.semgrepignore` excludes only these two intentionally vulnerable
fixture files from general repository scans. The explicit `--test` invocation
still scans both files and checks their annotations. Existing repository SAST
jobs are unchanged. `tests/test_semgrep_rules.py` guards baseline links, unique
rule IDs, fixture inventory, and the exact ignore list without importing Semgrep.
The existing drift tests continue to guard the non-runnable generated scaffold.

Update the engine pin, fixtures, and documentation together. Do not add these
hand-maintained rules to the scaffold generator or validator runtime. See
[ADR-0005](../../docs/adr/0005-executable-semgrep-subset.md).

## References

- [Semgrep rule tests](https://semgrep.dev/docs/writing-rules/testing-rules)
- [Semgrep taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview)
- [Focused sink arguments and taint limitations](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced)
