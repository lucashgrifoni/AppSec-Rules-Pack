# Examples

| Example | What it shows |
| --- | --- |
| [`minimal-pack.yaml`](minimal-pack.yaml) | The smallest pack that passes the strict gate; `appsec-rules init` writes the same file |
| [`review/`](review/README.md) | A worked review: one service reviewed against the baseline, with an open rule and an exception |
| [GitHub Actions template](#github-actions-template) | Pinned CLI, verified baseline, your own packs, review records, and a gate |
| [`validation_gate.py`](#portable-json-gate-any-ci-or-local-shell) | A stdlib-only gate for any other CI system |
| [PowerShell](#powershell) | The same steps on Windows |

```bash
appsec-rules validate examples/minimal-pack.yaml --require-examples --fail-on-warnings
```

## GitHub Actions template

This job is meant for a downstream repository laid out like this:

```text
rules/            your own packs, with your own id prefix (ACME-...)
rules/vendor/     the baseline, downloaded and verified by the job (not committed)
reviews/          one review record per service, made against the baseline
```

It installs a pinned CLI, downloads the baseline from the same release, verifies the
baseline's build provenance, validates every pack, checks every review record, and then
applies a gate. Pin a release you have reviewed, and keep the CLI and the baseline on the
same version.

```yaml
name: AppSec rules

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

env:
  APPSEC_RULES_VERSION: "0.5.0"

jobs:
  appsec-rules:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out repository
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"

      - name: Install the pinned CLI
        run: python -m pip install "appsec-rules-pack==${APPSEC_RULES_VERSION}"

      - name: Download and verify the pinned baseline
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          tag="v${APPSEC_RULES_VERSION}"
          gh release download "$tag" --repo lucashgrifoni/AppSec-Rules-Pack \
            --pattern appsec-baseline.yaml --dir rules/vendor
          gh attestation verify rules/vendor/appsec-baseline.yaml \
            --repo lucashgrifoni/AppSec-Rules-Pack \
            --signer-workflow lucashgrifoni/AppSec-Rules-Pack/.github/workflows/publish-pypi.yml \
            --source-ref "refs/tags/$tag"

      - name: Validate the baseline and your own packs
        run: appsec-rules validate rules --require-examples --fail-on-warnings --format json

      - name: Check review records
        run: |
          shopt -s nullglob
          mkdir -p reports
          for record in reviews/*.yaml; do
            name="$(basename "$record" .yaml)"
            appsec-rules review rules/vendor/appsec-baseline.yaml "$record" \
              --fail-on-warnings --format json > "reports/$name.json"
          done

      - name: Gate on open rules
        run: |
          python - <<'PY'
          import json, pathlib, sys

          failed = False
          for path in sorted(pathlib.Path("reports").glob("*.json")):
              report = json.loads(path.read_text())
              summary = report["summary"]
              blocking = summary["open_by_enforcement"].get("blocking", 0)
              critical = summary["open_by_severity"].get("critical", 0)
              print(f"{path.stem}: open blocking={blocking} critical={critical}")
              # Your policy goes here. This one stops on any open blocking or critical rule.
              if blocking or critical:
                  failed = True
          sys.exit(1 if failed else 0)
          PY
```

Notes:

- `validate` and `review` already fail the job when a pack or a record is invalid. The
  last step is the policy: what may stay open. Change it to match yours
  ([ADR-0006](../docs/adr/0006-review-records.md)).
- A review record fails once one of its exceptions expires. That is the point: renew the
  exception or fix the rule.
- `gh attestation verify` proves the baseline came from this project's release workflow
  at that tag. To verify without calling the GitHub API, also download
  `appsec-rules-pack-v<version>.intoto.jsonl` and add `--bundle` to the same command,
  keeping `--signer-workflow` and `--source-ref`.

For local development inside this repository, install the project in editable mode
and validate the bundled baseline rules:

```bash
python -m pip install -e ".[dev]"
python -m appsec_rules_pack validate rules --require-examples --fail-on-warnings --format json
```

All three validation commands (here and in the PowerShell section) apply the strict flags: enabled rules need compliant and
violating examples, and warnings produce a failing exit code.
`tests/test_documented_gates.py` runs them against valid, missing-example, and warning
cases to keep these examples aligned with that contract.

## Portable JSON gate (any CI or local shell)

[`validation_gate.py`](validation_gate.py) is a stdlib-only consumer of
`--format json` for systems other than GitHub Actions. It passes only when the CLI exits
`0` **and** the JSON reports `summary.ok: true`. Missing, malformed, or contradictory
output, or a CLI that cannot be started, fails the gate. Successfully starting the
process is not treated as a passing pack.

```bash
python -m pip install "appsec-rules-pack==0.5.0"   # pin a reviewed release
python examples/validation_gate.py rules --require-examples --fail-on-warnings
```

- `--require-examples` warns when an enabled rule lacks compliant/violating examples.
- `--fail-on-warnings` makes the CLI exit non-zero when any warning is present.

Real results against the repository fixtures:

| Fixture | CLI exit | `summary.ok` | Gate |
|---|---|---|---|
| `tests/fixtures/pass/minimal-valid.yaml` | `0` | `true` | PASS (`0`) |
| `tests/fixtures/fail/invalid-enum.yaml` | `1` | `false` | FAIL (`1`) |

## PowerShell

The same steps on Windows, verifying offline against the release's provenance bundle:

```powershell
$version = "0.5.0"
$tag = "v$version"
$repo = "lucashgrifoni/AppSec-Rules-Pack"
python -m pip install "appsec-rules-pack==$version"
gh release download $tag --repo $repo --dir rules/vendor `
  --pattern appsec-baseline.yaml --pattern "appsec-rules-pack-$tag.intoto.jsonl"
gh attestation verify rules/vendor/appsec-baseline.yaml --repo $repo `
  --bundle "rules/vendor/appsec-rules-pack-$tag.intoto.jsonl" `
  --signer-workflow "$repo/.github/workflows/publish-pypi.yml" `
  --source-ref "refs/tags/$tag"
if ($LASTEXITCODE -ne 0) { throw "baseline provenance could not be verified" }
appsec-rules validate rules --require-examples --fail-on-warnings --format json
if ($LASTEXITCODE -ne 0) { throw "a rules pack is invalid" }
Get-ChildItem reviews -Filter *.yaml | ForEach-Object {
  appsec-rules review rules/vendor/appsec-baseline.yaml $_.FullName --fail-on-warnings
  if ($LASTEXITCODE -ne 0) { throw "review record $($_.Name) is invalid" }
}
```
