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
reviews/          one review record per service, against the baseline or one of your packs
```

It installs a pinned CLI, downloads the baseline from the same release, verifies the
baseline's build provenance, validates every pack, checks every review record against the
pack the record names in `review.pack`, and then applies a gate. Pin a release you have
reviewed, and keep the CLI and the baseline on the same version.

```yaml
name: AppSec rules

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

env:
  APPSEC_RULES_VERSION: "0.9.0"

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
          mkdir -p reports
          python - <<'PY'
          import pathlib, subprocess, sys
          import yaml

          # Each record names the pack it was made against in review.pack; find that
          # pack, the baseline or one of yours, under rules/.
          packs = {}
          for path in sorted(pathlib.Path("rules").rglob("*.y*ml")):
              data = yaml.safe_load(path.read_text(encoding="utf-8"))
              if isinstance(data, dict) and isinstance(data.get("pack"), dict):
                  packs[data["pack"].get("id")] = path

          failed = False
          for record in sorted(pathlib.Path("reviews").glob("*.yaml")):
              pack_id = yaml.safe_load(record.read_text(encoding="utf-8"))["review"]["pack"]
              if pack_id not in packs:
                  print(f"{record}: no pack with id {pack_id!r} under rules/")
                  failed = True
                  continue
              command = ["appsec-rules", "review", str(packs[pack_id]), str(record),
                         "--fail-on-warnings", "--format", "json"]
              with open(f"reports/{record.stem}.json", "w", encoding="utf-8") as report:
                  failed |= subprocess.run(command, stdout=report).returncode != 0
          sys.exit(1 if failed else 0)
          PY

      - name: Gate on open rules
        env:
          # Your policy: open rules at these severities or enforcement levels stop the job.
          GATE_SEVERITIES: critical,high
          GATE_ENFORCEMENT: blocking
          # "rule" counts open rules at the pack's severity. "effective" uses the
          # reviewer's assessed_severity where a record sets one (ADR-0009).
          GATE_SEVERITY_VIEW: rule
        run: |
          python - <<'PY'
          import json, os, pathlib, sys

          def levels(name, default):
              return {item.strip() for item in os.environ.get(name, default).split(",") if item.strip()}

          severities = levels("GATE_SEVERITIES", "critical,high")
          enforcement = levels("GATE_ENFORCEMENT", "blocking")
          effective = os.environ.get("GATE_SEVERITY_VIEW", "rule") == "effective"

          failed = False
          for path in sorted(pathlib.Path("reports").glob("*.json")):
              summary = json.loads(path.read_text())["summary"]
              by_severity = summary["open_by_severity"]
              if effective:
                  by_severity = summary.get("open_by_effective_severity", by_severity)
              stop = {level: count for level, count in by_severity.items() if level in severities}
              stop.update(
                  (level, count)
                  for level, count in summary["open_by_enforcement"].items()
                  if level in enforcement
              )
              print(f"{path.stem}: open rules that stop the job: {stop or 'none'}")
              failed |= any(stop.values())
          sys.exit(1 if failed else 0)
          PY
```

To make this gate mandatory, mark the `appsec-rules` job as a required status check in
your branch protection or ruleset. The three `GATE_` values set the policy; none of them
changes what `validate` or `review` report.

Notes:

- `validate` and `review` already fail the job when a pack or a record is invalid. The
  last step is the policy: what may stay open. Change it to match yours
  ([ADR-0006](../docs/adr/0006-review-records.md)). A rule is open when it is `not-met` or
  `unreviewed`; `excepted` rules are not open, and an invalid or expired exception makes the
  record invalid, so the `review` step fails first.
- The gate counts open rules by the rule's severity. A record can set `assessed_severity`
  on a result; to gate on the reviewer's assessment instead, read
  `summary["open_by_effective_severity"]`, and review severity changes in the pull request
  that makes them ([ADR-0009](../docs/adr/0009-assessed-severity-and-subject-type.md)).
- `validate rules` reads every `.yaml` and `.yml` file under `rules/`, subdirectories
  included, so keep only packs there.
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
python -m pip install "appsec-rules-pack==0.9.0"   # pin a reviewed release
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
$version = "0.9.0"
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
