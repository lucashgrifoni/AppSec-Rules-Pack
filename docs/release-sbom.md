# Release SBOM construction

The `build` job in `publish-pypi.yml` inventories an environment containing the
built wheel and its resolved runtime dependencies. It uses `cyclonedx-bom==7.3.0`
and the other tools from the hash-locked release requirements. This job has no
publishing credential. It uploads the SBOM only after checking its root identity
and excluding installer packages.

Create the inventory environment with `venv --without-pip`, then use the build
environment's `pip --python` to install the wheel there. This keeps `pip`,
`setuptools`, and `wheel` out of the inventory. See the
[pip interpreter option](https://pip.pypa.io/en/stable/topics/python-option/), available
since pip 22.3.

## Resolving the root version

`cyclonedx-py environment --pyproject pyproject.toml` supplies a root component,
but version 7.3.0 does not resolve this project's dynamic version. Reproducing
that command yielded a root with a name and no version or purl. A static version
fixes the version field but still leaves the root purl absent.

`.github/release/sbom_project.py` runs under the inventory interpreter. It reads
the installed wheel's `Name` and `Version` metadata and makes a temporary copy
of the project's TOML with `project.version` set to that version. Other metadata
is preserved. This copy is only an input to the supported `--pyproject` option;
it is never used to build the distribution. `--mc-type library` identifies the
package as a library.

The supported options are documented by
[CycloneDX Python 7.3.0](https://github.com/CycloneDX/cyclonedx-python/tree/v7.3.0)
and its `cyclonedx-py environment --help` output. The temporary manifest needs
no additional TOML-writing dependency.

`.github/release/sbom_purl.py` then loads the generated SBOM using the public
`Bom.from_json` API, sets the root's `PackageURL`, serializes as CycloneDX 1.6,
and validates it with `JsonStrictValidator` before writing. These APIs are shown in
[CycloneDX Python Library 11.12.0 examples](https://github.com/CycloneDX/cyclonedx-python-lib/tree/v11.12.0/examples).
That library and `packageurl-python==0.17.6` already come from the release lock.
The purl identifies the package's intended PyPI coordinates; it is not evidence
that this version has been published.

## Upload gate and scope

`.github/release/check_sbom.py` checks that `metadata.component` has the name
`appsec-rules-pack`, the version declared by the package source, and the purl
`pkg:pypi/appsec-rules-pack@<version>`. It rejects installer components, including
nested components. `tests/test_release_sbom.py` exercises accepted and rejected
SBOMs, the command's failure exit code, and preservation of project metadata.

CycloneDX validates the generated document before writing it. The additional
gate checks the repository's release requirements; it does not establish that
the resolved dependencies have no vulnerabilities. Component versions can vary
with the platform and resolution date because runtime dependencies use ranges.
The inventory excludes build tools and does not inventory the baseline YAML or
the separately installed Semgrep engine.

A manual run on `feat/v0.6.0` executes `verify` and `build`; the existing condition
skips `release` on that branch. No tag or publication is needed to test the SBOM.
