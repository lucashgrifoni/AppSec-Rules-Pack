# ADR-0007: Lock the release toolchain with hashes; keep ranges everywhere else

- **Status:** Accepted
- **Date:** 2026-10-05
- **Related:** [ADR-0003](0003-release-provenance.md), issue #26

## Context

CI installed every tool from version ranges, including the release job, which also held
the PyPI publishing credential (an OIDC token). OpenSSF Scorecard's Pinned-Dependencies
check flagged the unpinned `pip install` steps. Two different risks hide behind that one
signal:

- a tool that runs next to a publishing credential, or that produces the published files,
  could be swapped for a malicious version between two releases;
- the test and lint jobs could break when an upstream release changes behaviour.

The second is information the project wants: the `min-deps` job tests the declared floors,
and the other jobs test the latest versions a user would get.

## Decision

- The release `build` job installs its tools (build, setuptools, wheel, cyclonedx-bom, and
  their dependencies) from `.github/release/requirements.txt`, locked with hashes from
  `.github/release/requirements.in` by
  `uv pip compile --generate-hashes --universal --python-version 3.12`, installed with
  `--require-hashes --only-binary :all:`, and builds with `--no-isolation` so `build`
  cannot fetch a different setuptools.
- The job that holds the OIDC token installs nothing. It receives the built files as an
  artifact, attests them, and publishes them.
- Test, lint, and security jobs keep floating ranges, and `min-deps` keeps testing the
  floors. The package declares ranges, not pins, so users can resolve it alongside other
  tools.
- The lock is updated by editing `requirements.in` and re-running the command above,
  in a pull request of its own.

## Alternatives considered

- **Lock everything, including CI test jobs.** Rejected: CI would stop seeing the
  versions users install, and every upstream release would need a lock bump to be tested.
- **Keep ranges in the release job too.** Rejected: it is the one job where a swapped
  tool changes what ships.
- **Pin versions without hashes.** Rejected: a version pin does not stop a replaced
  artifact; a hash does.

## Consequences

- **Positive:** what ships is built only by reviewed, hash-checked tools, away from the
  publishing credential.
- **Negative:** the lock goes stale and needs deliberate updates. Scorecard will keep
  flagging the floating installs in the test jobs; that is an accepted position.
- **Validation:** the lock was installed with `--require-hashes --only-binary :all:` in a
  clean environment, and the build and SBOM steps ran from it.
