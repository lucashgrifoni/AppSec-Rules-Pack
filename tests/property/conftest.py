"""Hypothesis profiles for the property harness (issue #32).

Pick one with HYPOTHESIS_PROFILE:

- ``dev`` (default): about a second per property, for the normal test run;
- ``ci``: the bounded budget of the `property` CI job;
- ``long``: a longer local search before a release.

Each profile is derandomized only in CI, so a CI failure reproduces exactly; locally
the search varies run to run and Hypothesis replays any failure it finds first.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

_COMMON = {
    "deadline": None,
    "suppress_health_check": [HealthCheck.too_slow, HealthCheck.data_too_large],
}
settings.register_profile("dev", max_examples=60, **_COMMON)
settings.register_profile("ci", max_examples=400, derandomize=True, database=None, **_COMMON)
settings.register_profile("long", max_examples=5000, **_COMMON)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
