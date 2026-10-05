"""The rules pack printed in the README must actually validate.

A new user's only path to authoring a pack is the example in the README: the schema
describes the contract but not in a copyable form, and the baseline pack is 19 rules
long. An example that drifts out of sync with the schema sends every new user into the
same wall of validation errors, and nothing else in the suite would notice.

The example is delimited by an HTML marker so this test binds to the intended block
rather than to whichever fenced YAML happens to come first.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from appsec_rules_pack.validator import validate_rules_payload

README = Path("README.md")
MARKER = "<!-- readme-example:minimal-pack"

# The marker line, then the next ```yaml ... ``` fence.
EXAMPLE_PATTERN = re.compile(
    re.escape(MARKER) + r"[^\n]*\n\s*```yaml\n(?P<body>.*?)\n```",
    re.DOTALL,
)


@pytest.fixture(scope="module")
def example_pack() -> dict:
    text = README.read_text(encoding="utf-8")
    match = EXAMPLE_PATTERN.search(text)
    assert match is not None, (
        f"README lost the '{MARKER}' marker or its yaml block. The example is a "
        "documented contract; move the marker with it rather than deleting it."
    )
    payload = yaml.safe_load(match.group("body"))
    assert isinstance(payload, dict)
    return payload


def test_readme_example_passes_the_strict_gate(example_pack: dict) -> None:
    """CI runs `--require-examples --fail-on-warnings`, so the documented pack must pass it."""

    result = validate_rules_payload(example_pack, require_examples=True)

    assert result.issues == (), [f"{i.level} {i.path}: {i.message}" for i in result.issues]
    assert result.rule_count == 1


def test_readme_example_is_the_init_template_and_the_examples_file() -> None:
    """One starter pack, three places: `appsec-rules init`, examples/, and the README."""

    text = README.read_text(encoding="utf-8")
    match = EXAMPLE_PATTERN.search(text)
    assert match is not None
    template = Path("src/appsec_rules_pack/templates/minimal-pack.yaml").read_text(encoding="utf-8")

    assert match.group("body") + "\n" == template
    assert Path("examples/minimal-pack.yaml").read_text(encoding="utf-8") == template
