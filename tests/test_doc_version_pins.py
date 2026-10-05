"""Every version the docs tell users to pin must be the current package version.

The downstream CI template in examples/README.md stayed on 0.5.0 after the 0.6.0 release
because nothing checked it; a user copying it got the previous release.
"""

import re
from pathlib import Path

import pytest

from appsec_rules_pack import __version__

ROOT = Path(__file__).resolve().parents[1]
PIN_PATTERNS = (
    r"appsec-rules-pack==(\d+\.\d+\.\d+)",
    r'APPSEC_RULES_VERSION: "(\d+\.\d+\.\d+)"',
    r'\$version = "(\d+\.\d+\.\d+)"',
    r"releases/download/v(\d+\.\d+\.\d+)/",
    r"refs/tags/v(\d+\.\d+\.\d+)",
    r"appsec-rules-pack-v(\d+\.\d+\.\d+)\.intoto\.jsonl",
)


@pytest.mark.parametrize("doc", ["README.md", "examples/README.md"])
def test_documented_pins_match_the_package_version(doc: str) -> None:
    text = (ROOT / doc).read_text(encoding="utf-8")
    pins = [pin for pattern in PIN_PATTERNS for pin in re.findall(pattern, text)]

    assert pins, f"{doc} has no version pins; update the patterns"
    assert set(pins) == {__version__}, f"{doc} pins {sorted(set(pins))}"


def test_readme_links_are_absolute() -> None:
    """PyPI renders the README off GitHub, where relative links break."""

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    relative = re.findall(r"\]\((?!https?://|#|mailto:)([^)]+)\)", text)

    assert relative == []
