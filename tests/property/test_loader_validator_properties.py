"""Property-based coverage of the public file-validation path (issue #32).

The validator reads untrusted YAML, so every input, however malformed, must come back
as a structured result: documented issue codes, a verdict that agrees with the issues,
and no exception escaping. The strategies below aim at the shapes that broke or nearly
broke the loader before: aliases, duplicate keys, deep nesting, non-UTF-8 bytes, and
packs that are almost valid.

Run with a larger budget: HYPOTHESIS_PROFILE=long python -m pytest tests/property
"""

from __future__ import annotations

import copy
import json
import re
import string
import tempfile
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from appsec_rules_pack.cli import app
from appsec_rules_pack.validator import KEY_MATERIAL_PATTERNS, validate_rules_file

ROOT = Path(__file__).resolve().parents[2]
STARTER = yaml.safe_load(
    (ROOT / "src/appsec_rules_pack/templates/minimal-pack.yaml").read_text(encoding="utf-8")
)
REPORT_SCHEMA = json.loads(
    (ROOT / "src/appsec_rules_pack/schemas/validation-report.schema.json").read_text(
        encoding="utf-8"
    )
)
DOCUMENTED_CODES = frozenset(
    re.findall(r"^\| `([a-z0-9-]+)` \|", (ROOT / "VERSIONING.md").read_text("utf-8"), re.M)
)
LOAD_CODES = frozenset(
    ("file-unreadable", "file-not-utf8", "file-too-large", "yaml-invalid", "yaml-too-deep")
)
# One scratch file, rewritten per example: function-scoped fixtures do not mix with
# Hypothesis, and thousands of temporary directories would only slow the search down.
_SCRATCH = Path(tempfile.mkdtemp(prefix="appsec-prop-")) / "pack.yaml"
runner = CliRunner()


def _validate_bytes(data: bytes):
    _SCRATCH.write_bytes(data)
    return validate_rules_file(_SCRATCH, require_examples=True)


def _check_invariants(result) -> None:
    for issue in result.issues:
        assert issue.level in ("error", "warning")
        assert issue.code in DOCUMENTED_CODES, issue.code
        assert isinstance(issue.message, str) and issue.message
        assert all(isinstance(part, str | int) for part in issue.path)
        assert issue.rule_id is None or isinstance(issue.rule_id, str)
    assert result.ok == (result.error_count == 0)
    assert result.error_count + result.warning_count == len(result.issues)
    if any(issue.code in LOAD_CODES for issue in result.issues):
        # A file that does not load yields exactly one issue and no rules.
        assert len(result.issues) == 1
        assert result.rule_count == 0


# --- strategies ---------------------------------------------------------------------

scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=40),
    st.sampled_from(["", "enabled", "APPSEC-X-001", "V1.1", "CWE-79", "PW.7", "x-ext"]),
)
values = st.recursive(
    scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(st.one_of(st.text(max_size=12), st.integers()), inner, max_size=4),
    ),
    max_leaves=12,
)


def _paths(node: Any, prefix: tuple = ()) -> list[tuple]:
    found = [prefix]
    if isinstance(node, dict):
        for key, child in node.items():
            found.extend(_paths(child, (*prefix, key)))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            found.extend(_paths(child, (*prefix, index)))
    return found


@st.composite
def mutated_packs(draw) -> Any:
    """The starter pack with one to three parts replaced, removed, or added."""

    pack = copy.deepcopy(STARTER)
    for _ in range(draw(st.integers(min_value=1, max_value=3))):
        path = draw(st.sampled_from(_paths(pack)))
        if not path:
            return draw(values)  # replace the whole document
        parent = pack
        for part in path[:-1]:
            parent = parent[part]
        action = draw(st.sampled_from(["replace", "delete", "add"]))
        if action == "replace":
            parent[path[-1]] = draw(values)
        elif action == "delete":
            del parent[path[-1]]
        elif isinstance(parent, dict):
            parent[draw(st.text(min_size=1, max_size=12))] = draw(values)
        else:
            parent.append(draw(values))
    return pack


YAML_TOKENS = [
    "pack:",
    "rules:",
    "- ",
    ": ",
    "id: ",
    "\n",
    "  ",
    "    ",
    "{",
    "}",
    "[",
    "]",
    ",",
    "&a ",
    "*a",
    "<<: *a",
    "&b [*a, *a]",
    "!!python/object/apply:os.system ['x']",
    "!!binary aGVsbG8=",
    "!!set {a, b}",
    "!!omap",
    "? ",
    "---\n",
    "...\n",
    "%YAML 1.1\n",
    "'",
    '"',
    "# c",
    "|\n",
    ">\n",
    "~",
    "null",
    "1e999",
    "0x1F",
    "2026-02-30",
    "\t",
]
token_soup = st.lists(
    st.one_of(st.sampled_from(YAML_TOKENS), st.text(alphabet=string.printable, max_size=6)),
    max_size=60,
).map("".join)

keys = st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True)


@st.composite
def alias_documents(draw) -> str:
    """Well-formed YAML that uses an anchor and at least one alias."""

    anchor = draw(st.from_regex(r"[a-z]{1,6}", fullmatch=True))
    first, second = draw(st.lists(keys, min_size=2, max_size=2, unique=True))
    value = draw(st.sampled_from(["1", "text", "[1, 2]", "{x: 1}"]))
    fan_out = draw(st.integers(min_value=1, max_value=9))
    aliases = ", ".join([f"*{anchor}"] * fan_out)
    return f"{first}: &{anchor} {value}\n{second}: [{aliases}]\n"


@st.composite
def duplicate_key_documents(draw) -> str:
    key = draw(keys)
    others = draw(st.lists(keys.filter(lambda k: k != key), max_size=3, unique=True))
    lines = [f"{key}: 1", *(f"{other}: 2" for other in others), f"{key}: 3"]
    if draw(st.booleans()):  # nest the duplicate one level down
        lines = ["pack:"] + [f"  {line}" for line in lines]
    return "\n".join(lines) + "\n"


# --- properties ---------------------------------------------------------------------


@given(mutated_packs())
def test_almost_valid_packs_get_structured_results(pack: Any) -> None:
    text = yaml.safe_dump(pack, allow_unicode=True, sort_keys=False)

    _check_invariants(_validate_bytes(text.encode("utf-8")))


@given(token_soup)
@example("pack: [unterminated\n")
@example("a: &a [*a]\n")
@example("!!python/object/apply:os.system ['true']\n")
@example("2026-02-30")
def test_yaml_token_soup_never_escapes_as_an_exception(text: str) -> None:
    _check_invariants(_validate_bytes(text.encode("utf-8")))


@given(st.binary(max_size=512))
@example(b"\xff\xfe\x00p\x00a")
@example(b"pack:\n  id: \xe9t\xe9\n")
def test_arbitrary_bytes_never_escape_as_an_exception(data: bytes) -> None:
    result = _validate_bytes(data)

    _check_invariants(result)
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        assert [issue.code for issue in result.issues] == ["file-not-utf8"]


@given(alias_documents())
@example("a: &x [1]\nb: [*x, *x, *x, *x, *x, *x, *x, *x, *x]\n")
def test_every_alias_is_refused(text: str) -> None:
    result = _validate_bytes(text.encode("utf-8"))

    [issue] = result.issues
    assert issue.code == "yaml-invalid"
    assert "aliases are not supported" in issue.message


@given(duplicate_key_documents())
@example("pack: 1\npack: 2\n")
def test_every_duplicate_key_is_refused(text: str) -> None:
    result = _validate_bytes(text.encode("utf-8"))

    [issue] = result.issues
    assert issue.code == "yaml-invalid"
    assert "duplicate key" in issue.message


# The parser gives up between depth 300 and 400, and each attempt near the interpreter's
# recursion limit is slow, so this one-dimensional search gets a small fixed budget that
# still spans the limit.
@settings(max_examples=50)
@given(st.integers(min_value=1, max_value=1000), st.sampled_from(["[]", "{}", "- "]))
@example(3000, "[]")
@example(399, "{}")
def test_deep_nesting_is_an_issue_not_a_crash(depth: int, shape: str) -> None:
    if shape == "- ":
        text = "".join("  " * level + "-\n" for level in range(min(depth, 400)))
    else:
        text = shape[0] * depth + shape[1] * depth
    _check_invariants(_validate_bytes(text.encode("utf-8")))


@given(st.sampled_from(KEY_MATERIAL_PATTERNS), st.sampled_from(["key", "value"]))
def test_key_material_is_never_echoed_in_messages(pattern: re.Pattern, where: str) -> None:
    samples = {
        "PRIVATE KEY": "-----BEGIN RSA PRIVATE KEY-----",
        "AKIA": "AKIA" + "Q" * 16,
        "ghp": "ghp_" + "a" * 36,
        "github_pat": "github_pat_" + "b" * 30,
        "xox": "xoxb-" + "1" * 12,
        "AIza": "AIza" + "c" * 35,
        "sk_live": "sk_live_" + "d" * 20,
    }
    secret = next(value for marker, value in samples.items() if marker in pattern.pattern)
    assert pattern.search(secret)
    pack = copy.deepcopy(STARTER)
    if where == "key":
        pack["rules"][0][secret] = "x"
    else:
        pack["rules"][0]["description"] = f"Rotate {secret} soon, it is in the repository."

    result = _validate_bytes(yaml.safe_dump(pack).encode("utf-8"))

    assert not result.ok
    assert all(secret not in issue.message for issue in result.issues)


@given(mutated_packs())
def test_cli_json_report_always_matches_its_schema(pack: Any) -> None:
    _SCRATCH.write_text(yaml.safe_dump(pack, allow_unicode=True), encoding="utf-8")

    result = runner.invoke(app, ["validate", str(_SCRATCH), "--format", "json"])

    report = json.loads(result.stdout)
    jsonschema.validate(report, REPORT_SCHEMA)
    assert result.exit_code == (0 if report["summary"]["ok"] else 1)
