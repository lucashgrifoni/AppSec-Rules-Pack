"""Coverage-guided fuzzing of the rules-pack loader and validator with Atheris.

The property harness in tests/property generates structured inputs; this target lets
libFuzzer mutate raw bytes guided by code coverage, which reaches parser states that
structured generators do not. Any exception that escapes `validate_rules_file`, or an
issue that breaks the invariants below, is a crash.

Linux or macOS only (Atheris has no Windows build). Bounded run, as in CI:

    python -m pip install --require-hashes -r .github/fuzz/requirements.txt
    mkdir -p /tmp/corpus && cp rules/*.yaml tests/fixtures/*/*.yaml /tmp/corpus/
    python fuzz/fuzz_validate.py -max_total_time=120 /tmp/corpus
"""

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from appsec_rules_pack.validator import validate_rules_file

_SCRATCH = Path(tempfile.mkdtemp(prefix="appsec-fuzz-")) / "pack.yaml"


def test_one_input(data: bytes) -> None:
    _SCRATCH.write_bytes(data)
    result = validate_rules_file(_SCRATCH, require_examples=True)
    for issue in result.issues:
        assert issue.level in ("error", "warning"), issue
        assert issue.code and issue.message, issue
    assert result.ok == (result.error_count == 0)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
