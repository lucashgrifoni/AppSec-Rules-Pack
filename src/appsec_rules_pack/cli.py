"""Typer command-line interface for AppSec rules pack validation."""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from appsec_rules_pack import __version__
from appsec_rules_pack.exporter import build_index_from_files
from appsec_rules_pack.validator import (
    ValidationIssue,
    ValidationResult,
    validate_rules_file,
    validate_rules_files,
)

app = typer.Typer(help="Validate AppSec rules pack files.")
export_app = typer.Typer(help="Derive machine-readable artifacts from rules packs.")
app.add_typer(export_app, name="export")


class OutputFormat(StrEnum):
    """Supported validation output formats."""

    text = "text"
    json = "json"


RulesPathArg = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=True),
]
FailOnWarningsOpt = Annotated[
    bool,
    typer.Option(
        "--fail-on-warnings",
        help="Return a non-zero exit code when warnings are present.",
    ),
]
RequireExamplesOpt = Annotated[
    bool,
    typer.Option(
        "--require-examples",
        help="Warn when an enabled rule has no compliant and violating examples.",
    ),
]
FormatOpt = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        "-f",
        help="Output format: text (default) or json.",
    ),
]
RULE_FILE_SUFFIXES = frozenset((".yaml", ".yml"))


class IndexFormat(StrEnum):
    """Supported export index formats."""

    json = "json"


IndexFormatOpt = Annotated[
    IndexFormat,
    typer.Option("--format", "-f", help="Index output format (json)."),
]
IndexOutputOpt = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Write the index to this file instead of stdout."),
]


def _issue_path_str(issue: ValidationIssue) -> str:
    return ".".join(str(part) for part in issue.path) if issue.path else "<root>"


def _format_issue(issue: ValidationIssue) -> str:
    return f"{issue.level.upper()} {_issue_path_str(issue)}: {issue.message}"


def _display_path(base_path: Path, file_path: Path) -> str:
    if base_path.is_file():
        return file_path.name
    try:
        return str(file_path.relative_to(base_path))
    except ValueError:
        return str(file_path)


def _format_file_issue(base_path: Path, file_path: Path, issue: ValidationIssue) -> str:
    return f"{_display_path(base_path, file_path)}: {_format_issue(issue)}"


def _iter_rule_files(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        return (path,)

    return tuple(
        sorted(
            (
                file_path
                for file_path in path.rglob("*")
                if file_path.is_file() and file_path.suffix.lower() in RULE_FILE_SUFFIXES
            ),
            key=lambda file_path: str(file_path).lower(),
        )
    )


def _plural(count: int, singular: str, plural: str) -> str:
    noun = singular if count == 1 else plural
    return f"{count} {noun}"


def _summarize(results: tuple[ValidationResult, ...]) -> tuple[int, int, int]:
    rule_count = sum(result.rule_count for result in results)
    error_count = sum(result.error_count for result in results)
    warning_count = sum(result.warning_count for result in results)
    return rule_count, error_count, warning_count


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"appsec-rules {__version__}")
        raise typer.Exit()


VersionOpt = Annotated[
    bool,
    typer.Option(
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
]


@app.callback()
def main(version: VersionOpt = False) -> None:
    """Run AppSec rules pack commands."""


def _build_report(
    rules_path: Path,
    file_results: tuple[tuple[Path, ValidationResult], ...],
) -> dict:
    rule_count, error_count, warning_count = _summarize(tuple(result for _, result in file_results))
    files = [
        {
            "path": _display_path(rules_path, rule_file),
            "rules": result.rule_count,
            "errors": result.error_count,
            "warnings": result.warning_count,
            "issues": [
                {
                    "level": issue.level,
                    "path": _issue_path_str(issue),
                    "message": issue.message,
                }
                for issue in result.issues
            ],
        }
        for rule_file, result in file_results
    ]
    return {
        "summary": {
            "files": len(file_results),
            "rules": rule_count,
            "errors": error_count,
            "warnings": warning_count,
        },
        "files": files,
    }


@app.command()
def validate(
    rules_path: RulesPathArg,
    fail_on_warnings: FailOnWarningsOpt = False,
    require_examples: RequireExamplesOpt = False,
    output_format: FormatOpt = OutputFormat.text,
) -> None:
    """Validate one YAML rules pack file or a directory of YAML rule packs."""

    rule_files = _iter_rule_files(rules_path)
    if not rule_files:
        if output_format is OutputFormat.json:
            typer.echo(
                json.dumps(
                    {
                        "summary": {"files": 0, "rules": 0, "errors": 1, "warnings": 0},
                        "files": [],
                        "error": f"no YAML rule files found in {rules_path}",
                    },
                    indent=2,
                )
            )
        else:
            typer.echo(f"Validation failed: no YAML rule files found in {rules_path}.")
        raise typer.Exit(code=1)

    if len(rule_files) == 1:
        file_results = (
            (rule_files[0], validate_rules_file(rule_files[0], require_examples=require_examples)),
        )
    else:
        file_results = validate_rules_files(rule_files, require_examples=require_examples)

    rule_count, error_count, warning_count = _summarize(tuple(result for _, result in file_results))
    ok = error_count == 0
    passed = ok and not (fail_on_warnings and warning_count)

    if output_format is OutputFormat.json:
        report = _build_report(rules_path, file_results)
        report["summary"]["ok"] = passed
        typer.echo(json.dumps(report, indent=2))
        if not passed:
            raise typer.Exit(code=1)
        return

    for rule_file, result in file_results:
        for issue in result.issues:
            typer.echo(_format_file_issue(rules_path, rule_file, issue))

    file_summary = _plural(len(rule_files), "file", "files")
    verdict = "passed" if passed else "failed"
    typer.echo(
        f"Validation {verdict}: {file_summary}, {rule_count} rules, "
        f"{error_count} errors, {warning_count} warnings."
    )
    if not passed:
        raise typer.Exit(code=1)


@export_app.command("index")
def export_index(
    rules_path: RulesPathArg,
    output_format: IndexFormatOpt = IndexFormat.json,
    output: IndexOutputOpt = None,
) -> None:
    """Derive a machine-readable JSON index from a rules pack file or directory.

    Derivation only: this reads pack and rule metadata and never executes rules.
    """

    rule_files = _iter_rule_files(rules_path)
    if not rule_files:
        typer.echo(f"Export failed: no YAML rule files found in {rules_path}.", err=True)
        raise typer.Exit(code=1)

    index = build_index_from_files(list(rule_files))
    document = json.dumps(index, indent=2) + "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8")
        typer.echo(f"Wrote index for {_plural(len(rule_files), 'file', 'files')} to {output}.")
        return

    typer.echo(document, nl=False)
