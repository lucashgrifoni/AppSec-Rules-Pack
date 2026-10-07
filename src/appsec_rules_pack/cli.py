"""Typer command-line interface for AppSec rules pack validation."""

import datetime as dt
import json
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml

from appsec_rules_pack import __version__
from appsec_rules_pack.exporter import build_index
from appsec_rules_pack.loader import load_yaml_file
from appsec_rules_pack.reporter import build_coverage
from appsec_rules_pack.review import ReviewResult, review_files, review_payloads
from appsec_rules_pack.sarif_export import build_sarif
from appsec_rules_pack.semgrep_scaffold import (
    PATTERN_PLACEHOLDER,
    build_semgrep_scaffold,
)
from appsec_rules_pack.validator import (
    ValidationIssue,
    ValidationResult,
    validate_rules_file,
    validate_rules_files,
)

# Typer's rich tracebacks print local variables, which for this tool means the content
# of the rules pack, into CI logs. Unexpected errors must not echo pack content.
_TYPER_SETTINGS: dict[str, Any] = {"pretty_exceptions_show_locals": False}

app = typer.Typer(help="Validate AppSec rules pack files.", **_TYPER_SETTINGS)
export_app = typer.Typer(
    help="Derive machine-readable artifacts from rules packs.", **_TYPER_SETTINGS
)
app.add_typer(export_app, name="export")
report_app = typer.Typer(
    help="Derive coverage and summary reports from rules packs.", **_TYPER_SETTINGS
)
app.add_typer(report_app, name="report")


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
# Format markers of the JSON reports; see schemas/validation-report.schema.json and
# schemas/review-report.schema.json. Additive changes keep v1.
VALIDATION_REPORT_SCHEMA = "appsec-rules-validation/v1"
REVIEW_REPORT_SCHEMA = "appsec-rules-review/v1"

SEMGREP_HEADER = (
    "# Reference Semgrep scaffold derived from the AppSec Rules Pack (derivation only).\n"
    "# NOT a runnable ruleset: the source rules are engine-agnostic review rules with no\n"
    "# detection patterns (see ADR-0001). Replace each rule's placeholder pattern-regex\n"
    f"# ('{PATTERN_PLACEHOLDER}') with a real detection before use. Only enabled rules are\n"
    "# emitted. Regenerate: appsec-rules export semgrep <rules> -o <out>.semgrep.yaml\n"
)


class IndexFormat(StrEnum):
    """Supported export index formats."""

    json = "json"


IndexFormatOpt = Annotated[
    IndexFormat,
    typer.Option("--format", "-f", help="Index output format (json)."),
]
IndexOutputOpt = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Write the result to this file instead of stdout."),
]


def _issue_path_str(issue: ValidationIssue) -> str:
    return ".".join(str(part) for part in issue.path) if issue.path else "<root>"


def _format_issue(issue: ValidationIssue) -> str:
    return f"{issue.level.upper()} {_issue_path_str(issue)}: {issue.message}"


def _display_path(base_path: Path, file_path: Path) -> str:
    # Forward slashes on every platform, so a report reads the same on Windows and Linux.
    if base_path.is_file():
        return file_path.name
    try:
        return file_path.relative_to(base_path).as_posix()
    except ValueError:
        return file_path.as_posix()


def _format_file_issue(base_path: Path, file_path: Path, issue: ValidationIssue) -> str:
    return f"{_display_path(base_path, file_path)}: {_format_issue(issue)}"


def _write_document(output: Path, document: str, inputs: tuple[Path, ...] = ()) -> None:
    """Write a derived document, reporting write failures as an actionable CLI error.

    Pointing ``--output`` at an existing directory, or at any path that cannot be
    written, used to escape as a raw Python traceback (``PermissionError`` on Windows,
    ``IsADirectoryError`` on POSIX). Pointing it at one of the input packs replaced the
    pack with the derived document, so that is refused. The caller keeps its own
    success message.
    """

    target = output.resolve()
    if any(target == source.resolve() for source in inputs):
        typer.echo(
            f"Write failed: {output} is one of the input rules files; "
            "choose a different output path.",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8", newline="\n")
    except OSError as error:
        reason = error.strerror or str(error)
        typer.echo(f"Write failed: cannot write to {output}: {reason}.", err=True)
        raise typer.Exit(code=1) from error


def _load_payloads(rule_files: tuple[Path, ...], action: str) -> list[Any]:
    """Load rule files for derivation, reporting read failures as actionable CLI errors.

    A file that cannot be read, decoded as UTF-8, or parsed as YAML used to escape as a
    raw Python traceback from the export and report commands. Judging pack structure
    stays in ``validate``; this only guards the file-to-payload step.
    """

    payloads: list[Any] = []
    for rule_file in rule_files:
        try:
            payloads.append(load_yaml_file(rule_file))
        except OSError as error:
            reason = error.strerror or str(error)
            typer.echo(f"{action} failed: could not read {rule_file}: {reason}.", err=True)
            raise typer.Exit(code=1) from error
        except UnicodeDecodeError as error:
            typer.echo(
                f"{action} failed: could not decode {rule_file} as UTF-8: {error.reason}.",
                err=True,
            )
            raise typer.Exit(code=1) from error
        except RecursionError as error:
            typer.echo(
                f"{action} failed: could not parse YAML in {rule_file}: "
                "nesting depth exceeds the supported limit.",
                err=True,
            )
            raise typer.Exit(code=1) from error
        except yaml.YAMLError as error:
            problem = getattr(error, "problem", None) or "invalid YAML"
            typer.echo(
                f"{action} failed: could not parse YAML in {rule_file}: {problem}.",
                err=True,
            )
            raise typer.Exit(code=1) from error
    return payloads


def _dump_json(document: Any, action: str) -> str:
    """Serialize a derived document, reporting unrepresentable values as a CLI error.

    Exports skip validation, so a malformed pack can carry values JSON cannot hold, such
    as an unquoted YAML date. That used to escape as a raw traceback.
    """

    try:
        return json.dumps(document, indent=2) + "\n"
    except (TypeError, ValueError) as error:
        typer.echo(
            f"{action} failed: the rules pack contains a value JSON cannot represent "
            f"({error}). Run `validate` to find it.",
            err=True,
        )
        raise typer.Exit(code=1) from error


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
                    "code": issue.code,
                    "rule_id": issue.rule_id,
                    "path": _issue_path_str(issue),
                    "message": issue.message,
                }
                for issue in result.issues
            ],
        }
        for rule_file, result in file_results
    ]
    return {
        "schema": VALIDATION_REPORT_SCHEMA,
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
                        "schema": VALIDATION_REPORT_SCHEMA,
                        "summary": {
                            "files": 0,
                            "rules": 0,
                            "errors": 1,
                            "warnings": 0,
                            "ok": False,
                        },
                        "files": [],
                        "error": f"no YAML rule files found in {rules_path.as_posix()}",
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
        f"Validation {verdict}: {file_summary}, {_plural(rule_count, 'rule', 'rules')}, "
        f"{_plural(error_count, 'error', 'errors')}, "
        f"{_plural(warning_count, 'warning', 'warnings')}."
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

    index = build_index(_load_payloads(rule_files, "Export"))
    document = _dump_json(index, "Export")

    if output is not None:
        _write_document(output, document, rule_files)
        typer.echo(f"Wrote index for {_plural(len(rule_files), 'file', 'files')} to {output}.")
        return

    typer.echo(document, nl=False)


@export_app.command("semgrep")
def export_semgrep(
    rules_path: RulesPathArg,
    output: IndexOutputOpt = None,
) -> None:
    """Derive a NON-RUNNABLE reference Semgrep scaffold (derivation only).

    The scaffold carries rule metadata but placeholder patterns; it is not a working
    ruleset and must have real detections added before use (see ADR-0001).
    """

    rule_files = _iter_rule_files(rules_path)
    if not rule_files:
        typer.echo(f"Export failed: no YAML rule files found in {rules_path}.", err=True)
        raise typer.Exit(code=1)

    scaffold = build_semgrep_scaffold(_load_payloads(rule_files, "Export"))
    body = yaml.safe_dump(scaffold, sort_keys=False, allow_unicode=True)
    document = SEMGREP_HEADER + body

    if output is not None:
        _write_document(output, document, rule_files)
        typer.echo(
            f"Wrote Semgrep scaffold for {_plural(len(rule_files), 'file', 'files')} to {output}."
        )
        return

    typer.echo(document, nl=False)


@export_app.command("sarif")
def export_sarif(
    rules_path: RulesPathArg,
    output: IndexOutputOpt = None,
) -> None:
    """Derive a SARIF 2.1.0 rule-catalog (reportingDescriptors, no results).

    The pack does not execute, so the SARIF ``results`` array is intentionally empty;
    this publishes the rule catalog and metadata for SARIF-aware tools (see ADR-0001).
    """

    rule_files = _iter_rule_files(rules_path)
    if not rule_files:
        typer.echo(f"Export failed: no YAML rule files found in {rules_path}.", err=True)
        raise typer.Exit(code=1)

    sarif = build_sarif(_load_payloads(rule_files, "Export"))
    document = _dump_json(sarif, "Export")

    if output is not None:
        _write_document(output, document, rule_files)
        typer.echo(
            f"Wrote SARIF rule-catalog for {_plural(len(rule_files), 'file', 'files')} to {output}."
        )
        return

    typer.echo(document, nl=False)


@report_app.command("coverage")
def report_coverage(
    rules_path: RulesPathArg,
    output_format: FormatOpt = OutputFormat.text,
    output: IndexOutputOpt = None,
) -> None:
    """Report framework-mapping coverage across a rules pack.

    Derivation only: this summarizes mapping metadata and never executes rules.
    """

    rule_files = _iter_rule_files(rules_path)
    if not rule_files:
        typer.echo(f"Report failed: no YAML rule files found in {rules_path}.", err=True)
        raise typer.Exit(code=1)

    coverage = build_coverage(_load_payloads(rule_files, "Report"))

    if coverage["rules"] == 0:
        # The report is derived without schema validation, so a pack whose `rules` key is
        # missing or malformed still produces a clean-looking 0/0 report. Say so on stderr
        # rather than letting an empty report read as a healthy one. The exit code stays 0:
        # reporting is derivation, and `validate` is what judges pack structure.
        typer.echo(
            f"Warning: no rules found in {rules_path}; the coverage report is empty. "
            "Run `validate` to check the pack structure.",
            err=True,
        )

    if output_format is OutputFormat.json:
        document = _dump_json(coverage, "Report")
        if output is not None:
            _write_document(output, document, rule_files)
            typer.echo(f"Wrote coverage report to {output}.")
            return
        typer.echo(document, nl=False)
        return

    total = coverage["rules"]
    lines = [f"Mapping coverage for {_plural(total, 'rule', 'rules')}:"]
    for framework, stats in coverage["frameworks"].items():
        covered = stats["covered"]
        pct = round(100 * covered / total) if total else 0
        line = f"  {framework:<22} {covered}/{total}  ({pct}%)"
        if stats["missing"]:
            line += "  missing: " + ", ".join(stats["missing"])
        lines.append(line)
    if coverage["categories"]:
        cats = ", ".join(f"{name}={count}" for name, count in coverage["categories"].items())
        lines.append(f"Categories: {cats}")

    document = "\n".join(lines) + "\n"
    if output is not None:
        # `--output` in the default text mode used to be silently ignored; the text
        # report now lands in the file exactly like the JSON variant does.
        _write_document(output, document, rule_files)
        typer.echo(f"Wrote coverage report to {output}.")
        return
    typer.echo(document, nl=False)


ReviewInputArg = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=False),
]
AsOfOpt = Annotated[
    str | None,
    typer.Option(
        "--as-of",
        metavar="YYYY-MM-DD",
        help="Check exception expiry as of this date instead of today (UTC).",
    ),
]


def _parse_as_of(value: str | None) -> dt.date:
    if value is None:
        return dt.datetime.now(dt.UTC).date()
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise typer.BadParameter(
            "expected a date in YYYY-MM-DD format", param_hint="--as-of"
        ) from error


def _review_report(result: ReviewResult, passed: bool) -> dict:
    counts = result.status_counts()
    results = []
    for outcome in result.outcomes:
        entry: dict[str, Any] = {
            "rule_id": outcome.rule_id,
            "title": outcome.title,
            "severity": outcome.severity,
            "effective_severity": outcome.effective_severity,
            "enforcement": outcome.enforcement,
            "status": outcome.status,
            "evidence": list(outcome.evidence),
            "exception": outcome.exception,
        }
        if outcome.notes is not None:
            entry["notes"] = outcome.notes
        if outcome.assessed_severity is not None:
            entry["assessed_severity"] = outcome.assessed_severity
        entry.update(outcome.extensions)
        results.append(entry)
    return {
        "schema": REVIEW_REPORT_SCHEMA,
        "pack": {"id": result.pack_id, "version": result.pack_version},
        "review": result.review,
        "as_of": result.as_of.isoformat(),
        "summary": {
            "rules": len(result.outcomes),
            "met": counts["met"],
            "not_met": counts["not-met"],
            "not_applicable": counts["not-applicable"],
            "excepted": counts["excepted"],
            "unreviewed": counts["unreviewed"],
            "open_by_enforcement": result.open_counts("enforcement"),
            "open_by_severity": result.open_counts("severity"),
            "open_by_effective_severity": result.open_counts("effective_severity"),
            "errors": result.error_count,
            "warnings": result.warning_count,
            "ok": passed,
        },
        "results": results,
        "issues": [
            {
                "level": issue.level,
                "code": issue.code,
                "rule_id": issue.rule_id,
                "path": _issue_path_str(issue),
                "message": issue.message,
            }
            for issue in result.issues
        ],
    }


@app.command()
def review(
    pack: ReviewInputArg,
    record: ReviewInputArg,
    as_of: AsOfOpt = None,
    fail_on_warnings: FailOnWarningsOpt = False,
    output_format: FormatOpt = OutputFormat.text,
) -> None:
    """Check a review record against the rules pack it was made with.

    The record says, rule by rule, whether a reviewed subject met each rule, with
    evidence and exceptions. This checks the record against the pack's policy; it does
    not inspect the subject. Exit 1 means the record is invalid. Open rules never change
    the exit code: the gate decides what to do with them (ADR-0006).
    """

    result = review_files(pack, record, as_of=_parse_as_of(as_of))
    passed = result.ok and not (fail_on_warnings and result.warning_count)

    if output_format is OutputFormat.json:
        typer.echo(json.dumps(_review_report(result, passed), indent=2))
        if not passed:
            raise typer.Exit(code=1)
        return

    for outcome in result.outcomes:
        assessed = f" (assessed {outcome.assessed_severity})" if outcome.assessed_severity else ""
        typer.echo(
            f"{outcome.rule_id:<24} {outcome.severity:<9} {outcome.enforcement:<9} "
            f"{outcome.status}{assessed}"
        )
    for issue in result.issues:
        rule = f" [{issue.rule_id}]" if issue.rule_id else ""
        typer.echo(f"{_format_issue(issue)}{rule}")

    if result.review is None:
        # Nothing was checked, so rule counts of zero would read as an empty pack.
        typer.echo(
            "Review failed: the record could not be checked against the pack; "
            f"{_plural(result.error_count, 'error', 'errors')}, "
            f"{_plural(result.warning_count, 'warning', 'warnings')}."
        )
        raise typer.Exit(code=1)

    counts = result.status_counts()
    open_count = counts["not-met"] + counts["unreviewed"]
    verdict = "passed" if passed else "failed"
    typer.echo(
        f"Review {verdict}: {_plural(len(result.outcomes), 'rule', 'rules')}; "
        f"{counts['met']} met, {counts['not-met']} not met, "
        f"{counts['not-applicable']} not applicable, {counts['excepted']} excepted, "
        f"{counts['unreviewed']} unreviewed; {open_count} open; "
        f"{_plural(result.error_count, 'error', 'errors')}, "
        f"{_plural(result.warning_count, 'warning', 'warnings')}."
    )
    if not passed:
        raise typer.Exit(code=1)


InitPathArg = Annotated[
    Path,
    typer.Argument(dir_okay=False, help="Where to write the new pack."),
]
ForceOpt = Annotated[
    bool,
    typer.Option("--force", help="Overwrite the file if it already exists."),
]


@app.command()
def init(path: InitPathArg, force: ForceOpt = False) -> None:
    """Write a minimal rules pack that passes the strict gate, to start from."""

    if path.exists() and not force:
        typer.echo(f"Init failed: {path} already exists; pass --force to overwrite.", err=True)
        raise typer.Exit(code=1)

    template = resources.files("appsec_rules_pack").joinpath("templates/minimal-pack.yaml")
    _write_document(path, template.read_text(encoding="utf-8"))
    typer.echo(
        f"Wrote a starter pack to {path}. Next: appsec-rules validate {path} "
        "--require-examples --fail-on-warnings"
    )


RecordPathArg = Annotated[
    Path,
    typer.Argument(dir_okay=False, help="Where to write the new review record."),
]
SubjectOpt = Annotated[
    str,
    typer.Option("--subject", help="What is being reviewed: a service, repository, or release."),
]
ReviewerOpt = Annotated[
    str,
    typer.Option("--reviewer", help="Who is doing the review."),
]
SubjectRefOpt = Annotated[
    str | None,
    typer.Option(
        "--subject-ref",
        help="Exact revision reviewed: a commit SHA, tag, image digest, or package version.",
    ),
]

RECORD_HEADER = """\
# Review record for {pack} {version}, written by `appsec-rules init-review`.
# Every enabled rule starts as not-met with no notes. Change each one to:
#   met             with evidence: what you checked, and where
#   not-met         with notes: the finding
#   not-applicable  with notes: why the rule does not apply to this subject
#   excepted        with an exception block (`appsec-rules export index` shows each
#                   rule's exception policy)
# Until a rule has its evidence or notes, `appsec-rules review` warns
# review-justification-missing for it, so a run with --fail-on-warnings fails.
"""


def _yaml_text(value: str) -> str:
    # A JSON string is a valid double-quoted YAML scalar, whatever characters it holds.
    return json.dumps(value, ensure_ascii=False)


def _record_document(
    pack: dict[str, Any], subject: str, reviewer: str, subject_ref: str | None, today: dt.date
) -> str:
    meta = pack["pack"]
    lines = [RECORD_HEADER.format(pack=meta["id"], version=meta["version"]).rstrip("\n")]
    lines += [
        "review:",
        f"  pack: {_yaml_text(meta['id'])}",
        f"  pack_version: {_yaml_text(meta['version'])}",
        f"  subject: {_yaml_text(subject)}",
    ]
    if subject_ref is not None:
        lines.append(f"  subject_ref: {_yaml_text(subject_ref)}")
    lines += [
        f"  reviewer: {_yaml_text(reviewer)}",
        f'  date: "{today.isoformat()}"',
        "results:",
    ]
    for rule in pack["rules"]:
        if rule["status"] != "enabled":
            continue
        title = " ".join(rule["title"].split())
        lines += [
            f"  # {title} ({rule['severity']}, {rule['enforcement']})",
            f"  - rule: {rule['id']}",
            "    status: not-met",
        ]
    return "\n".join(lines) + "\n"


@app.command("init-review")
def init_review(
    pack: ReviewInputArg,
    path: RecordPathArg,
    subject: SubjectOpt,
    reviewer: ReviewerOpt,
    subject_ref: SubjectRefOpt = None,
    force: ForceOpt = False,
) -> None:
    """Write a review record that lists every enabled rule of a pack, to fill in.

    Each rule starts as not-met with no notes, so the record counts every rule as open
    and warns until each one is reviewed.
    """

    if path.exists() and not force:
        typer.echo(f"Init failed: {path} already exists; pass --force to overwrite.", err=True)
        raise typer.Exit(code=1)

    validation = validate_rules_file(pack)
    if not validation.ok:
        noun = "error" if validation.error_count == 1 else "errors"
        typer.echo(
            f"Init failed: the rules pack has {validation.error_count} validation {noun}; "
            f"run `appsec-rules validate {pack}` first.",
            err=True,
        )
        raise typer.Exit(code=1)

    payload = load_yaml_file(pack)
    today = dt.datetime.now(dt.UTC).date()
    document = _record_document(payload, subject, reviewer, subject_ref, today)
    # Check the record before writing it, so a bad --subject or --reviewer value fails
    # here instead of on the first review.
    check = review_payloads(payload, yaml.safe_load(document), as_of=today)
    if not check.ok:
        for issue in check.issues:
            if issue.level == "error":
                typer.echo(f"Init failed: {_issue_path_str(issue)}: {issue.message}", err=True)
        raise typer.Exit(code=1)

    _write_document(path, document, (pack,))
    typer.echo(
        f"Wrote a review record with {_plural(len(check.outcomes), 'rule', 'rules')} to {path}. "
        f"Next: fill it in, then appsec-rules review {pack} {path} --fail-on-warnings"
    )
