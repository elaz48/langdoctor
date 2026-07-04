"""Command-line interface.

Phase 1 ships the default scan, `--version`, and `list-checks`. Additional
flags/formats (json/sarif/markdown, --strict combos, inline suppression) are
wired further in Phase 3; the arguments are declared here where cheap.

Exit codes: 0 = clean (or below threshold), 1 = findings at/above --fail-on,
2 = scan error.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .advisories import load_db
from .checks import all_checks
from .engine import exit_code_for, run_scan
from .output.console import render
from .output.json_out import render_json
from .output.markdown import render_markdown
from .output.sarif import render_sarif
from .scanner import scan
from .settings import load_settings


def _parse_ignore(raw: str) -> list[str]:
    return [t.strip() for t in (raw or "").replace(" ", ",").split(",") if t.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="langdoctor",
        description=(
            "Scan a LangGraph/LangChain project for known CVEs, insecure configs, "
            "and production footguns — deterministic, offline, no API key."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="project directory to scan")
    parser.add_argument(
        "--format",
        choices=["console", "json", "sarif", "markdown"],
        default="console",
        help="output format (default: console)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default=None,
        help="exit 1 at or above this severity (default: high, or [tool.langdoctor])",
    )
    parser.add_argument(
        "--strict", action="store_true", help="let heuristic findings affect the exit code"
    )
    parser.add_argument(
        "--ignore", default="", help="comma-separated check IDs / CVEs / aliases to suppress"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print findings without summary chrome"
    )
    parser.add_argument(
        "--version", action="store_true", help="print tool version and advisory DB date"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "list-checks":
        return _list_checks()

    args = build_parser().parse_args(argv)

    if args.version:
        db = load_db()
        print(f"langdoctor {__version__}")
        print(f"advisories as of {db.updated}")
        return 0

    settings = load_settings(args.path)
    fail_on = args.fail_on or settings.fail_on or "high"
    ignore = _parse_ignore(args.ignore) + settings.ignore

    try:
        project = scan(args.path, excludes=set(settings.exclude))
    except Exception as exc:  # scan error -> exit code 2
        print(f"langdoctor: scan error: {exc}", file=sys.stderr)
        return 2

    db = load_db()
    result = run_scan(project, ignore=ignore)
    _emit(result.findings, project.root, db.updated, args, result.suppressed)
    return exit_code_for(result.findings, fail_on=fail_on, strict=args.strict)


def _emit(findings, project_root, db_date, args, suppressed: int) -> None:
    if args.format == "json":
        print(render_json(findings, project_root, db_date, suppressed))
    elif args.format == "sarif":
        print(render_sarif(findings, project_root, db_date, suppressed))
    elif args.format == "markdown":
        print(render_markdown(findings, project_root, db_date, suppressed))
    else:
        render(findings, project_root, db_date, suppressed=suppressed, quiet=args.quiet)


def _list_checks() -> int:
    from rich.console import Console
    from rich.table import Table

    db = load_db()
    console = Console()
    table = Table(title=f"langdoctor checks — advisories as of {db.updated}")
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Package / category")
    table.add_column("Title")
    for adv in db.advisories:
        badge = " 🔴KEV" if adv.exploited_in_the_wild else ""
        table.add_row(adv.id, adv.severity(db.buckets), adv.package, adv.title + badge)
    for check in all_checks():
        table.add_row(check.id, check.severity or "-", check.category, check.title)
    console.print(table)
    return 0
