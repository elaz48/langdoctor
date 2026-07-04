"""Rich human-readable console output.

Rich respects NO_COLOR and non-TTY automatically; we pass it through explicitly
so behaviour is deterministic in CI and when piped.
"""

from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..finding import Finding

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
SEV_DOT = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _make_console() -> Console:
    return Console(no_color=bool(os.environ.get("NO_COLOR")))


def render(findings, project_root, db_date, console: Console | None = None, quiet: bool = False):
    console = console or _make_console()

    if not findings:
        render_clean(console, db_date)
        return

    if not quiet:
        _render_summary(console, findings, project_root)

    for severity in SEV_ORDER:
        for finding in [f for f in findings if f.severity == severity]:
            _render_finding(console, finding)

    if not quiet:
        console.print(Text(f"advisories as of {db_date}", style="dim"))


def _render_summary(console: Console, findings, project_root) -> None:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    header = Text("langdoctor 🩺  ", style="bold")
    printed = False
    for s in SEV_ORDER:
        if counts[s]:
            if printed:
                header.append("  ")
            header.append(f"{counts[s]} {s}", style=SEV_STYLE[s])
            printed = True
    kev = sum(1 for f in findings if f.exploited_in_the_wild)
    if kev:
        header.append(f"   {kev} 🔴 KEV", style="bold red")
    console.print(header)
    console.print(Text(f"scanned {project_root}", style="dim"))
    console.print()


def _render_finding(console: Console, f: Finding) -> None:
    title_line = Text()
    title_line.append("● ", style=SEV_DOT.get(f.severity, "dim"))
    title_line.append(f.id, style="bold")
    title_line.append(f"  {f.severity.upper()}", style=SEV_STYLE.get(f.severity, ""))
    if f.exploited_in_the_wild:
        title_line.append("  🔴 KEV", style="bold red")
    if f.heuristic:
        title_line.append("  [heuristic]", style="dim italic")
    console.print(title_line)

    console.print(Text(f"  {f.title}", style="bold"))
    if f.detail:
        console.print(Text(f"  {f.detail}", style="dim"))

    meta: list[str] = []
    loc = f.file or ""
    if f.line:
        loc = f"{loc}:{f.line}"
    if loc:
        meta.append(loc)
    if f.cve:
        ids = f.cve
        if f.aliases:
            ids += " (" + ", ".join(f.aliases) + ")"
        meta.append(ids)
    if meta:
        console.print(Text("  " + "  ·  ".join(meta), style="dim"))

    if f.fix:
        console.print(Text(f"  → {f.fix}", style="green"))
    console.print()


def render_clean(console: Console, db_date: str) -> None:
    console.print(
        Panel.fit(
            Text.assemble(
                ("🩺  All clear — no findings.\n", "bold green"),
                ("Your LangGraph / LangChain stack looks production-ready.\n\n", ""),
                ("Keep it that way — run langdoctor in CI:\n", "dim"),
                ("  - uses: elaz48/langdoctor@v1", "cyan"),
            ),
            title="langdoctor",
            border_style="green",
        )
    )
    console.print(Text(f"advisories as of {db_date}", style="dim"))
