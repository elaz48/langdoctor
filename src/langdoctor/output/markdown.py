"""Markdown output — great for pasting into PRs and issues."""

from __future__ import annotations

from ..finding import Finding
from . import summarize

_SEVERITY_EMOJI = {
    "critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"
}


def render_markdown(
    findings: list[Finding], project_root, db_date: str, suppressed: int = 0
) -> str:
    if not findings:
        note = f" ({suppressed} suppressed)" if suppressed else ""
        return (
            "## 🩺 langdoctor\n\n"
            f"**All clear — no findings.**{note} Your LangGraph/LangChain stack looks "
            "production-ready.\n\n"
            f"_advisories as of {db_date}_\n"
        )

    s = summarize(findings, suppressed)
    tallies = [
        f"{s[sev]} {sev}" for sev in ("critical", "high", "medium", "low", "info") if s[sev]
    ]
    header = " · ".join(tallies)
    if s["kev"]:
        header += f" · 🔴 {s['kev']} KEV"
    if suppressed:
        header += f" · {suppressed} suppressed"

    lines = [
        "## 🩺 langdoctor",
        "",
        f"**{header}**",
        "",
        "| Severity | ID | Location | Issue | Fix |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        sev = f"{_SEVERITY_EMOJI.get(f.severity, '')} {f.severity}"
        if f.exploited_in_the_wild:
            sev += " 🔴KEV"
        loc = _escape(f"{f.file}:{f.line}" if f.file and f.line else (f.file or "—"))
        title = _escape(f.title)
        if f.cve:
            title += f" ({f.cve})"
        lines.append(f"| {sev} | {f.id} | {loc} | {title} | {_escape(f.fix or '')} |")

    lines += ["", f"_advisories as of {db_date}_"]
    return "\n".join(lines) + "\n"


def _escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
