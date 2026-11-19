"""Output formatters and shared serialization helpers.

console (Phase 1) + json / sarif / markdown (Phase 3).
"""

from __future__ import annotations

import re

from ..finding import SEVERITY_ORDER, Finding, Reachability

# C0 and C1 control characters except tab and newline: ESC, BEL, CSI, ...
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def printable(text: str) -> str:
    """Drop control characters from text that can come from the scanned repo.

    A directory or package name is attacker-chosen. Written to a terminal as
    is, `\x1b[2J` clears the screen and `\x1b]0;...\x07` retitles the window;
    without the control bytes the rest is just odd-looking text.
    """
    return _CONTROL_CHARS.sub("", text)

# Fallback numeric CVSS-equivalent for code-pattern checks that have no real
# CVSS score. Aligned to the advisory severity_buckets thresholds.
_SEVERITY_SCORE_FALLBACK = {
    "critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0
}


def security_severity(f: Finding) -> str:
    """GitHub code scanning sorts SARIF by this numeric CVSS string.

    Prefer the advisory's real CVSS score; fall back to the severity bucket
    threshold for code-pattern checks that carry no CVSS.
    """
    if f.cvss_score is not None:
        return f"{f.cvss_score}"
    return f"{_SEVERITY_SCORE_FALLBACK.get(f.severity, 0.0)}"


def finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "file": f.file,
        "line": f.line,
        "fix": f.fix,
        "cve": f.cve,
        "aliases": list(f.aliases),
        "refs": list(f.refs),
        "cvss_score": f.cvss_score,
        "heuristic": f.heuristic,
        "exploited_in_the_wild": f.exploited_in_the_wild,
        "reachability": _reachability_to_dict(f.reachability),
    }


def _reachability_to_dict(evidence: Reachability | None) -> dict | None:
    if evidence is None:
        return None
    return {
        "reachable": evidence.reachable,
        "symbols": list(evidence.symbols),
        "uses": [{"file": u.file, "line": u.line, "symbol": u.symbol} for u in evidence.uses],
        "total_uses": evidence.total_uses,
        "files_searched": evidence.files_searched,
        "files_unparsed": evidence.files_unparsed,
    }


def symbol_name(symbol: str) -> str:
    """`pkg.module:Name` -> `Name`; a bare module stays as it is."""
    return symbol.rpartition(":")[2]


def describe_reachability(evidence: Reachability) -> str:
    """One line for a human: where the vulnerable API is used, or that it is not."""
    if evidence.uses:
        first = evidence.uses[0]
        others = max(evidence.total_uses, len(evidence.uses)) - 1
        more = f", +{others} more" if others else ""
        return f"used at {first.file}:{first.line} ({symbol_name(first.symbol)}{more})"
    names = ", ".join(dict.fromkeys(symbol_name(s) for s in evidence.symbols))
    files = "file" if evidence.files_searched == 1 else "files"
    searched = f"{evidence.files_searched} Python {files}"
    if evidence.files_unparsed:
        # Not "not imported": the unread code may be where the import is.
        return (
            f"no import found in {searched}, but {evidence.files_unparsed} more could not "
            f"be read: {names}"
        )
    return f"not imported in {searched}: {names}"


def summarize(findings: list[Finding], suppressed: int = 0) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "kev": sum(1 for f in findings if f.exploited_in_the_wild),
        "suppressed": suppressed,
        **counts,
    }
