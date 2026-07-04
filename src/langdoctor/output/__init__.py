"""Output formatters and shared serialization helpers.

console (Phase 1) + json / sarif / markdown (Phase 3).
"""

from __future__ import annotations

from ..finding import SEVERITY_ORDER, Finding

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
    }


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
