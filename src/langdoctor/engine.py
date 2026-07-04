"""The engine: run all checks, suppress, sort, and compute exit codes."""

from __future__ import annotations

from dataclasses import dataclass

from .checks import all_checks
from .checks.versions import check_versions
from .finding import SEVERITY_ORDER, Finding
from .suppress import inline_suppressed

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")


@dataclass
class ScanResult:
    findings: list[Finding]
    suppressed: int  # count dropped by --ignore / config / inline directives


def run_scan(project, ignore: list[str] | None = None) -> ScanResult:
    ignore = list(ignore or ())
    raw: list[Finding] = list(check_versions(project))

    for check in all_checks():
        try:
            raw.extend(check.func(project) or [])
        except Exception:
            # A broken individual check must never abort the whole scan.
            continue

    line_cache: dict = {}
    kept: list[Finding] = []
    suppressed = 0
    for f in raw:
        if _suppressed(f, ignore) or inline_suppressed(project, f, line_cache):
            suppressed += 1
        else:
            kept.append(f)

    # KEV first, then severity desc, then stable by id.
    kept.sort(key=lambda f: (not f.exploited_in_the_wild, -f.severity_rank, f.id))
    return ScanResult(findings=kept, suppressed=suppressed)


def run_checks(project, ignore: list[str] | None = None) -> list[Finding]:
    """Convenience wrapper returning just the surviving findings."""
    return run_scan(project, ignore).findings


def _suppressed(finding: Finding, ignore: list[str]) -> bool:
    return any(finding.matches_id(token) for token in ignore)


def _considered(findings: list[Finding], strict: bool) -> list[Finding]:
    # Heuristic findings never affect exit code unless --strict.
    return [f for f in findings if strict or not f.heuristic]


def exit_code_for(findings: list[Finding], fail_on: str = "high", strict: bool = False) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    if any(f.severity_rank >= threshold for f in _considered(findings, strict)):
        return 1
    return 0
