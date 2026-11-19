"""The engine: run all checks, suppress, sort, and compute exit codes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import all_checks
from .checks.versions import check_versions
from .finding import SEVERITY_ORDER, Finding
from .output import printable
from .suppress import inline_suppressed

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")
_MAX_ERROR_LENGTH = 200


@dataclass
class ScanResult:
    findings: list[Finding]
    suppressed: int  # count dropped by --ignore / config / inline directives
    # One line per check that crashed. A scan with any is INCOMPLETE: the
    # findings of those checks are missing, so it must not read as a result.
    errors: list[str] = field(default_factory=list)


def run_scan(project, ignore: list[str] | None = None) -> ScanResult:
    ignore = list(ignore or ())
    raw: list[Finding] = []
    errors: list[str] = []
    # SystemExit too: code a check calls into must not be able to end the
    # process, least of all with status 0.
    try:
        raw.extend(check_versions(project))
    except (Exception, SystemExit) as exc:
        errors.append(_describe_failure("known-vulnerability check", exc))

    for check in all_checks():
        try:
            raw.extend(check.func(project) or [])
        except (Exception, SystemExit) as exc:
            # One broken check does not stop the others — but it is recorded.
            # Dropping it silently would let input that crashes a check pass
            # for a clean scan.
            errors.append(_describe_failure(check.id, exc))

    line_cache: dict = {}
    kept: list[Finding] = []
    suppressed = 0
    for f in raw:
        if _suppressed(f, ignore) or inline_suppressed(project, f, line_cache):
            suppressed += 1
        else:
            kept.append(f)

    # KEV first, then severity desc; within a severity, findings whose API is
    # not imported anywhere go last; then stable by id.
    kept.sort(
        key=lambda f: (not f.exploited_in_the_wild, -f.severity_rank, _not_imported(f), f.id)
    )
    return ScanResult(findings=kept, suppressed=suppressed, errors=errors)


def _describe_failure(name: str, exc: BaseException) -> str:
    # The message can quote the scanned repository: strip control characters, cap the length.
    return printable(f"{name}: {type(exc).__name__}: {exc}")[:_MAX_ERROR_LENGTH]


def run_checks(project, ignore: list[str] | None = None) -> list[Finding]:
    """Convenience wrapper returning just the surviving findings."""
    return run_scan(project, ignore).findings


def _not_imported(finding: Finding) -> bool:
    # `is False`, not falsy: None means some code could not be read, and an
    # unknown answer must not push a finding down the list.
    return finding.reachability is not None and finding.reachability.reachable is False


def _suppressed(finding: Finding, ignore: list[str]) -> bool:
    return any(finding.matches_id(token) for token in ignore)


def _considered(findings: list[Finding], strict: bool) -> list[Finding]:
    # Heuristic findings never affect exit code unless --strict.
    return [f for f in findings if strict or not f.heuristic]


def _exempt(finding: Finding) -> bool:
    """Under --allow-unimported: reported, but does not fail the build.

    Only a conclusive "not imported" qualifies — never an unknown, never a
    finding no claim was made about — and a known-exploited vulnerability
    always counts, whatever the imports say.
    """
    return _not_imported(finding) and not finding.exploited_in_the_wild


def exit_code_for(
    findings: list[Finding], fail_on: str = "high", strict: bool = False,
    allow_unimported: bool = False,
) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    for finding in _considered(findings, strict):
        if finding.severity_rank >= threshold and not (allow_unimported and _exempt(finding)):
            return 1
    return 0


def not_counted(
    findings: list[Finding], fail_on: str = "high", strict: bool = False,
    allow_unimported: bool = False,
) -> list[Finding]:
    """The findings that would have failed the run but for --allow-unimported."""
    if not allow_unimported or fail_on == "never":
        return []
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    return [
        f for f in _considered(findings, strict) if f.severity_rank >= threshold and _exempt(f)
    ]
