"""Data-driven version/CVE check (LD1xx) — reads advisories.json.

Exact versions (from lockfiles or `==` pins) yield precise results. A bare
specifier (e.g. `langgraph>=1.0`) is evaluated heuristically: it is only
flagged when the specifier is *capped below* the fix so every version it can
resolve to is vulnerable — an open `>=` is left alone because the resolver can
pick a patched release.
"""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from ..advisories import Advisory, AdvisoryDB, load_db, matched_range, normalize_name
from ..finding import Finding

_UNREACHABLE_HIGH = "9999.0.0"


def check_versions(project, db: AdvisoryDB | None = None) -> list[Finding]:
    db = db or load_db()

    by_name: dict[str, list] = {}
    for dep in project.dependencies:
        by_name.setdefault(normalize_name(dep.name), []).append(dep)

    hits: list[tuple[Advisory, Finding]] = []
    for adv in db.advisories:
        for dep in by_name.get(normalize_name(adv.package), []):
            evaluated = _evaluate(dep, adv)
            if evaluated is None:
                continue
            heuristic, target = evaluated
            hits.append(
                (
                    adv,
                    Finding(
                        id=adv.id,
                        severity=adv.severity(db.buckets),
                        title=adv.title,
                        detail=adv.detail,
                        file=dep.source,
                        line=dep.line,
                        fix=_fix_line(adv, target),
                        cve=adv.cve,
                        aliases=adv.aliases,
                        refs=adv.refs,
                        heuristic=heuristic,
                        exploited_in_the_wild=adv.exploited_in_the_wild,
                    ),
                )
            )

    return _apply_aggregate_suppression(hits)


def _evaluate(dep, adv: Advisory) -> tuple[bool, str | None] | None:
    """Return (is_heuristic, recommended_fix_version) if affected, else None."""
    if dep.version:
        r = matched_range(dep.version, adv.ranges)
        if r is None:
            return None
        return (False, r.fixed or adv.fixed_in)
    if dep.specifier:
        return _evaluate_specifier(dep.specifier, adv)
    return None


def _evaluate_specifier(specifier: str, adv: Advisory) -> tuple[bool, str | None] | None:
    # Only reason from a bare specifier for single-range advisories; multi-range
    # (dual-line) fixes need an exact version to answer correctly.
    if len(adv.ranges) != 1 or not adv.ranges[0].fixed:
        return None
    try:
        spec = SpecifierSet(specifier)
    except InvalidSpecifier:
        return None
    fixed = adv.ranges[0].fixed
    # If a fixed-or-later version is reachable, a safe install exists -> don't flag.
    if spec.contains(fixed, prereleases=True) or spec.contains(_UNREACHABLE_HIGH, prereleases=True):
        return None
    return (True, fixed or adv.fixed_in)


def _fix_line(adv: Advisory, target: str | None) -> str | None:
    target = target or adv.fixed_in
    if not target:
        return None
    return f'pip install "{adv.package}>={target}"'


def _apply_aggregate_suppression(hits: list[tuple[Advisory, Finding]]) -> list[Finding]:
    """Drop an aggregate/catch-all finding when a specific finding already fired
    for the same package install (avoids double-counting — e.g. LD150 vs LD106)."""
    specific_packages = {
        normalize_name(adv.package) for adv, _ in hits if not adv.aggregate
    }
    result = []
    for adv, finding in hits:
        if adv.aggregate and normalize_name(adv.package) in specific_packages:
            continue
        result.append(finding)
    return result
