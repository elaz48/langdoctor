"""Data-driven version/CVE check (LD1xx) — reads advisories.json.

Exact versions (from lockfiles or `==` pins) yield precise results. A bare
specifier (e.g. `langgraph>=1.0`) is evaluated heuristically: it is only
flagged when the specifier is *capped below* the fix so every version it can
resolve to is vulnerable — an open `>=` is left alone because the resolver can
pick a patched release.
"""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..advisories import (
    Advisory,
    AdvisoryDB,
    inherited_identifiers,
    load_db,
    matched_range,
    normalize_name,
)
from ..finding import Finding

_UNREACHABLE_HIGH = "9999.0.0"


def check_versions(project, db: AdvisoryDB | None = None) -> list[Finding]:
    db = db or load_db()

    by_name: dict[str, list] = {}
    for dep in project.dependencies:
        by_name.setdefault(normalize_name(dep.name), []).append(dep)

    inherited = inherited_identifiers(db)
    hits: list[tuple[Advisory, object, Finding]] = []
    for adv in db.advisories:
        if adv.deprecated:
            continue  # kept for its permanent ID; its replacement fires instead
        for dep in by_name.get(normalize_name(adv.package), []):
            evaluated = _evaluate(dep, adv)
            if evaluated is None:
                continue
            heuristic, target = evaluated
            hits.append(
                (
                    adv,
                    dep,
                    Finding(
                        id=adv.id,
                        severity=adv.severity(db.buckets),
                        title=adv.title,
                        detail=adv.detail,
                        file=dep.source,
                        line=dep.line,
                        fix=_fix_line(adv, target, dep),
                        cve=adv.cve,
                        # + the IDs of entries it supersedes, so their
                        # suppressions keep working (e.g. LD112 -> LD133)
                        aliases=adv.aliases + inherited.get(adv.id, ()),
                        refs=adv.refs,
                        heuristic=heuristic,
                        exploited_in_the_wild=adv.exploited_in_the_wild,
                        cvss_score=adv.cvss_score,
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
    if not _reaches_introduced(spec, adv.ranges[0].introduced):
        return None
    return (True, fixed or adv.fixed_in)


def _reaches_introduced(spec: SpecifierSet, introduced: str | None) -> bool:
    """Can the specifier resolve to a version at or above `introduced`?

    A range that starts above zero (e.g. LD131: 1.2.3 <= v < 1.2.14) is out of
    reach for a pin capped below it (langgraph<1.0.0). Candidates are the
    introduced version and every bound the specifier itself names at or above
    it, each also bumped by one in its last release segment, so `>=1.2.5,<1.2.10`
    and `>1.2.3` / `!=1.2.3` still count although they exclude 1.2.3 itself.
    """
    if introduced in (None, "", "0"):
        return True
    try:
        floor = Version(introduced)
    except InvalidVersion:
        return True  # unparseable bound: keep the previous (flagging) behavior
    bases = [floor]
    for clause in spec:
        try:
            version = Version(clause.version)
        except InvalidVersion:  # wildcard clauses such as ==1.2.*
            continue
        if version >= floor:
            bases.append(version)
    candidates = [str(v) for v in bases] + [_bump_last_segment(v) for v in bases]
    return any(spec.contains(c, prereleases=True) for c in candidates)


def _bump_last_segment(version: Version) -> str:
    """1.2.3 -> 1.2.4: the next release a `>V` or `!=V` clause still admits."""
    release = (*version.release[:-1], version.release[-1] + 1)
    epoch = f"{version.epoch}!" if version.epoch else ""
    return epoch + ".".join(str(part) for part in release)


def _fix_line(adv: Advisory, target: str | None, dep) -> str | None:
    target = target or adv.fixed_in
    if not target:
        return None
    image = getattr(dep, "image", None)
    if image:  # the install is a container image: pip is not how it gets fixed
        return f"Use {image}:{target} or newer"
    return f'pip install "{adv.package}>={target}"'


def _apply_aggregate_suppression(hits: list[tuple[Advisory, object, Finding]]) -> list[Finding]:
    """Drop an aggregate/catch-all finding when a specific finding already fired
    for the same install (avoids double-counting — e.g. LD150 vs LD106).

    "The same install" is one dependency entry, not the package name: a second
    service in a monorepo that only trails the baseline keeps its own LD150.
    """
    specific = {_install_key(dep) for adv, dep, _ in hits if not adv.aggregate}
    return [
        finding for adv, dep, finding in hits
        if not (adv.aggregate and _install_key(dep) in specific)
    ]


def _install_key(dep) -> tuple:
    return (normalize_name(dep.name), dep.source, dep.line)
