"""Load and interpret the advisory database (advisories.json, schema v2).

Advisories are DATA, not code. This module is the only place that knows the
JSON shape: it parses it into typed objects, derives severity from CVSS, and
answers version-applicability questions via OSV-style affected_ranges.

IDs are permanent, so a wrong entry is deprecated, never removed: `deprecated`
(an ISO date) plus `superseded_by` (replacement IDs). A deprecated advisory
stays in the DB — its CVE and aliases keep suppression and the advisory watcher
working — but never produces a finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from packaging.version import InvalidVersion, Version

DATA_PATH = Path(__file__).parent / "data" / "advisories.json"
DEFAULT_BUCKETS = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1}

_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """PEP 503 normalization so 'LangGraph_Checkpoint.Sqlite' == 'langgraph-checkpoint-sqlite'."""
    return _NORMALIZE_RE.sub("-", name.strip()).lower()


@dataclass(frozen=True)
class VersionRange:
    introduced: str
    fixed: str | None


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    cve: str | None
    aliases: tuple[str, ...]
    ranges: tuple[VersionRange, ...]
    fixed_in: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity_override: str | None
    exploited_in_the_wild: bool
    aggregate: bool
    title: str
    detail: str
    refs: tuple[str, ...]
    deprecated: str | None = None  # date it was deprecated; None = live
    superseded_by: tuple[str, ...] = ()
    # Public entry points an application must import for the vulnerable code to
    # be in play: "pkg.module:Name" or "pkg.module". Empty = no claim is made.
    symbols: tuple[str, ...] = ()

    def severity(self, buckets: dict[str, float] | None = None) -> str:
        return derive_severity(self.cvss_score, self.severity_override, buckets or DEFAULT_BUCKETS)


@dataclass
class AdvisoryDB:
    schema_version: int
    updated: str
    buckets: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_BUCKETS))
    advisories: tuple[Advisory, ...] = ()
    # image repository -> the package its release tags are versions of
    container_images: dict[str, str] = field(default_factory=dict)


def derive_severity(
    score: float | None, override: str | None, buckets: dict[str, float]
) -> str:
    """Bucket = highest threshold the CVSS score meets; override wins when set."""
    if override:
        return override
    if score is None:
        return "info"
    for name, threshold in sorted(buckets.items(), key=lambda kv: kv[1], reverse=True):
        if score >= threshold:
            return name
    return "info"


def _parse_advisory(raw: dict) -> Advisory:
    ranges = tuple(
        VersionRange(introduced=str(r.get("introduced", "0")), fixed=r.get("fixed"))
        for r in raw.get("affected_ranges", [])
    )
    return Advisory(
        id=raw["id"],
        package=raw["package"],
        cve=raw.get("cve"),
        aliases=tuple(raw.get("aliases") or ()),
        ranges=ranges,
        fixed_in=raw.get("fixed_in"),
        cvss_score=raw.get("cvss_score"),
        cvss_vector=raw.get("cvss_vector"),
        severity_override=raw.get("severity_override"),
        exploited_in_the_wild=bool(raw.get("exploited_in_the_wild", False)),
        aggregate=bool(raw.get("aggregate", False)),
        title=raw.get("title", raw["id"]),
        detail=raw.get("detail", ""),
        refs=tuple(raw.get("refs") or ()),
        deprecated=_deprecated(raw.get("deprecated")),
        superseded_by=_id_list(raw.get("superseded_by")),
        symbols=_id_list(raw.get("symbols")),
    )


_FALSY_STRINGS = {"", "false", "no", "0", "none", "null"}


def _deprecated(value) -> str | None:
    """`"2026-11-19"` -> the date; a bare `true` -> "yes"; absent, false or a
    falsy spelling ("false", "no", "0") -> None, so a hand edit cannot
    deprecate an entry by accident."""
    if value is True:
        return "yes"
    if not value or (isinstance(value, str) and value.strip().lower() in _FALSY_STRINGS):
        return None
    return str(value)


def _id_list(value) -> tuple[str, ...]:
    """A list of IDs; a single string is one ID, never split into characters."""
    if isinstance(value, str):
        value = [value]
    return tuple(str(v).strip() for v in value or () if str(v).strip())


def inherited_identifiers(db: AdvisoryDB) -> dict[str, tuple[str, ...]]:
    """Successor ID -> the identifiers of the deprecated entries it replaces.

    A finding for the successor also matches these, so an existing suppression
    of the old ID (or of an alias only the old entry carried) keeps working
    after the deprecation instead of surfacing a "new" finding for the same
    vulnerability. Identifiers the successor already has are not repeated.
    """
    by_id = {a.id: a for a in db.advisories}
    inherited: dict[str, list[str]] = {}
    for old in db.advisories:
        if not old.deprecated:
            continue
        for target in old.superseded_by:
            successor = by_id.get(target)
            if successor is None:
                continue
            seen = {x.upper() for x in (successor.id, successor.cve or "", *successor.aliases)}
            seen |= {x.upper() for x in inherited.get(target, [])}
            for ident in (old.id, old.cve or "", *old.aliases):
                if ident and ident.upper() not in seen:
                    inherited.setdefault(target, []).append(ident)
                    seen.add(ident.upper())
    return {target: tuple(ids) for target, ids in inherited.items()}


def load_db(path: Path | None = None) -> AdvisoryDB:
    return _load_db_cached(str(path or DATA_PATH))


@lru_cache(maxsize=8)
def _load_db_cached(path_str: str) -> AdvisoryDB:
    data = json.loads(Path(path_str).read_text(encoding="utf-8", errors="replace"))
    buckets = data.get("severity_buckets") or dict(DEFAULT_BUCKETS)
    advisories = tuple(_parse_advisory(a) for a in data.get("advisories", []))
    return AdvisoryDB(
        schema_version=data.get("schema_version", 1),
        updated=data.get("updated", "unknown"),
        buckets=buckets,
        advisories=advisories,
        container_images=_container_images(data.get("container_images")),
    )


def _container_images(raw) -> dict[str, str]:
    """`{"langflowai/langflow": "langflow"}`; absent or malformed -> empty."""
    if not isinstance(raw, dict):
        return {}
    return {str(image).lower(): str(package) for image, package in raw.items() if package}


def _to_version(value: str) -> Version | None:
    try:
        return Version(value)
    except (InvalidVersion, TypeError):
        return None


def matched_range(version_str: str, ranges: tuple[VersionRange, ...]) -> VersionRange | None:
    """Return the first range `[introduced, fixed)` that contains the version, else None."""
    v = _to_version(version_str)
    if v is None:
        return None
    for r in ranges:
        lo = _to_version(r.introduced) if r.introduced not in (None, "") else None
        hi = _to_version(r.fixed) if r.fixed else None
        if (lo is None or v >= lo) and (hi is None or v < hi):
            return r
    return None


def version_affected(version_str: str, ranges: tuple[VersionRange, ...]) -> bool:
    return matched_range(version_str, ranges) is not None
