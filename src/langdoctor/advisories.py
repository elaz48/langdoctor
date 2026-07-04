"""Load and interpret the advisory database (advisories.json, schema v2).

Advisories are DATA, not code. This module is the only place that knows the
JSON shape: it parses it into typed objects, derives severity from CVSS, and
answers version-applicability questions via OSV-style affected_ranges.
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

    def severity(self, buckets: dict[str, float] | None = None) -> str:
        return derive_severity(self.cvss_score, self.severity_override, buckets or DEFAULT_BUCKETS)


@dataclass
class AdvisoryDB:
    schema_version: int
    updated: str
    buckets: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_BUCKETS))
    advisories: tuple[Advisory, ...] = ()


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
    )


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
    )


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
