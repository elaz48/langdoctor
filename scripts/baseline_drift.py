"""Aggregate-baseline drift detection against NVD — pure logic, no network.

An aggregate advisory (LD150: "Langflow older than the current secure
baseline") only protects users while its baseline sits at or above the fix of
every Langflow CVE langdoctor does not enumerate individually. It drifted twice:
1.10.1 in 0.1.4 and 1.11.0 in 0.1.6, both times because IBM PSIRT publishes
Langflow CVEs straight to NVD and OSV never indexes them. On 2026-11-18 none of
the 108 IBM-attributed Langflow CVEs published since 2026-08-20 were in OSV, so
an OSV/KEV-only watcher cannot see the drift at all.

This module decides, per NVD record, whether a CVE affects any version at or
above an aggregate's baseline. Version bounds come from NVD's analysed CPE
configuration when present and fall back to the CNA description — freshly
published CVEs sit in "Awaiting Analysis" with no CPE for days or weeks, which
is exactly when an alert is most useful.

The baseline itself is always read from advisories.json (the aggregate's
`affected_ranges`), so the data file stays the single source of truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

# Aggregate package -> NVD keywordSearch term. An aggregate missing here is
# reported by `baseline_targets` rather than silently left unwatched.
NVD_KEYWORDS = {"langflow": "langflow"}

# CVEs listed per aggregate in the issue body. GitHub rejects bodies over 65,536
# characters, and a long gap between runs once meant 145 drift CVEs; the rest
# are summarized, and the highest stated fix is computed over all of them.
MAX_LISTED = 40
_SUMMARY_CHARS = 200

# A version, keeping PEP 440-ish prerelease suffixes ("1.13.0-rc.1", "1.14.0b1"):
# truncating "through 1.13.0-rc.1" to 1.13.0 would invent drift.
# The suffix digit is optional ("1.13.0-dev" == 1.13.0.dev0), but the suffix must
# end the word, so "1.14.0-based" stays 1.14.0.
_VERSION = r"v?(\d+(?:\.\d+)+(?:[.-]?(?:rc|alpha|beta|a|b|dev|post)\.?\d*(?![a-z]))?)"
_LEAD = r"(?:langflow\s+)?(?:versions?\s+)?"
_DESCRIPTION_PATTERNS = (
    # "before 1.12.0", "Before Langflow 1.10.3", "Prior to 1.9.0", "until 1.10.1",
    # "before version 1.14.0", "< 1.14.0"
    ("fixed", re.compile(rf"\b(?:before|prior to|until|below|earlier than|lower than)\s+"
                         rf"{_LEAD}{_VERSION}", re.IGNORECASE)),
    ("fixed", re.compile(rf"(?<![<=])<(?!=)\s*{_VERSION}")),
    # "IBM Langflow OSS 1.0.0 through 1.11.1", "up to and including 1.2.3", "<= 1.14.0"
    ("through", re.compile(rf"\b(?:through|up to and including|up to)\s+{_LEAD}{_VERSION}",
                           re.IGNORECASE)),
    ("through", re.compile(rf"<=\s*{_VERSION}")),
    # "from 1.0.0 to 1.14.0" (bare "to" alone would misread "upgrade to 1.14.0")
    ("through", re.compile(rf"\bfrom\s+{_LEAD}v?\d+(?:\.\d+)+\S*\s+to\s+{_LEAD}{_VERSION}",
                           re.IGNORECASE)),
    # "1.14.0 and earlier", "1.14.0 or prior"
    ("through", re.compile(rf"\b{_VERSION}\s+(?:and|or)\s+(?:earlier|prior|below|lower)\b",
                           re.IGNORECASE)),
    # "langflow-ai langflow v1.9.3 is affected by: ..."
    ("affected", re.compile(rf"\b{_VERSION}\s+(?:is|are)\s+(?:affected|vulnerable)",
                            re.IGNORECASE)),
)
# GitHub-CNA boilerplate names the subject's fix in a sentence that often omits
# the product name: "This issue has been patched in version 1.9.0." / "Version
# 1.9.0 contains a patch for the issue." Both are anchored on that subject, so a
# dependency's fix ("the dependency foo was patched in 2.5.0") does not count.
_PATCHED_IN = (
    re.compile(rf"\b(?:this|the)\s+(?:issue|vulnerability|flaw|problem|bug)\s+"
               rf"(?:(?:has|have)\s+been|is|was|were)\s+(?:fixed|patched|resolved|addressed)"
               rf"\s+in\s+{_LEAD}{_VERSION}", re.IGNORECASE),
    re.compile(rf"\b(?:langflow|versions?)\s+(?:versions?\s+)?{_VERSION}\s+"
               rf"(?:contains|includes)\s+(?:a\s+)?(?:patch|fix)", re.IGNORECASE),
)
_ALL_VERSIONS = re.compile(r"\ball versions\b", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
# A description version only counts within this many characters of a product
# mention in the same sentence — "Langflow before 1.12.0 ... requires Python
# before 3.12" must not read 3.12 as a Langflow fix.
_PROXIMITY = 80
_UNVERSIONED = ("*", "-", "")
_MENTION = re.compile(r"(?<![\w.+-])@(?=\w)")   # "@alice", not "sec@langflow.org"
_ISSUE_REF = re.compile(r"(?<![\w&/])#(?=\d)")  # "#123" would cross-link an issue


@dataclass(frozen=True)
class Bound:
    """One statement about which versions a CVE affects.

    kind: "fixed" (first unaffected version), "through" (last affected
    version), "affected" (one affected version) or "unfixed" (every version).
    source: "cpe" (NVD analysis) or "description" (CNA prose).
    """

    kind: str
    version: str
    source: str


def _cve(record) -> dict:
    cve = record.get("cve") if isinstance(record, dict) else None
    return cve if isinstance(cve, dict) else {}


def _cpe_matches(cve: dict) -> list[dict]:
    matches = []
    for conf in cve.get("configurations") or []:
        if not isinstance(conf, dict):
            continue
        for node in conf.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            matches += [m for m in node.get("cpeMatch") or [] if isinstance(m, dict)]
    return matches


def _cpe_product_version(criteria: str) -> tuple[str, str]:
    parts = (criteria or "").split(":")
    if len(parts) < 6:
        return "", ""
    return parts[4].lower(), parts[5]


def cpe_bounds(record, product: str) -> list[Bound]:
    """Bounds from NVD's analysed CPE configuration for `product`."""
    bounds: list[Bound] = []
    for match in _cpe_matches(_cve(record)):
        if match.get("vulnerable") is not True:
            continue  # platform CPEs (OS, runtime) are context, not the target
        name, version = _cpe_product_version(match.get("criteria", ""))
        if name != product:
            continue
        if match.get("versionEndExcluding"):
            bounds.append(Bound("fixed", match["versionEndExcluding"], "cpe"))
        elif match.get("versionEndIncluding"):
            bounds.append(Bound("through", match["versionEndIncluding"], "cpe"))
        elif version not in _UNVERSIONED:
            bounds.append(Bound("affected", version, "cpe"))
        else:
            bounds.append(Bound("unfixed", "*", "cpe"))
    return bounds


def _description(cve: dict) -> str:
    for desc in cve.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return str(desc.get("value") or "")
    return ""


def _product_re(product: str) -> re.Pattern:
    return re.compile(rf"\b{re.escape(product)}\b", re.IGNORECASE)


def mentions_product(text: str, product: str) -> bool:
    return bool(_product_re(product).search(text or ""))


def _near_product(sentence: str, span: tuple[int, int], product_re: re.Pattern) -> bool:
    start, end = span
    window = sentence[max(0, start - _PROXIMITY): end + _PROXIMITY]
    return bool(product_re.search(window))


def description_bounds(record, product: str) -> list[Bound]:
    """Bounds parsed from the CNA description (fallback for CPE-less records).

    Only sentences that name the product are read, and only versions within
    `_PROXIMITY` characters of that name count — prose routinely cites
    dependency versions ("requires Python before 3.12") that are not ours.
    """
    product_re = _product_re(product)
    text = _description(_cve(record))
    if not product_re.search(text):
        return []
    found: list[tuple[str, str]] = []
    for sentence in _SENTENCE_END.split(text):
        for pattern in _PATCHED_IN:  # CNA boilerplate: the subject's own fix
            found += [("fixed", m.group(1)) for m in pattern.finditer(sentence)]
        if not product_re.search(sentence):
            continue
        if _ALL_VERSIONS.search(sentence):
            found.append(("unfixed", "*"))
        for kind, pattern in _DESCRIPTION_PATTERNS:
            for match in pattern.finditer(sentence):
                if _near_product(sentence, match.span(), product_re):
                    found.append((kind, match.group(1)))
    bounds = [Bound(k, v, "description") for k, v in dict.fromkeys(found)]
    # "1.0.0 through 1.11.1 is vulnerable" also reads as "1.11.1 is vulnerable";
    # the range statement already says it, so drop the redundant point.
    ranged = {b.version for b in bounds if b.kind != "affected"}
    return [b for b in bounds if b.kind != "affected" or b.version not in ranged]


def has_vulnerable_cpe(record) -> bool:
    return any(m.get("vulnerable") is True for m in _cpe_matches(_cve(record)))


def version_bounds(record, product: str) -> list[Bound]:
    """CPE bounds when NVD has analysed the record, else the description's.

    A record whose vulnerable CPEs all name another product is not ours (a
    keyword hit elsewhere), so the description is not consulted for it.
    """
    bounds = cpe_bounds(record, product)
    if bounds or has_vulnerable_cpe(record):
        return bounds
    return description_bounds(record, product)


def _version(value: str) -> Version | None:
    try:
        return Version(value)
    except (InvalidVersion, TypeError):
        return None


def _drifts(bound: Bound, baseline: Version) -> bool:
    if bound.kind in ("unfixed", "unparsed"):
        return True
    version = _version(bound.version)
    if version is None:
        return False
    if bound.kind == "fixed":
        return version > baseline  # the baseline itself is still affected
    return version >= baseline  # "through" / "affected": that version is affected


def drifting_bound(bounds: list[Bound], baseline: str) -> Bound | None:
    """The strongest bound putting a version at/above `baseline` in scope."""
    floor = _version(baseline)
    if floor is None:
        return None
    offending = [b for b in bounds if _drifts(b, floor)]
    if not offending:
        return None
    for kind in ("unfixed", "unparsed"):
        if any(b.kind == kind for b in offending):
            return next(b for b in offending if b.kind == kind)
    return max(offending, key=lambda b: _version(b.version))


def baseline_of(adv) -> str | None:
    """The aggregate's baseline: the highest `fixed` bound of its ranges."""
    fixes = [r.fixed for r in adv.ranges if r.fixed and _version(r.fixed)]
    if fixes:
        return max(fixes, key=_version)
    return adv.fixed_in


def baseline_targets(db) -> tuple[list[tuple[object, str]], list[object]]:
    """(aggregate, NVD keyword) pairs to check, plus aggregates with no keyword."""
    watched, unmapped = [], []
    for adv in db.advisories:
        if not getattr(adv, "aggregate", False) or getattr(adv, "deprecated", None):
            continue  # a deprecated aggregate never fires, so its drift is noise
        keyword = NVD_KEYWORDS.get(adv.package)
        if keyword:
            watched.append((adv, keyword))
        else:
            unmapped.append(adv)
    return watched, unmapped


def _cvss(cve: dict) -> float | None:
    scores = []
    metrics_by_type = cve.get("metrics")
    if not isinstance(metrics_by_type, dict):
        return None
    for metrics in metrics_by_type.values():
        for metric in metrics if isinstance(metrics, list) else []:
            data = metric.get("cvssData") if isinstance(metric, dict) else None
            if isinstance(data, dict) and isinstance(data.get("baseScore"), (int, float)):
                scores.append(float(data["baseScore"]))
    return max(scores) if scores else None


def _unanalysed_mention(record, product: str) -> bool:
    return not has_vulnerable_cpe(record) and mentions_product(
        _description(_cve(record)), product
    )


def _sort_key(entry: dict):
    """Unfixed first, then highest offending version, then most severe."""
    version = _version(entry["version"]) or Version("0")
    cvss = entry["cvss"] if entry["cvss"] is not None else -1.0
    return (entry["bound"] == "unfixed", version, cvss, entry["id"])


def baseline_drift(nvd_records, adv, covered: set[str]) -> list[dict]:
    """NVD CVEs affecting a version at/above `adv`'s baseline, not yet covered.

    `covered` holds upper-cased identifiers (shipped advisories + ignore list):
    a CVE langdoctor already enumerates individually fires on its own, so it
    is not drift even when its fix sits above the aggregate's baseline.
    """
    baseline = baseline_of(adv)
    if not baseline:
        return []
    covered_upper = {c.upper() for c in covered}
    out, seen = [], set()
    for record in nvd_records or []:
        cve = _cve(record)
        cve_id = str(cve.get("id") or "")
        if not cve_id or cve_id.upper() in covered_upper or cve_id in seen:
            continue
        if cve.get("vulnStatus") == "Rejected":
            continue
        bounds = version_bounds(record, adv.package)
        if not bounds and _unanalysed_mention(record, adv.package):
            # No CPE yet and no version we can read: a human has to look. A
            # watcher that drops what it cannot parse defeats its purpose.
            bounds = [Bound("unparsed", "?", "description")]
        bound = drifting_bound(bounds, baseline)
        if bound is None:
            continue
        seen.add(cve_id)
        out.append({
            "id": cve_id,
            "advisory": adv.id,
            "package": adv.package,
            "baseline": baseline,
            "bound": bound.kind,
            "version": bound.version,
            "source": bound.source,
            "cvss": _cvss(cve),
            "published": str(cve.get("published") or "")[:10],
            "summary": " ".join(_description(cve).split())[:300],
        })
    return sorted(out, key=_sort_key, reverse=True)


_BOUND_TEXT = {
    "fixed": "fixed in {v}",
    "through": "affected through {v}",
    "affected": "{v} affected",
    "unfixed": "no fixed version",
    "unparsed": "no version bound in the NVD record yet — check manually",
}


def _highest(entries: list[dict], kinds: tuple[str, ...]) -> str | None:
    versions = [e["version"] for e in entries if e["bound"] in kinds and _version(e["version"])]
    return max(versions, key=_version) if versions else None


def _suggestion(entries: list[dict]) -> str:
    parts = []
    fix = _highest(entries, ("fixed",))
    if fix:
        parts.append(f"highest stated fix: **{fix}**")
    last_affected = _highest(entries, ("through", "affected"))
    if last_affected:
        parts.append(f"some CVEs affect versions through {last_affected}, so the new "
                     f"baseline must be above {last_affected}")
    unknown = sum(1 for e in entries if e["bound"] in ("unfixed", "unparsed"))
    if unknown:
        parts.append(f"{unknown} CVE(s) state no usable fix version — check the "
                     "vendor advisory before choosing the new baseline")
    return "; ".join(parts)


def no_mentions(text: str) -> str:
    """Neutralise @mentions and #refs: NVD/OSV prose is pasted into a GitHub
    issue, where "@someone" notifies a stranger and "#123" cross-links an issue.
    A zero-width space breaks both; e-mail addresses are left intact."""
    return _ISSUE_REF.sub("#\u200b", _MENTION.sub("@\u200b", text or ""))


def render_drift(drift: list[dict]) -> list[str]:
    """Markdown lines for the watch issue (empty when there is no drift)."""
    lines: list[str] = []
    for advisory in dict.fromkeys(e["advisory"] for e in drift):
        entries = [e for e in drift if e["advisory"] == advisory]
        first = entries[0]
        lines += [
            f"## ⚠️ Baseline drift — `{advisory}` (`{first['package']}` < {first['baseline']})",
            "",
            f"NVD lists CVEs that affect `{first['package']}` at or above this "
            "aggregate's baseline and have no advisory of their own, so an install "
            "on the baseline scans clean while still vulnerable. Raise the baseline "
            f"(`affected_ranges`, `fixed_in`, title and detail of `{advisory}` in "
            "`advisories.json`) or add individual entries — "
            f"{_suggestion(entries)}.",
            "",
        ]
        for e in entries[:MAX_LISTED]:
            cvss = f" · CVSS {e['cvss']:g}" if e["cvss"] is not None else ""
            when = f" · published {e['published']}" if e["published"] else ""
            bound = _BOUND_TEXT[e["bound"]].format(v=e["version"])
            lines.append(f"- `{e['id']}`{cvss} · {bound} ({e['source']}){when}")
            if e["summary"]:
                summary = no_mentions(e["summary"])
                if len(summary) > _SUMMARY_CHARS:
                    summary = summary[:_SUMMARY_CHARS].rstrip() + "…"
                lines.append(f"  - {summary}")
        hidden = len(entries) - MAX_LISTED
        if hidden > 0:
            lines.append(f"- …and {hidden} more (search NVD for `{first['package']}`).")
        lines.append("")
    return lines
