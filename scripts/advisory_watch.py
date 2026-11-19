"""Weekly advisory watcher — flags advisories not yet in advisories.json.

Three independent sources, because one is not enough (see CLAUDE.md,
"Verification discipline"):

1. **OSV.dev** — queried per covered package; the broad, structured baseline.
2. **CISA KEV** — the known-exploited catalog, filtered to our ecosystem.
3. **NVD** — checked only for *baseline drift* of aggregate advisories (LD150):
   a CVE that affects a version at or above the aggregate's baseline and has
   no advisory of its own means a project on the baseline scans clean while
   vulnerable. See `baseline_drift.py`.

KEV exists because OSV *lags*. CVE-2026-9198 (LD124) was a CVSS 9.8
unauthenticated Langflow RCE on the KEV list with a three-day federal
remediation deadline, and OSV had no record of it at all — an OSV-only watcher
reported "0 new" for weeks. KEV is the highest-signal feed langdoctor consumes:
a KEV entry we do not cover is invisible exactly where the tool sorts loudest.

NVD exists because OSV does not index IBM PSIRT's Langflow CVEs at all. LD150
drifted twice (0.1.4, 0.1.6) while the watcher reported nothing.

Results are diffed against the IDs + aliases already in the advisory DB and
written to `advisory-report.md` for the workflow to open as an issue.

Design notes:
- The comparisons are pure (`uncovered_advisories`, `uncovered_kev`,
  `covered_identifiers`, `baseline_drift.baseline_drift`) and unit-tested
  without any network access.
- Network is isolated in `fetch_osv` / `fetch_kev` / `fetch_nvd`, which never
  raise — on any API hiccup they log a warning and return None so the run still
  exits 0. If *every* query fails, nothing is reported and no spurious issue
  opens.
- The sources fail independently: one outage never suppresses another
  source's report, and a failed source keeps its previous state baseline.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import baseline_drift as bd

OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000      # NVD's maximum; ~240 Langflow CVEs today = one page
NVD_MAX_PAGES = 10        # hard stop: a runaway pager must not loop forever
NVD_PAGE_DELAY_S = 6      # NVD's guidance for unauthenticated clients
NVD_ATTEMPTS = 3          # per page; NVD answers 503 / rate limits often
NVD_RETRY_DELAY_S = 15    # x attempt number
NVD_DEADLINE_S = 300      # whole-fetch budget; the job also has timeout-minutes
_NVD_RETRYABLE = {403, 429, 500, 502, 503, 504}  # NVD rate-limits with 403

# A KEV entry is "ours" when any of these appears in its vendor/product/name.
# Deliberately broad: a false positive costs one line in an issue, a false
# negative costs a known-exploited RCE nobody is told about.
KEV_KEYWORDS = ("langflow", "langchain", "langgraph")

_HERE = Path(__file__).resolve().parent
IGNORE_PATH = _HERE / "watch-ignore.json"          # out-of-scope advisories (never alerted)
STATE_PATH = _HERE.parent / ".watch-state.json"    # committed delta state (known-uncovered)

_STATE_OSV_KEY = "known_uncovered"
_STATE_KEV_KEY = "known_uncovered_kev"
_STATE_DRIFT_KEY = "known_baseline_drift"

# Packages langdoctor ships advisories for (plus close ecosystem siblings).
PACKAGES = [
    "langgraph",
    "langgraph-sdk",
    "langgraph-checkpoint",
    "langgraph-checkpoint-sqlite",
    "langgraph-checkpoint-redis",
    "langgraph-checkpoint-postgres",
    "langchain-core",
    "langchain",
    "langchain-community",
    "langchain-classic",
    # Partner packages, in scope since advisories already tracked for another
    # package turned out to live in them (LD134/LD136, LD135).
    "langchain-openai",
    "langchain-anthropic",
    "langflow",
    "langflow-base",
]


def _norm(identifier: str) -> str:
    return identifier.strip().upper()


def covered_identifiers(db) -> set[str]:
    """Every identifier we already cover: LD id, primary CVE, and all aliases."""
    covered: set[str] = set()
    for adv in db.advisories:
        covered.add(_norm(adv.id))
        if adv.cve:
            covered.add(_norm(adv.cve))
        for alias in adv.aliases:
            covered.add(_norm(alias))
    return covered


def vuln_identifiers(vuln: dict) -> set[str]:
    """Every identifier an OSV record is known by (its id + aliases)."""
    ids: set[str] = set()
    if vuln.get("id"):
        ids.add(_norm(vuln["id"]))
    for alias in vuln.get("aliases") or []:
        ids.add(_norm(alias))
    return ids


def _fixed_versions(vuln: dict) -> set[str]:
    fixes: set[str] = set()
    for affected in _affected_entries(vuln):
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    fixes.add(event["fixed"])
    return fixes


def _affected_packages(vuln: dict, queried: str) -> list[str]:
    """Every package an OSV record names, falling back to the one we queried.

    One GHSA often spans several packages with different fix versions (e.g.
    GHSA-6hmw: sqlite 3.1.2, postgres 3.1.3); naming only the queried package
    hides the others from whoever triages the issue.
    """
    names = {
        affected["package"].get("name")
        for affected in _affected_entries(vuln)
        if isinstance(affected.get("package"), dict)
    }
    return sorted(n for n in names if isinstance(n, str) and n) or [queried]


def _affected_entries(vuln: dict) -> list[dict]:
    """The record's `affected` rows, skipping junk so one bad row cannot abort
    the whole report (the run would then exit 0 without updating state)."""
    return [a for a in vuln.get("affected") or [] if isinstance(a, dict)]


def uncovered_advisories(osv_by_package: dict, covered: set[str]) -> list[dict]:
    """Pure diff: OSV advisories with NO identifier in `covered`, deduped by id.

    A vuln is considered covered if ANY of its identifiers (OSV id or any alias)
    matches one we already track — so a CVE we list under its GHSA still counts.
    `package` is the watched package that returned the record; `packages` is
    every package the record itself names.
    """
    seen: set[str] = set()
    out: list[dict] = []
    for package, vulns in osv_by_package.items():
        for vuln in vulns or []:
            vids = vuln_identifiers(vuln)
            if vids & covered:
                continue
            key = vuln.get("id") or ";".join(sorted(vids))
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "package": package,
                    "packages": _affected_packages(vuln, package),
                    "id": vuln.get("id"),
                    "aliases": sorted(a for a in (vuln.get("aliases") or [])),
                    "summary": (vuln.get("summary") or "").strip(),
                    "fixed": sorted(_fixed_versions(vuln)),
                }
            )
    return out


def kev_is_ours(entry: dict, keywords=KEV_KEYWORDS) -> bool:
    """Does this KEV catalog entry belong to the ecosystem langdoctor covers?"""
    haystack = " ".join(
        str(entry.get(k) or "")
        for k in ("vendorProject", "product", "vulnerabilityName")
    ).lower()
    return any(k in haystack for k in keywords)


def uncovered_kev(kev_vulns, covered: set[str], keywords=KEV_KEYWORDS) -> list[dict]:
    """Pure diff: KEV entries in our ecosystem whose CVE we do not already cover.

    Shaped like `uncovered_advisories` (an "id" key) so the delta-state and
    report helpers work on either source without special-casing.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for entry in kev_vulns or []:
        cve = _norm(entry.get("cveID") or "")
        if not cve or cve in seen or cve in covered:
            continue
        if not kev_is_ours(entry, keywords):
            continue
        seen.add(cve)
        out.append(
            {
                "id": entry.get("cveID"),
                "product": f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip(),
                "name": (entry.get("vulnerabilityName") or "").strip(),
                "summary": (entry.get("shortDescription") or "").strip(),
                "date_added": entry.get("dateAdded") or "",
                "due_date": entry.get("dueDate") or "",
                "ransomware": entry.get("knownRansomwareCampaignUse") or "Unknown",
            }
        )
    return sorted(out, key=lambda u: (u["date_added"], u["id"] or ""))


def load_ignore(path) -> set[str]:
    """Out-of-scope advisory identifiers that are never alerted (wontfix)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {_norm(k) for k in (data.get("ignore") or {})}


def _read_state(path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def load_state(path) -> set[str]:
    """OSV identifiers already known-uncovered as of the last run (delta baseline)."""
    return {_norm(x) for x in (_read_state(path).get(_STATE_OSV_KEY) or [])}


def load_kev_state(path) -> set[str]:
    """KEV CVEs already known-uncovered as of the last run."""
    return {_norm(x) for x in (_read_state(path).get(_STATE_KEV_KEY) or [])}


def load_drift_state(path) -> set[str]:
    """NVD baseline-drift CVEs already alerted as of the last run."""
    return {_norm(x) for x in (_read_state(path).get(_STATE_DRIFT_KEY) or [])}


def save_state(path, ids=None, kev_ids=None, drift_ids=None) -> None:
    """Write every delta. A source passed as None keeps exactly what is on disk,
    so a fetch failure neither drops its baseline (which would re-alert every
    known advisory next week) nor rewrites its entries."""
    current = _read_state(path)
    if ids is None:
        ids = current.get(_STATE_OSV_KEY) or []
    if kev_ids is None:
        kev_ids = current.get(_STATE_KEV_KEY) or []
    if drift_ids is None:
        drift_ids = current.get(_STATE_DRIFT_KEY) or []
    payload = {
        _STATE_OSV_KEY: sorted(ids),
        _STATE_KEV_KEY: sorted(kev_ids),
        _STATE_DRIFT_KEY: sorted(drift_ids),
    }
    Path(path).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def _identifiers(u: dict) -> set[str]:
    """Primary id plus aliases of an uncovered entry (KEV entries have no aliases)."""
    return {x for x in [u.get("id"), *(u.get("aliases") or [])] if x}


def advisory_ids(uncovered: list[dict]) -> list[str]:
    """Every identifier of the uncovered set, for the delta state.

    Aliases are stored too: OSV often publishes a GHSA and its PYSEC twin weeks
    apart, and a GHSA record rarely aliases its PYSEC — so remembering only the
    primary id would re-alert the same advisory under its other name.
    """
    return sorted(set().union(*(_identifiers(u) for u in uncovered)))


def new_advisories(uncovered: list[dict], known: set[str]) -> list[dict]:
    """Uncovered advisories not known last run under ANY of their identifiers.

    Matching on the primary id alone re-alerted ten Langflow GHSAs on
    2026-10-19 when OSV published their PYSEC records.
    """
    known_upper = {_norm(k) for k in known}
    return [
        u
        for u in uncovered
        if u.get("id") and not ({_norm(x) for x in _identifiers(u)} & known_upper)
    ]


def render_issue(
    uncovered: list[dict], kev: list[dict] | None = None, drift: list[dict] | None = None
) -> str:
    """Issue body: KEV first, then aggregate-baseline drift, then plain OSV."""
    lines: list[str] = []

    # KEV first and unmissable: known-exploited beats anything merely published.
    if kev:
        lines += [
            "## 🔴 CISA KEV — known-exploited and NOT covered",
            "",
            "These are on the CISA Known Exploited Vulnerabilities catalog and have "
            "no matching entry in `advisories.json`. Treat as drop-everything work: "
            "langdoctor sorts KEV findings above all others, so a gap here is "
            "invisible exactly where it matters most.",
            "",
        ]
        for u in kev:
            added = f" · KEV since {u['date_added']}" if u["date_added"] else ""
            due = f" · due {u['due_date']}" if u["due_date"] else ""
            ransom = " · ⚠️ ransomware" if u["ransomware"].lower() == "known" else ""
            product = bd.no_mentions(u["product"])
            lines.append(f"- **{product}** — `{u['id']}`{added}{due}{ransom}")
            if u["name"]:
                lines.append(f"  - {bd.no_mentions(u['name'])}")
            if u["summary"]:
                lines.append(f"  - {bd.no_mentions(u['summary'])}")
        lines.append("")

    # Drift next: an aggregate gone stale silently clears whole version lines.
    if drift:
        lines += bd.render_drift(drift)

    if uncovered:
        if kev or drift:
            lines += ["## OSV — published but not covered", ""]
        lines += [
            "The advisory watcher found OSV advisories for covered packages that are "
            "**not yet in `advisories.json`**:",
            "",
        ]
        for u in uncovered:
            ident = u["id"] or "(no id)"
            alias = f" · aliases: {', '.join(u['aliases'])}" if u["aliases"] else ""
            fixed = f" · fixed in: {', '.join(u['fixed'])}" if u["fixed"] else ""
            pkgs = ", ".join(f"**{p}**" for p in u.get("packages") or [u["package"]])
            lines.append(f"- {pkgs} — `{ident}`{alias}{fixed}")
            if u["summary"]:
                lines.append(f"  - {bd.no_mentions(u['summary'])}")

    lines += [
        "",
        "For each real advisory, add an `LD1xx` entry (with a vulnerable/clean "
        "fixture pair) and cut a patch release — see `CLAUDE.md`. Cross-check "
        "≥2 sources and pull CVSS base scores from NVD.",
        "",
        "_Opened automatically by `.github/workflows/advisory-watch.yml`._",
    ]
    return "\n".join(lines)


def fetch_osv(package: str) -> list | None:
    """Query OSV for a PyPI package. Returns the vuln list, or None on any error."""
    body = json.dumps({"package": {"name": package, "ecosystem": "PyPI"}}).encode()
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "langdoctor-advisory-watch"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp).get("vulns") or []
    except Exception as exc:  # noqa: BLE001 - never fail the build on API hiccups
        print(f"::warning::OSV query failed for {package}: {exc}", file=sys.stderr)
        return None


def fetch_kev() -> list | None:
    """Fetch the CISA KEV catalog. Returns its vulnerability list, or None on error."""
    req = urllib.request.Request(
        KEV_URL, headers={"User-Agent": "langdoctor-advisory-watch"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp).get("vulnerabilities") or []
    except Exception as exc:  # noqa: BLE001 - never fail the build on API hiccups
        print(f"::warning::CISA KEV fetch failed: {exc}", file=sys.stderr)
        return None


def fetch_nvd(keyword: str) -> list | None:
    """Every NVD CVE record matching `keyword`, or None on any error.

    Partial data is treated as failure (None), so a broken page never rewrites
    the drift state. Unauthenticated NVD access allows 5 requests per 30 s; an
    optional NVD_API_KEY raises that, but one weekly query is normally one page.
    """
    headers = {"User-Agent": "langdoctor-advisory-watch"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    records: list = []
    deadline = time.monotonic() + NVD_DEADLINE_S
    try:
        for page_no in range(NVD_MAX_PAGES):
            if time.monotonic() > deadline:
                raise RuntimeError(f"time budget of {NVD_DEADLINE_S}s spent")
            if page_no:
                time.sleep(NVD_PAGE_DELAY_S)
            query = urllib.parse.urlencode({
                "keywordSearch": keyword,
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": len(records),
            })
            page = _nvd_page(f"{NVD_URL}?{query}", headers, deadline)
            # A 200 without the results schema (an error body, a proxy page)
            # must not read as "0 CVEs" and empty the drift state.
            batch = page.get("vulnerabilities") if isinstance(page, dict) else None
            total = page.get("totalResults") if isinstance(page, dict) else None
            if not isinstance(batch, list) or not isinstance(total, int):
                raise RuntimeError("unexpected NVD reply (no totalResults/vulnerabilities)")
            records += batch
            if len(records) >= total:
                return records
            if not batch:  # short of the total: partial data is failure
                raise RuntimeError(f"empty page at {len(records)}/{total} records")
        raise RuntimeError(f"more than {NVD_MAX_PAGES} pages")
    except Exception as exc:  # noqa: BLE001 - never fail the build on API hiccups
        print(f"::warning::NVD query failed for {keyword!r}: {exc}", file=sys.stderr)
        return None


def _nvd_page(url: str, headers: dict, deadline: float) -> dict:
    """One NVD page, retrying transient errors with a growing delay.

    Transient = a retryable HTTP status, or the connection failing mid-way
    (reset, timeout, truncated body, undecodable JSON). The retry never sleeps
    past the fetch's overall deadline.
    """
    for attempt in range(1, NVD_ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code not in _NVD_RETRYABLE or attempt == NVD_ATTEMPTS:
                raise
        except (OSError, http.client.HTTPException, json.JSONDecodeError):
            if attempt == NVD_ATTEMPTS:
                raise
        delay = NVD_RETRY_DELAY_S * attempt
        if time.monotonic() + delay > deadline:
            raise RuntimeError(f"time budget of {NVD_DEADLINE_S}s spent while retrying")
        time.sleep(delay)
    raise RuntimeError("unreachable")


def _set_output(name: str, value: str) -> None:
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


# Each source returns (new entries to report, ids for the state file). The ids
# are None when the source failed, which keeps its previous baseline untouched.


def _run_kev(covered: set[str]) -> tuple[list[dict], list[str] | None]:
    kev_vulns = fetch_kev()
    if kev_vulns is None:
        print("::warning::KEV unavailable this run; the other sources continue")
        return [], None
    found = uncovered_kev(kev_vulns, covered)
    new = new_advisories(found, load_kev_state(STATE_PATH))
    print(f"{len(found)} uncovered KEV entries; {len(new)} new since last run")
    for u in new:
        print(f"::warning::uncovered KEV entry {u['id']} ({u['product']})")
    return new, advisory_ids(found)


def _run_drift(db, covered: set[str]) -> tuple[list[dict], list[str] | None]:
    watched, unmapped = bd.baseline_targets(db)
    for adv in unmapped:
        print(f"::warning::aggregate {adv.id} ({adv.package}) has no NVD keyword in "
              "baseline_drift.NVD_KEYWORDS; its baseline drift is not checked")
    if not watched:
        return [], None
    found: list[dict] = []
    for adv, keyword in watched:
        records = fetch_nvd(keyword)
        if records is None:  # all-or-nothing, like OSV: partial data never saves
            print("::warning::NVD unavailable this run; baseline-drift check skipped")
            return [], None
        if not records:
            # Every aggregate exists because of a long CVE history (~240 for
            # langflow); zero records is an outage, not good news.
            print(f"::warning::NVD returned no records for {keyword!r}; "
                  "treated as an outage, baseline-drift check skipped")
            return [], None
        found += bd.baseline_drift(records, adv, covered)
    new = new_advisories(found, load_drift_state(STATE_PATH))
    print(f"{len(found)} baseline-drift CVEs; {len(new)} new since last run")
    for e in new:
        print(f"::warning::baseline drift: {e['id']} affects {e['package']} "
              f">= {e['baseline']} ({e['advisory']})")
    return new, advisory_ids(found)


def _run_osv(covered: set[str]) -> tuple[list[dict], list[str] | None]:
    osv_by_package: dict = {}
    for package in PACKAGES:
        result = fetch_osv(package)
        if result is None:
            # On partial data do NOT diff or rewrite the OSV state — a transient
            # outage must never drop known advisories or emit false alerts.
            print(f"::warning::OSV query failed for {package}; "
                  "skipping OSV report and state update this run")
            return [], None
        osv_by_package[package] = result
    found = uncovered_advisories(osv_by_package, covered)
    new = new_advisories(found, load_state(STATE_PATH))
    print(f"{len(found)} uncovered advisories; {len(new)} new since last run")
    return new, advisory_ids(found)


def _isolated(name: str, run, *args) -> tuple[list[dict], list[str] | None]:
    """Run one source; an unexpected error there must not lose the others."""
    try:
        return run(*args)
    except Exception as exc:  # noqa: BLE001 - one broken source is non-fatal
        print(f"::warning::{name} source failed (non-fatal): {exc}", file=sys.stderr)
        return [], None


def _render_report(new_osv: list[dict], new_kev: list[dict], new_drift: list[dict]) -> str:
    """The issue body; if the drift section cannot render, list its CVE ids so
    the KEV/OSV findings and the drift alert still reach the issue."""
    try:
        return render_issue(new_osv, new_kev, new_drift)
    except Exception as exc:  # noqa: BLE001 - a render bug must not lose the report
        print(f"::warning::drift section failed to render (non-fatal): {exc}", file=sys.stderr)
        ids = "\n".join(f"- `{e.get('id')}`" for e in new_drift)
        fallback = f"## ⚠️ Baseline drift (details failed to render)\n\n{ids}\n\n"
        return fallback + render_issue(new_osv, new_kev)


def main() -> int:
    from langdoctor.advisories import load_db

    db = load_db()
    # Covered = shipped advisories + explicitly out-of-scope (ignored) identifiers.
    covered = covered_identifiers(db) | load_ignore(IGNORE_PATH)

    new_kev, kev_ids = _isolated("KEV", _run_kev, covered)
    new_drift, drift_ids = _isolated("NVD baseline drift", _run_drift, db, covered)
    new_osv, osv_ids = _isolated("OSV", _run_osv, covered)

    has_news = new_osv or new_kev or new_drift
    with open("advisory-report.md", "w", encoding="utf-8") as fh:
        fh.write(_render_report(new_osv, new_kev, new_drift) if has_news else "")

    # State mirrors the current sets: newly-seen entries stop re-alerting, and
    # anything we later cover (or a baseline bump) drops out naturally.
    if any(ids is not None for ids in (osv_ids, kev_ids, drift_ids)):
        save_state(STATE_PATH, osv_ids, kev_ids, drift_ids)
    _set_output("new_count", str(len(new_osv) + len(new_kev) + len(new_drift)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - watcher must never fail the workflow
        print(f"::warning::advisory watcher error (non-fatal): {exc}", file=sys.stderr)
        raise SystemExit(0) from None
