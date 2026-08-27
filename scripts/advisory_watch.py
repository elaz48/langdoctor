"""Weekly advisory watcher — flags advisories not yet in advisories.json.

Two independent sources, because one is not enough (see CLAUDE.md, "Verification
discipline"):

1. **OSV.dev** — queried per covered package; the broad, structured baseline.
2. **CISA KEV** — the known-exploited catalog, filtered to our ecosystem.

The second source exists because OSV *lags*. CVE-2026-9198 (LD124) was a
CVSS 9.8 unauthenticated Langflow RCE on the KEV list with a three-day federal
remediation deadline, and OSV had no record of it at all — an OSV-only watcher
reported "0 new" for weeks. KEV is the highest-signal feed langdoctor consumes:
a KEV entry we do not cover is invisible exactly where the tool sorts loudest.

Results from both are diffed against the IDs + aliases already in the advisory
DB and written to `advisory-report.md` for the workflow to open as an issue.

Design notes:
- The comparisons are pure (`uncovered_advisories`, `uncovered_kev`,
  `covered_identifiers`) and unit-tested without any network access.
- Network is isolated in `fetch_osv` / `fetch_kev`, which never raise — on any
  API hiccup they log a warning and return None so the run still exits 0. If
  *every* query fails, the uncovered list is empty and no spurious issue opens.
- The two sources fail independently: a KEV outage must not suppress the OSV
  report, and vice versa.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# A KEV entry is "ours" when any of these appears in its vendor/product/name.
# Deliberately broad: a false positive costs one line in an issue, a false
# negative costs a known-exploited RCE nobody is told about.
KEV_KEYWORDS = ("langflow", "langchain", "langgraph")

_HERE = Path(__file__).resolve().parent
IGNORE_PATH = _HERE / "watch-ignore.json"          # out-of-scope advisories (never alerted)
STATE_PATH = _HERE.parent / ".watch-state.json"    # committed delta state (known-uncovered)

_STATE_OSV_KEY = "known_uncovered"
_STATE_KEV_KEY = "known_uncovered_kev"

# Packages langdoctor ships advisories for (plus close ecosystem siblings).
PACKAGES = [
    "langgraph",
    "langgraph-checkpoint",
    "langgraph-checkpoint-sqlite",
    "langgraph-checkpoint-redis",
    "langgraph-checkpoint-postgres",
    "langchain-core",
    "langchain",
    "langchain-community",
    "langchain-classic",
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
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fixes.add(event["fixed"])
    return fixes


def uncovered_advisories(osv_by_package: dict, covered: set[str]) -> list[dict]:
    """Pure diff: OSV advisories with NO identifier in `covered`, deduped by id.

    A vuln is considered covered if ANY of its identifiers (OSV id or any alias)
    matches one we already track — so a CVE we list under its GHSA still counts.
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


def save_state(path, ids=None, kev_ids=None) -> None:
    """Write both deltas. A source passed as None keeps exactly what is on disk,
    so a fetch failure neither drops its baseline (which would re-alert every
    known advisory next week) nor rewrites its entries."""
    current = _read_state(path)
    if ids is None:
        ids = current.get(_STATE_OSV_KEY) or []
    if kev_ids is None:
        kev_ids = current.get(_STATE_KEV_KEY) or []
    payload = {_STATE_OSV_KEY: sorted(ids), _STATE_KEV_KEY: sorted(kev_ids)}
    Path(path).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def advisory_ids(uncovered: list[dict]) -> list[str]:
    return sorted({u["id"] for u in uncovered if u["id"]})


def new_advisories(uncovered: list[dict], known: set[str]) -> list[dict]:
    """Uncovered advisories whose id was not already known last run (the delta)."""
    known_upper = {_norm(k) for k in known}
    return [u for u in uncovered if u["id"] and _norm(u["id"]) not in known_upper]


def render_issue(uncovered: list[dict], kev: list[dict] | None = None) -> str:
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
            lines.append(f"- **{u['product']}** — `{u['id']}`{added}{due}{ransom}")
            if u["name"]:
                lines.append(f"  - {u['name']}")
            if u["summary"]:
                lines.append(f"  - {u['summary']}")
        lines.append("")

    if uncovered:
        if kev:
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
            lines.append(f"- **{u['package']}** — `{ident}`{alias}{fixed}")
            if u["summary"]:
                lines.append(f"  - {u['summary']}")

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


def _set_output(name: str, value: str) -> None:
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main() -> int:
    from langdoctor.advisories import load_db

    # Covered = shipped advisories + explicitly out-of-scope (ignored) identifiers.
    covered = covered_identifiers(load_db()) | load_ignore(IGNORE_PATH)

    # --- source 1: CISA KEV (independent of OSV; failure is isolated) -------
    new_kev: list[dict] = []
    kev_ids = None  # None => keep the state already on disk
    kev_vulns = fetch_kev()
    if kev_vulns is None:
        print("::warning::KEV unavailable this run; OSV diff continues")
    else:
        uncovered_kev_list = uncovered_kev(kev_vulns, covered)
        new_kev = new_advisories(uncovered_kev_list, load_kev_state(STATE_PATH))
        kev_ids = advisory_ids(uncovered_kev_list)
        print(
            f"{len(uncovered_kev_list)} uncovered KEV entries; "
            f"{len(new_kev)} new since last run"
        )
        for u in new_kev:
            print(f"::warning::uncovered KEV entry {u['id']} ({u['product']})")

    # --- source 2: OSV, per package ----------------------------------------
    osv_by_package: dict = {}
    errors = 0
    for package in PACKAGES:
        result = fetch_osv(package)
        if result is None:
            errors += 1
            continue
        osv_by_package[package] = result

    # On partial data (any query failed) do NOT diff or rewrite the OSV state — a
    # transient OSV outage must never drop known advisories or emit false alerts.
    # A KEV hit found above is still reported: it does not depend on OSV.
    new: list[dict] = []
    osv_ids = None
    if errors:
        print(
            f"::warning::{errors}/{len(PACKAGES)} OSV queries failed; "
            "skipping OSV report and state update this run"
        )
    else:
        uncovered = uncovered_advisories(osv_by_package, covered)
        new = new_advisories(uncovered, load_state(STATE_PATH))
        osv_ids = advisory_ids(uncovered)
        print(f"{len(uncovered)} uncovered advisories; {len(new)} new since last run")

    with open("advisory-report.md", "w", encoding="utf-8") as fh:
        fh.write(render_issue(new, new_kev) if (new or new_kev) else "")

    # State mirrors the current uncovered sets: newly-seen entries stop
    # re-alerting, and anything we later cover drops out naturally. A source
    # that failed passes None and keeps its previous baseline untouched.
    if osv_ids is not None or kev_ids is not None:
        save_state(STATE_PATH, osv_ids, kev_ids)
    _set_output("new_count", str(len(new) + len(new_kev)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - watcher must never fail the workflow
        print(f"::warning::advisory watcher error (non-fatal): {exc}", file=sys.stderr)
        raise SystemExit(0) from None
