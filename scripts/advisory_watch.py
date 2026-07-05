"""Weekly advisory watcher — flags OSV advisories not yet in advisories.json.

Queries OSV.dev for the packages langdoctor covers and diffs the results against
the IDs + aliases already in the advisory DB. Anything uncovered is written to
`advisory-report.md` for the workflow to open as an issue.

Design notes:
- The comparison is pure (`uncovered_advisories`, `covered_identifiers`) and
  unit-tested without any network access.
- Network is isolated in `fetch_osv`, which never raises — on any API hiccup it
  logs a warning and returns None so the run still exits 0. If *every* query
  fails, the uncovered list is empty and no spurious issue is opened.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/query"

_HERE = Path(__file__).resolve().parent
IGNORE_PATH = _HERE / "watch-ignore.json"          # out-of-scope advisories (never alerted)
STATE_PATH = _HERE.parent / ".watch-state.json"    # committed delta state (known-uncovered)

# Packages langdoctor ships advisories for (plus close ecosystem siblings).
PACKAGES = [
    "langgraph",
    "langgraph-checkpoint",
    "langgraph-checkpoint-sqlite",
    "langgraph-checkpoint-redis",
    "langgraph-checkpoint-postgres",
    "langchain-core",
    "langchain",
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


def load_ignore(path) -> set[str]:
    """Out-of-scope advisory identifiers that are never alerted (wontfix)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {_norm(k) for k in (data.get("ignore") or {})}


def load_state(path) -> set[str]:
    """Identifiers already known-uncovered as of the last run (delta baseline)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {_norm(x) for x in (data.get("known_uncovered") or [])}


def save_state(path, ids) -> None:
    Path(path).write_text(
        json.dumps({"known_uncovered": sorted(ids)}, indent=2) + "\n", encoding="utf-8"
    )


def advisory_ids(uncovered: list[dict]) -> list[str]:
    return sorted({u["id"] for u in uncovered if u["id"]})


def new_advisories(uncovered: list[dict], known: set[str]) -> list[dict]:
    """Uncovered advisories whose id was not already known last run (the delta)."""
    known_upper = {_norm(k) for k in known}
    return [u for u in uncovered if u["id"] and _norm(u["id"]) not in known_upper]


def render_issue(uncovered: list[dict]) -> str:
    lines = [
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
        "fixture pair) and cut a patch release — see `CLAUDE.md`.",
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


def _set_output(name: str, value: str) -> None:
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main() -> int:
    from langdoctor.advisories import load_db

    # Covered = shipped advisories + explicitly out-of-scope (ignored) identifiers.
    covered = covered_identifiers(load_db()) | load_ignore(IGNORE_PATH)
    known = load_state(STATE_PATH)

    osv_by_package: dict = {}
    errors = 0
    for package in PACKAGES:
        result = fetch_osv(package)
        if result is None:
            errors += 1
            continue
        osv_by_package[package] = result

    # On partial data (any query failed) do NOT report or rewrite state — a
    # transient OSV outage must never drop known advisories or emit false alerts.
    if errors:
        print(
            f"::warning::{errors}/{len(PACKAGES)} OSV queries failed; "
            "skipping report and state update this run"
        )
        _set_output("new_count", "0")
        return 0

    uncovered = uncovered_advisories(osv_by_package, covered)
    new = new_advisories(uncovered, known)
    print(f"{len(uncovered)} uncovered advisories; {len(new)} new since last run")

    with open("advisory-report.md", "w", encoding="utf-8") as fh:
        fh.write(render_issue(new) if new else "")
    # State mirrors the current uncovered set: newly-seen ones stop re-alerting,
    # and anything we later cover drops out naturally.
    save_state(STATE_PATH, advisory_ids(uncovered))
    _set_output("new_count", str(len(new)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - watcher must never fail the workflow
        print(f"::warning::advisory watcher error (non-fatal): {exc}", file=sys.stderr)
        raise SystemExit(0) from None
