# Changelog

All notable changes to langdoctor are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-08-27

First coverage for `langchain-community`, plus `langchain-classic` on the watch
list. langchain-community is first-party LangChain and pulls 44.8M downloads a
month, but had no advisory coverage at all — while langflow, at 65k a month,
carries eight entries.

### Added
- **LD125** — CVE-2025-2828: SSRF via `RequestsToolkit`, which places no
  restriction on the addresses it fetches, so an agent steered by untrusted
  input can reach localhost and internal services. Fixed in 0.0.28. Unusual
  timeline — the fix shipped in March 2024 but the CVE was only published on
  2025-06-23, so this fires only on a pre-0.0.28 pin. NVD's primary score is
  10.0; the huntr CNA scores it 8.4.
- **LD126** — CVE-2025-6984: XXE in `EverNoteLoader`, which calls
  `etree.iterparse()` without disabling external entity resolution. Fixed in
  0.3.27. The huntr write-up (mirrored by NVD) names 0.3.63 as affected, but
  langchain-community has no such release — its 0.3 line stops at 0.3.31 — so
  that number is the reporter's `langchain-core` version. GHSA and OSV agree on
  `< 0.3.27`, which is the bound used here.
- **LD127** — CVE-2026-72848: SSRF via nested sitemap index entries in
  `SitemapLoader`, where `restrict_to_same_domain` is enforced only on leaf
  `<url>` elements. **No released fix** — upstream closed the issue on
  2026-08-13, but no langchain-community release carries it (0.4.2, from
  2026-05-22, is still the newest). The advisory therefore has an open-ended
  range and no fix version, and langdoctor reports it as affected with no
  upgrade to recommend. Mitigate by not pointing `SitemapLoader` at untrusted
  sitemaps and by restricting egress from the ingestion host.
- Advisory watcher now also queries `langchain-community` and
  `langchain-classic`. The latter joins at zero data cost — its sole OSV record
  is the LangSmith SDK issue already declared out of scope — but is worth
  watching because it inherited the legacy chains and is now a hard dependency
  of langchain-community.
- Fixture pair `community_project` (0.0.27, trips all three) and
  `community_latest_project` (0.4.2, only the unfixed LD127 survives).

### Changed
- `scripts/watch-ignore.json`: two new pre-2025 entries, CVE-2024-2057 (unsafe
  pickle in `TFIDFRetriever.load_local`) and CVE-2024-3095 (SSRF in
  `WebResearchRetriever`). CVE-2024-2965 / -5998 / -8309 were already ignored
  via their langchain cross-listing. The file's note now states that the
  pre-2025 cutoff applies even to a package langdoctor otherwise covers.
- `README.md`: check table gains LD125–LD127 (41 rows), plus a note that a
  finding can legitimately arrive with no fix line.
- `site/index.html`: catalog table gains the three entries, check count 38 → 41.
  (Uploaded manually via FTP — no automated deploy.)

### Notes
- Adding a package needed **no code change**: package support is pure advisory
  data, and an advisory with a `null` fixed bound already flows correctly
  through `matched_range` and `_fix_line`.
- Out of scope by design: CVE-2026-26019 and CVE-2026-27795 look like
  langchain-community issues but are `@langchain/community` on npm — langdoctor
  scans Python projects only.

## [0.1.4] - 2026-08-27

Advisory data + watcher update. Found by cross-checking NVD and the CISA KEV
catalog by hand — the OSV-only watcher reported "0 new" for weeks while five
known-exploited Langflow CVEs went uncovered and the aggregate baseline drifted
two minor lines behind.

### Added
- **LD120–LD124** — the five CISA KEV Langflow CVEs that had no advisory entry.
  All are flagged `exploited_in_the_wild`, so they sort above every non-KEV
  finding:
  - **LD124** — CVE-2026-9198 (CVSS 9.8, KEV 2026-08-04, three-day federal
    deadline): `/api/v1/auto_login` mints SUPERUSER tokens to any caller that
    can reach the port and `/api/v1/validate/code` runs submitted code through
    `exec()` — chaining them is unauthenticated RCE in two HTTP requests.
    Fixed in 1.10.1. **Not in OSV at all**, which is precisely why an OSV-only
    watcher never raised it.
  - **LD121** — CVE-2026-0770 (CVSS 9.8, KEV 2026-07-21, ZDI-26-036):
    unauthenticated RCE via the `exec_globals` parameter of the validate
    endpoint, as root in the default container. Fixed in 1.8.0 — OSV records no
    fix version, so the bound comes from the NVD CPE range plus the absence of
    any 1.7.4 release.
  - **LD122** — CVE-2026-33017 (CVSS 9.8, KEV 2026-03-25): unauthenticated RCE
    via attacker-supplied flow data in `POST /api/v1/build_public_tmp`, distinct
    from CVE-2025-3248 (LD106). Sources disagree on the bound (vendor GHSA/OSV
    say 1.9.0, NVD CPE stops at 1.8.2); we take the wider vendor bound so a
    1.8.2–1.8.4 install is still flagged.
  - **LD120** — CVE-2025-34291 (CVSS 8.8, KEV 2026-05-21): `allow_origins='*'`
    with `allow_credentials=True` plus a `SameSite=None` refresh cookie lets a
    malicious page hijack tokens, chaining to account takeover and RCE. Fixed in
    1.7.0. Score is the NVD primary CVSS 3.1 base; the VulnCheck CNA rates it
    9.4 critical on CVSS 4.0.
  - **LD123** — CVE-2026-55255 (CVSS 8.4, KEV 2026-07-07): IDOR in
    `/api/v1/responses` executes another tenant's flow. Fixed in 1.9.1 (GHSA and
    NVD agree; PYSEC-2026-221 records 1.9.2).
- **Advisory watcher: CISA KEV as a second source.** `advisory_watch.py` now
  diffs the KEV catalog alongside OSV, filtered to the LangChain/LangGraph/
  Langflow ecosystem, and reports KEV misses in their own section above the OSV
  findings. The two sources fail independently — a KEV outage cannot suppress
  the OSV report, and a partial OSV run still reports KEV hits.
- Fixture pair `langflow_baseline_project` (1.10.3) / `langflow_patched_project`
  (1.11.0) pinning the aggregate baseline regression.

### Changed
- **LD150** — the aggregate Langflow baseline moves **1.10.1 → 1.11.0**. IBM
  PSIRT published 24 further Langflow CVEs on 2026-08-05, all affecting
  `< 1.11.0` and including CVE-2026-8182 (unauthenticated RCE in two HTTP
  requests, CVSS 8.8); none were indexed by OSV as of 2026-08-27. A project
  pinned to langflow 1.10.2 or 1.10.3 previously scanned **completely clean**.
- `.watch-state.json` gains a `known_uncovered_kev` key; the OSV delta keeps its
  existing `known_uncovered` key. A source that fails to fetch keeps its previous
  baseline rather than dropping it and re-alerting next week.
- `README.md` check table now mirrors `list-checks` again — LD112–LD119 shipped
  in 0.1.1–0.1.3 but were never transcribed into it.
- `site/index.html`: catalog table gains the KEV entries, check count 25 → 38,
  advisory date refreshed. (Uploaded manually via FTP — no automated deploy.)

### Fixed
- `test_cli_ignore_flag` asserted on raw console text, so an advisory detail that
  cross-references another LD id (LD122 cites LD106) read as a suppressed finding
  still being present. It now asserts on parsed finding ids.

## [0.1.3] - 2026-08-11

Advisory data update (LD118–LD119), surfaced by the weekly watcher.

### Added
- **LD118 / LD119** — CVE-2026-71433: namespace prefix matching crosses segment
  boundaries in the LangGraph SQLite and Postgres stores. Namespaces are stored
  dot-joined and scoped reads use `LIKE '<path>%'`, so a scoped `search` /
  `list_namespaces` also returns sibling namespaces sharing leading characters
  (cross-tenant state leak). Medium (CVSS 5.3), both fixed in 3.1.1.
  - One CVE, two packages: the schema models one package per advisory, so this
    ships as two entries sharing the CVE and aliases. Each finding names the
    package actually installed in its fix line; suppressing the CVE silences both.
  - First coverage for `langgraph-checkpoint-postgres`.

### Changed
- Test fixtures: `clean_project` bumps `langgraph-checkpoint-sqlite` to 3.1.1
  (3.1.0 is affected by the new advisory) and both fixtures now pin
  `langgraph-checkpoint-postgres`.

## [0.1.2] - 2026-07-20

Advisory data update (LD115–LD117), surfaced by the weekly watcher.

### Added
- **LD117** — CVE-2026-44843: unsafe deserialization of attacker-controlled
  objects via overly broad `load()` allowlists in `langchain-core` (dual-line fix
  0.3.85 / 1.3.3). High (CVSS 8.2).
- **LD116** — CVE-2026-40087: incomplete f-string validation in prompt templates
  (`langchain-core`, dual-line fix 0.3.84 / 1.2.28). Medium (5.3); same family
  as LD113.
- **LD115** — CVE-2026-26013: SSRF via `image_url` token counting in
  `ChatOpenAI.get_num_tokens_from_messages` (`langchain-core < 1.2.11`). Low (3.7).

### Changed
- `scripts/watch-ignore.json`: added CVE-2026-45134 (LangSmith SDK prompt-pull
  deserialization, cross-listed by OSV to `langchain` but out of scope) and
  broadened the ignore criteria to cover recent third-party-SDK advisories that
  only affect a line langdoctor does not flag. Re-seeded `.watch-state.json`.

## [0.1.1] - 2026-07-13

Advisory data update (LD112–LD114), surfaced by the new weekly watcher.

### Added
- **LD112** — CVE-2026-48776: unsafe URL path construction in the LangGraph SDK
  (`langgraph < 0.3.15`, 0.x line only). Medium (CNA 4.2); the detail notes the
  inconsistent NVD-secondary 9.1.
- **LD113** — CVE-2025-65106: template injection via attribute access in prompt
  templates (`langchain-core`, dual-line fix 0.3.80 / 1.0.7). High (CVSS 4.0, 8.3).
- **LD114** — CVE-2026-55443: path traversal / sandbox escape in file-search
  middleware and loaders (`langchain < 1.3.9`). Medium (5.1). First advisory on
  the top-level `langchain` package.
- Weekly advisory watcher (`.github/workflows/advisory-watch.yml` +
  `scripts/advisory_watch.py`): queries OSV.dev for the covered packages, diffs
  against the IDs/aliases in `advisories.json`, and reports advisories not yet
  covered on a single tracking issue. Never fails the workflow on API hiccups
  (partial data → skip, exit 0). Pure comparison logic is unit-tested.
  - `scripts/watch-ignore.json`: advisories that are intentionally out of scope
    (pre-2025 historical langchain CVEs) and never alerted.
  - Delta reporting via a committed `.watch-state.json`: an advisory alerts once,
    not every week; deferred-but-planned items (the Langflow long tail) are
    tracked without re-alerting.

### Changed
- `scripts/watch-ignore.json`: added CVE-2024-5998 (pre-2025 LangChain pickle
  deserialization) as out of scope; re-seeded `.watch-state.json` so the newly
  covered (LD112–114) and ignored advisories stop alerting.

## [0.1.0] - 2026-07-04

Initial release.

### Added
- **Known-CVE checks (data-driven, offline).** 12 advisories for
  LangGraph / LangChain / Langflow (LD101–LD111 + the LD150 Langflow catch-all),
  shipped in `advisories.json` (schema v2): OSV-style `affected_ranges`
  (including dual-line fixes), CVSS-derived severity with a manual override,
  `exploited_in_the_wild` (KEV) flags, and `aliases`.
- **Code-pattern checks.** Checkpointer/state (LD201–204), graph/runtime config
  (LD301–304), secrets & exposure (LD401–403, LD203), and hygiene (LD501–502) —
  via cached stdlib-`ast` analysis and file heuristics.
- **Project scanner** for `requirements.txt`, `pyproject.toml` (PEP 621 +
  poetry), `uv.lock`, and `poetry.lock`, plus Python-source discovery.
- **CLI**: `langdoctor [PATH]`, `list-checks`, `--version`; `--fail-on`,
  `--strict`, `--ignore`, `--quiet`; exit codes 0 (clean) / 1 (findings) / 2
  (scan error).
- **Output formats**: console, json, sarif (2.1.0 for GitHub code scanning, with
  CVSS-backed `security-severity`), and markdown.
- **Config & suppression**: `[tool.langdoctor]` (`fail-on`/`ignore`/`exclude`)
  and inline `# langdoctor: ignore[=IDs]` matched on LD id / CVE / alias
  (case-insensitive). Suppressed findings are counted, never hidden.
- **Integrations**: composite GitHub Action (`action.yml`, install pinned to the
  action's own ref) and `.pre-commit-hooks.yaml`.

### Fixed
- Scanner `DEFAULT_EXCLUDES` matched any path component, silently excluding a
  top-level `.env` file and breaking LD402/LD403 detection.

[Unreleased]: https://github.com/elaz48/langdoctor/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/elaz48/langdoctor/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/elaz48/langdoctor/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/elaz48/langdoctor/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/elaz48/langdoctor/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/elaz48/langdoctor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/elaz48/langdoctor/releases/tag/v0.1.0
