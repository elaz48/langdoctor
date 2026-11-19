# Changelog

All notable changes to langdoctor are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-20

langdoctor now sees how Langflow is actually deployed and whether a vulnerable
API is actually used. Container images and manifests anywhere in the tree are
dependency sources; a CVE finding says where the project imports the vulnerable
API, or that it does not; Jupyter notebooks are read; and a check that crashes
fails the run instead of passing for a clean scan. Three advisories are new
(LD134-LD136), LD115 is deprecated, and four SQLite-store ranges are corrected.

### Added
- **Reachability: is the vulnerable API imported?** An advisory can now list
  `symbols`, the public entry points an application must import for the
  vulnerable code to be in play, and a version finding then says where the
  project uses them (`↳ used at svc/ingest.py:1 (EverNoteLoader)`) or that it
  does not (`↳ not imported in 14 Python files: EverNoteLoader`). It is
  evidence, not a verdict: severity and exit code are untouched, and a
  not-imported finding is only listed after the others of its severity. When
  some Python could not be read (a file the interpreter rejects, a notebook
  that cannot be followed), the result is reported as unknown — `no import found in 14 Python
  files, but 2 more could not be read` — and the finding is not moved. JSON
  has a `reachability` object per finding (`reachable` is `true`, `false` or
  `null`); SARIF adds the use sites as related locations.
  - Opt-in gate: `--allow-unimported` (or `allow-unimported = true` under
    `[tool.langdoctor]`) keeps a finding whose API is conclusively not imported
    from failing the run. It is still reported, and the console and the JSON
    summary (`not_counted`) say how many were let through. An unknown result,
    a finding without entry points and any known-exploited vulnerability count
    as before.
  - 10 advisories list entry points, each checked against the vendor advisory
    text and the package source at an affected tag (2026-11-19): LD101
    (`SqliteSaver`, `AsyncSqliteSaver`), LD107 (`langgraph.cache`), LD109 /
    LD110 / LD118 / LD128 (`langgraph.store.sqlite`), LD126 (`EverNoteLoader`),
    LD127 (`SitemapLoader` and its subclass `DocusaurusLoader`), LD131
    (`RemoteGraph`), LD132 (`Auth`). Legacy re-export paths
    (`langchain.document_loaders`, `langchain_classic.document_loaders`) are
    included.
  - Another 16 library advisories make no claim, deliberately, because an
    import list would be incomplete: the vulnerable code is the default
    serializer of every checkpointer (LD102, LD103, LD108), runs inside
    `astream_log()` / `RunnableWithMessageHistory` / template handling on any
    runnable (LD105, LD113, LD116, LD117), is a method (LD130, LD133, LD134,
    LD136),
    is created by the hosting platform (LD119, LD129), or has entry points the
    advisory does not name (LD104's `.save()`, LD114's loaders, LD125's
    request tools).
  - The GitHub Advisory Database lists no vulnerable functions for any of
    these advisories; the entry points are langdoctor's own curation.
- **Jupyter notebooks are read.** The hardcoded-key check (LD401) and the
  reachability search now look inside `.ipynb` code cells — where a great deal
  of LangChain code, and many pasted API keys, actually live. Every statement
  keeps the line number it has in the `.ipynb` file, so a finding opens at the
  right place, GitHub can annotate it, and an inline `# langdoctor: ignore`
  comment in the cell works. Line magics and `!shell` lines are stepped over,
  cells that are certainly not Python (`%%bash`, `%%sql`) are skipped, every
  other cell magic's body is read as Python, top-level `await` is accepted.
  Anything that could not be read — a cell that does not parse, a notebook
  that is minified or otherwise not one-line-per-source-line — makes the
  notebook count as not fully read rather than be guessed at. The
  production-readiness checks (LD2xx, LD3xx) do not read notebooks, and
  `.ipynb_checkpoints` is skipped.
- **Container images are a dependency source.** A Dockerfile `FROM` or a
  compose / Kubernetes `image:` line that names an official Langflow image
  (`langflowai/langflow`, `-backend`, `-ep`, `-all`, `-nightly`, and their
  `ghcr.io/langflow-ai/` mirrors) counts as an install of the version in its
  tag. A project that only runs `langflowai/langflow:1.2.0` used to scan "all
  clear"; it now reports the seven KEV-listed Langflow CVEs on the image line,
  with the fix given as an image tag. `ARG` defaults and `${VAR:-default}` are
  resolved; `latest` and `base-*` tags name no Langflow version and yield no
  version finding (`base-*` is the `langflow-base` version line — verified
  against Langflow's release workflow). The same image behind a mirror or a
  private registry is matched by its `org/name`. Which image means which
  package is data: `container_images` in `advisories.json`.
- **Manifests are found anywhere in the tree**, not only at the project root:
  `requirements*.txt`, `*requirements.txt`, `requirements/*.txt`,
  `pyproject.toml` and lockfiles in any subdirectory, so a monorepo is scanned
  service by service. `-r` / `--requirement` includes are followed, but never
  out of the scanned directory.
- **`pdm.lock`, `Pipfile.lock` and `pylock.toml` (PEP 751) are parsed.** LD501
  already accepted the first two as lockfiles while the scanner could not read
  the versions in them.

### Security
Hardening for scans of repositories you do not trust (fork pull requests,
fresh clones). None of this was exploitable for more than a misleading or
stalled scan.
- **A symlink that points out of the scanned directory is no longer read.** A
  `requirements.txt` linked to a file elsewhere on the machine had its lines
  quoted in the LD501 finding.
- **Control characters from the repository are stripped from the console
  report, and `<` is escaped in the Markdown one.** A directory or package name
  could carry terminal escape sequences or an HTML tag into the output.
- **A malformed manifest no longer aborts the scan.** `pyproject.toml` with
  unexpected types, a NUL byte or a symlink loop in a `-r` include, an include
  chain of any length, and absurdly nested JSON/TOML are all read as far as
  they make sense instead of ending the run with exit code 2.

### Advisories
- **LD135** — `langchain-anthropic` 1.0.0–1.4.5, CVE-2026-55443: path-prefix
  authorization bypass in the Anthropic tools middleware. It is the
  `langchain-anthropic` half of the advisory LD114 already tracks for
  `langchain`. The middleware first ships in 1.0.0 (absent from the 0.3.22
  wheel), so the range starts there although GHSA gives `<= 1.4.5`. Its entry
  points for reachability have not been researched yet, so it makes no claim.
- **LD136** — `langchain-openai` < 1.1.14, CVE-2026-41488: the SSRF check that
  1.1.9 added to image token counting (LD134's fix) could be bypassed by DNS
  rebinding. Low severity; CVSS 3.1 from GHSA and NVD.
- `langchain-openai` and `langchain-anthropic` are now watched by the weekly
  advisory watcher. Both came into scope through advisories that were already
  tracked for another package; OSV lists nothing else for either today.
- Advisory DB date moves to 2026-11-20.

### Deprecated
- **LD115** (CVE-2026-26013 on `langchain-core < 1.2.11`), superseded by
  **LD134** (the same CVE on `langchain-openai < 1.1.9`). GHSA and PYSEC file
  the image-URL SSRF under `langchain-core`, but the vendor advisory's own text
  names `langchain_openai/chat_models/base.py` and says it is "patched in
  `langchain-openai==1.1.9` (requires `langchain-core==1.2.11`)"; the fix commit
  adds only an SSRF helper to core. LD115 therefore flagged projects that do
  not install `langchain-openai`, and missed projects that upgraded core but
  kept `langchain-openai` 1.1.8, which accepts any core from 1.2.9. Checked
  against the advisory text, the fix commit and the PyPI metadata of both
  releases. An existing `ignore` of `LD115` keeps suppressing LD134.

### Fixed
- **SQLite-store advisories no longer fire on releases that have no store.**
  LD109, LD110, LD118 and LD128 were reported for every
  `langgraph-checkpoint-sqlite` below their fix, as GHSA and OSV give the range
  from 0. The store first shipped in 2.0.8: the 2.0.5–2.0.7 wheels on PyPI and
  the source tree at those tags contain no `langgraph/store/sqlite`. Their
  ranges now start at 2.0.8; LD101, which is in the checkpointer, is unchanged.
- **LD114's description said "document loaders".** The advisory names the
  prompt and chain/agent *configuration* loaders. Its range is unchanged: those
  loaders ship in the 0.x wheels, the fixed middleware only in 1.x.
- **A Python file nested too deeply to parse crashed the scan** with a
  traceback, or — when the parser ran out of memory instead — silently removed
  every hardcoded-key finding of the project. It is now treated like any
  other file that does not parse.
- **Line numbers no longer drift after a form feed or a Unicode line
  separator** inside a string: lines are counted on newlines only, as editors
  and the Python tokenizer do.

### Changed
- **A check that crashes fails the run.** One check raising an exception used
  to be dropped without a word, so input that crashed a check produced the
  same output as a clean project. The other checks still run and their
  findings are printed, but the failure is named on stderr, listed under
  `errors` in the JSON output, and the exit code is 2 — also under
  `--fail-on never`. No SARIF is written for such a run, because GitHub closes
  every alert that a new upload no longer contains.
- **Large codebases scan about five times faster.** Every check walked each
  file's syntax tree on its own — LD302 twelve times, once per chat-model
  class — so 1,500 Python files took 45 seconds. The calls, imports and
  attribute accesses of a file are now indexed in one walk; the same tree
  scans in 9 seconds (5 of them parsing), with identical findings.
- **Scanning subdirectories can surface findings an upgrade did not have
  before** — an old pin in a nested service, for instance. Directories that
  are vulnerable on purpose belong in `exclude`.
- **LD501 is judged per manifest directory** and names the manifest: a lockfile
  covers its own directory and everything below it (one root `uv.lock` covers a
  workspace), and a directory without one gets its own finding.
- **LD150 is suppressed per install, not per package:** a second service that
  only trails the Langflow baseline keeps its finding even when another
  service has specific Langflow CVEs.
- **LD403 points at the manifest or image line Langflow comes from**, so it has
  a location in SARIF and can be suppressed inline there.

## [0.1.8] - 2026-11-20

Fixes only, no advisory data changes. The GitHub Action the README documented
could not be resolved at all; it is now `elaz48/langdoctor@v0`, and the release
pipeline that moves that tag is hardened. Two false positives are gone and
large `node_modules` trees no longer slow a scan down.

### Fixed
- **The documented GitHub Action could not be resolved.** The README, the
  website and the "all clear" panel all said `uses: elaz48/langdoctor@v1`, but
  only `v0.1.x` tags exist. They now say `@v0`, a major tag the release
  workflow moves to the newest release of its line (re-running an older
  release's workflow does not move it back). The release trigger is narrowed
  from `v*` to `vX.Y.Z` so pushing `v0` by hand cannot start a release.
- **LD204 false positive on `re.compile()`.** Any `.compile(...)` call in a
  file that also called `interrupt()` counted as a graph compiled without a
  checkpointer. The builtin `compile()` and functions called through an
  imported module (`re.compile`, `torch.compile`) are no longer considered.
  A `.compile()` on another non-graph object in such a file (a SQLAlchemy
  statement, say) is still picked up, which is one reason LD204 is now marked
  heuristic (see Changed).
- **LD502 false positive on comments.** A commented-out step, or a comment
  that merely quotes a `uses: owner/repo@tag` line, was reported as an unpinned
  action. Only a real `uses:` key counts now. Found by running langdoctor on
  its own workflows.
- **Excluded directories were walked and then filtered.** A project with a
  60,000-file `node_modules` took 2.9s to scan instead of 0.2s. Excluded
  directories are now pruned before they are entered. Files are also visited
  in sorted order, so equally ranked findings come out in the same order on
  every filesystem.
- The README's pre-commit snippet pinned `rev: v0.1.0`; it now names the
  current release, and a test keeps it there.
- The Action's `@vX.Y` form installed anything below the next major instead of
  the `X.Y.x` line its comment promised.

### Changed
- **LD204 is now a heuristic.** It decides that "interrupts are used" per file,
  and a graph deployed on a platform that injects the checkpointer is compiled
  without one on purpose. Like every heuristic it prints `[heuristic]` and no
  longer affects the exit code unless `--strict` is given — this only changes
  the result for runs with `--fail-on medium` or `low`.
- **Release workflow hardened.** Building and publishing are separate jobs:
  the only job that can obtain the PyPI token downloads the already-built
  files and runs the PyPA publisher, with no build tool, no shell step and no
  write access to the repository. Every action in `release.yml` is pinned to a
  commit SHA, and a tag whose commit is not on `main` is refused before
  anything is built.
- **Action: pinning to a commit SHA pins the checks and the advisory DB.** A
  SHA or branch ref used to install the latest release from PyPI; it now builds
  langdoctor from the action's own checkout (its dependencies still resolve
  from PyPI). The README says plainly that LD502 flags the recommended `@v0`
  line and shows the SHA-pinned form.
- **Action: inputs are passed through the environment**, not interpolated into
  the shell script. `args` is therefore split on whitespace (it may span
  lines) and shell quoting inside it is no longer interpreted — write
  `--ignore LD203,LD302`, not `--ignore "LD203, LD302"`. A `path` or `output`
  that starts with `-` is no longer read as an option, and the step sets
  `PYTHONUTF8=1` so non-ASCII output survives a Windows runner's pipe.
- CI runs `langdoctor .` on this repository and runs `action.yml` from the
  checkout on Linux, macOS and Windows. The repo's own config excludes
  `examples/` and `tests/`, which are vulnerable on purpose.

## [0.1.7] - 2026-11-19

Advisory deprecation support, used to retire LD112 in favor of LD133, plus an
NVD baseline-drift source for the weekly advisory watcher (dev tooling — not
part of the installed package) so LD150 cannot silently go stale a third time.

### Added
- **Advisory watcher: NVD baseline-drift check.** The aggregate LD150 baseline
  went stale twice (0.1.4, 0.1.6) because IBM PSIRT publishes Langflow CVEs
  straight to NVD and OSV never indexes them — on 2026-11-18 none of the 108
  IBM-attributed Langflow CVEs published since 2026-08-20 were in OSV. The
  weekly watcher now queries NVD for every aggregate advisory and reports CVEs
  that affect a version at or above its baseline and have no LD entry of their
  own, in a "Baseline drift" section between KEV and OSV, with the highest
  stated fix as the suggested new baseline. Version bounds come from NVD's CPE
  analysis, falling back to the CNA description for records still awaiting
  analysis. The description is only read in sentences naming the product, near
  that name — prose routinely cites dependency versions ("requires Python
  before 3.12") — and a CPE-less record with no readable version is reported
  as "unparsed" for a human rather than dropped. Replayed against live NVD data
  it flags 100 CVEs (16 with CVSS ≥ 9.0) for the old 1.11.0 baseline and
  suggests 1.13.0 — the bump 0.1.6 made by hand — and nothing for the current
  baseline.
- `scripts/baseline_drift.py` holds the pure, unit-tested logic;
  `.watch-state.json` gains `known_baseline_drift`; the workflow passes an
  optional `NVD_API_KEY` secret (unset is fine — one query a week). NVD pages
  retry transient errors (403/429/5xx, dropped connections, truncated bodies)
  within a 5-minute budget, and the job gets `timeout-minutes: 20`. A reply
  without the results schema, a page short of the total, or zero records for
  the keyword all count as an outage, so bad data never rewrites the state.
- The CNA "patched in" boilerplate only counts in its subject-anchored form
  ("This issue has been patched in version X", "Version X contains a patch")
  and only when the description names the product, so a dependency's fix
  ("the dependency foo was patched in 2.5.0") cannot pose as a Langflow one.

### Changed
- `advisory_watch.main()` is split into one function per source, and each
  source now runs isolated: an unexpected error in one is logged and never
  loses another source's report or state. A failed source still reports
  nothing and keeps its previous state baseline.
- NVD, OSV and KEV prose pasted into the watch issue has its `@mentions`
  neutralised, so an advisory text cannot notify arbitrary GitHub users.
- Advisory DB date moves to 2026-11-19.

### Deprecated
- **LD112** (CVE-2026-48776 on `langgraph < 0.3.15`), superseded by **LD133**
  (the same CVE on `langgraph-sdk < 0.3.15`). LD112 followed PYSEC-2026-2194,
  which files the CVE under `langgraph` although its own text, the vendor GHSA
  and the fix release all name `langgraph-sdk`. It compared langgraph versions
  against an SDK fix number and missed the installs that matter: langgraph
  0.3.34 pins `langgraph-sdk < 0.2.0` and 0.6.11 pins `< 0.3.0`, so both always
  resolve a vulnerable SDK, yet neither was flagged. LD112 no longer produces
  findings; the ID stays in the DB and in `list-checks` (marked deprecated).
  - When the SDK version is visible — a lockfile (`uv.lock`, `poetry.lock`)
    records it, or it is pinned directly — LD133 reports every affected
    install. A bare `requirements.txt` pinning only an old `langgraph` no
    longer gets this CVE reported: LD112 only caught the `< 0.3.15` slice of
    that case, and by accident.
  - Existing suppressions keep working: an `ignore` of `LD112` (or of
    `PYSEC-2026-2194`) now suppresses LD133, which also lists both among its
    aliases. Suppressed findings are still counted, never hidden.
- Advisories support deprecation: `deprecated` (ISO date) and `superseded_by`
  in `advisories.json`. A deprecated entry never fires and is marked in
  `list-checks`; its successor inherits its identifiers for suppression; its
  identifiers still count as covered for the advisory watcher, so the
  misattributed PYSEC record never alerts; and a deprecated aggregate is not
  polled for NVD baseline drift.

## [0.1.6] - 2026-11-18

Advisory data + watcher update. Two LangGraph CVEs from the open watch issue
(#4) made the "clean" test fixture vulnerable, and — for the second time — the
Langflow aggregate baseline had drifted: IBM PSIRT published ~99 Langflow CVEs
fixed above 1.11.0 that OSV never indexed, so a project on 1.11.x or 1.12.x
scanned completely clean.

### Added
- **LD128 / LD129** — CVE-2026-115883: namespace labels containing `.` reach
  other namespaces in the LangGraph SQLite / Postgres stores. Only `put`
  rejected such labels; `get`, `search`, `delete`, `list_namespaces` and
  `batch` did not, so a caller who controls a label can read, overwrite or
  delete another tenant's items. Follow-up to CVE-2026-71433 (LD118/LD119):
  3.1.1 is still affected. Fixed in sqlite **3.1.2** and postgres **3.1.3** —
  one CVE, two packages, and unlike LD118/LD119 two different fix versions.
  Medium (GitHub CNA, CVSS 4.0: 6.0; NVD has no primary score yet).
- **LD130 / LD131** — CVE-2026-118667: the LangGraph SDK v3 streaming client
  puts `thread_id` / `assistant_id` into request paths unencoded, so a crafted
  id redirects an authenticated GET to another path on the server. Affects
  `langgraph-sdk` 0.4.0–0.4.5 (LD130; the 0.3.x line has no v3 stream module)
  and `langgraph` 1.2.3–1.2.13 through RemoteGraph (LD131). Medium (CNA 4.3).
- **LD132** — CVE-2026-104873: the `langgraph-sdk` custom-auth decorators
  (`@auth.on.threads` / `.assistants` / `.crons`) ignore `actions=` and register
  the handler for every action, so authorization checks in fallback handlers
  never run. 0.1.45–0.4.3, fixed in 0.4.4. High (CNA, CVSS 4.0: 7.6). It was
  not on the watch issue because `langgraph-sdk` was not watched; found by
  cross-checking NVD.
- **LD133** — CVE-2026-48776 on `langgraph-sdk < 0.3.15`. The vendor GHSA and
  PYSEC-2026-2575 attribute it to the SDK; LD112 follows PYSEC-2026-2194, which
  files it under `langgraph`. LD112 is a shipped ID and stays; LD133 makes an
  old SDK pinned next to a modern langgraph visible.
- First coverage for `langgraph-sdk`, and the advisory watcher now queries it.
  All five of its current OSV records are covered, so this opens no issue.

### Changed
- **LD150** — the aggregate Langflow baseline moves **1.11.0 → 1.13.0**. IBM
  PSIRT published ~99 further Langflow CVEs between 2026-08-28 and 2026-11-08,
  with fixes from 1.11.2 to 1.13.0 — 16 of them CVSS ≥ 9.0, including
  CVE-2026-110186 (remote code execution through 1.12.8, CVSS 9.8). OSV had
  indexed none of the 108 IBM-attributed Langflow CVEs published since
  2026-08-20. 1.12.9 and 1.12.10 shipped after 1.13.0, but they branch from
  release-1.12.8 and backport only the 1.13.0 → 1.13.1 delta (langflow PR
  #16119), so they stay below the baseline.
- Test fixtures: `clean_project` moves to langgraph 1.2.14, langgraph-sdk
  0.4.6, checkpoint-sqlite 3.1.2 and checkpoint-postgres 3.1.3 — its 1.2.7 /
  3.1.1 pins were affected by the new advisories yet scanned clean.
  `vulnerable_project` gains `langgraph-sdk==0.4.3`; `langflow_baseline_project`
  moves to 1.12.8 and `langflow_patched_project` to 1.13.0.
- `README.md`: check table gains LD128–LD133 (47 rows) and the new LD150 baseline.
- `site/index.html`: catalog gains LD132 and the new LD150 baseline; check
  count 41 → 47 (the hero pill still said 25); advisory date refreshed.
  (Uploaded manually via FTP — no automated deploy.)
- `.watch-state.json` re-seeded: the now-covered GHSA-3fx2-cqw9-xr3c and
  GHSA-6hmw-9432-67qq drop out, and entries carry their aliases (see Fixed).

### Fixed
- **The advisory watcher re-alerted known advisories under a new id.** The
  delta compared only the primary OSV id, so when OSV published PYSEC records
  for ten Langflow GHSAs alerted the week before, the 2026-10-19 comment on #4
  was entirely duplicates. The state file now stores every identifier (id +
  aliases), and an advisory is new only if none of them is known — in either
  publication order.
- **The watch report named one package per advisory.** A record spanning
  several packages (GHSA-6hmw: sqlite *and* postgres, with different fixes) was
  attributed to whichever watched package returned it first. The report now
  lists every package the record names; malformed `affected` rows are skipped
  instead of aborting the run.
- **The heuristic specifier check ignored an advisory's lower bound.** A capped
  specifier such as `langgraph<1.0.0` was flagged for any single-range advisory
  whose fix it could not reach — even one whose range starts above it (LD131
  starts at 1.2.3). A range with a non-zero `introduced` is now flagged only
  when the specifier can resolve into the affected window; `>1.2.3`, `!=1.2.3`
  and `>=1.2.5,<1.2.10` still count.

### Notes
- Langflow GHSAs on watch issue #4 (all fixed ≤ 1.10.3) stay covered in
  aggregate by LD150.
- Seen on NVD but out of scope — packages langdoctor does not scan:
  `langgraph-api` (CVE-2026-55235, -55236, -118668), `langgraph-cli`
  (CVE-2026-115885), `langgraph-checkpoint-mongodb` / `langchain-mongodb`
  (CVE-2026-55253, -106119).

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

[Unreleased]: https://github.com/elaz48/langdoctor/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/elaz48/langdoctor/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/elaz48/langdoctor/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/elaz48/langdoctor/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/elaz48/langdoctor/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/elaz48/langdoctor/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/elaz48/langdoctor/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/elaz48/langdoctor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/elaz48/langdoctor/releases/tag/v0.1.0
