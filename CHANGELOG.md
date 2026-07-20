# Changelog

All notable changes to langdoctor are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/elaz48/langdoctor/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/elaz48/langdoctor/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/elaz48/langdoctor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/elaz48/langdoctor/releases/tag/v0.1.0
