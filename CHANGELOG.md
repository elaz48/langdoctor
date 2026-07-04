# Changelog

All notable changes to langdoctor are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/elaz48/langdoctor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/elaz48/langdoctor/releases/tag/v0.1.0
