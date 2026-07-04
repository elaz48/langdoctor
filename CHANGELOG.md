# Changelog

All notable changes to langdoctor are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 1 skeleton: project scanner (requirements.txt, pyproject, uv.lock,
  poetry.lock), `Finding` model, check registry, data-driven version/CVE check
  reading `advisories.json` (schema v2), rich console output, and the CLI
  (`langdoctor`, `list-checks`, `--version`).
- `advisories.json` seeded with the verified LD1xx catalog (LD101–LD111 + the
  LD150 Langflow catch-all), with CVSS-derived severity, `exploited_in_the_wild`
  (KEV) flags, and `aliases`.
- Phase 2 full check catalog — AST/file-heuristic code-pattern checks:
  - Checkpointer/state: LD201 (MemorySaver in prod), LD202 (SqliteSaver
    concurrency), LD204 (interrupts without checkpointer).
  - Graph/runtime config: LD301 (no recursion_limit), LD302 (no LLM timeout,
    heuristic), LD303 (deprecated pre-1.0 imports), LD304 (legacy load_prompt).
  - Secrets/exposure: LD401 (hardcoded API keys), LD402 (.env not gitignored),
    LD403 (Langflow auto-login not disabled), LD203 (checkpoint filter from
    user input, heuristic).
  - Hygiene: LD501 (unpinned dependencies), LD502 (unpinned GitHub Actions).
  - Shared `analysis.py` (cached AST parsing + helpers); checks auto-register.
