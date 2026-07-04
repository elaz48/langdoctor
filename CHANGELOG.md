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
- Phase 3 output & integration:
  - Output formats: `--format console|json|sarif|markdown` (SARIF 2.1.0 wires
    findings into the GitHub Security tab; markdown is PR/issue-ready). SARIF
    `security-severity` uses the advisory's real CVSS score when present and the
    severity-bucket threshold (9.0/7.0/4.0/1.0) for CVSS-less code checks.
  - `[tool.langdoctor]` config in pyproject.toml (`fail-on`, `ignore`,
    `exclude`); CLI flags take precedence, ignore lists union.
  - Inline suppression: `# langdoctor: ignore` / `ignore=LD203,CVE-...` on a
    finding's line, matched centrally by the engine (LD id / CVE / alias,
    case-insensitive). Every output surfaces a `suppressed: N` count so nothing
    is hidden silently.
  - `action.yml` (composite GitHub Action) — pins the installed langdoctor to
    the action's own ref (`@v1.2.3` → `==1.2.3`; the moving `@v1` tracks the
    latest 1.x) for reproducible CI. `.pre-commit-hooks.yaml` for pre-commit.

### Fixed
- Scanner `DEFAULT_EXCLUDES` matched any path component, silently excluding a
  top-level `.env` file and breaking LD402/LD403 detection.
