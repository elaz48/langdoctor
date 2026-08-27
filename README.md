# langdoctor 🩺

> **Scan your LangGraph/LangChain project for known CVEs, insecure configs, and production footguns — in seconds, offline, no API key.**
>
> _brew doctor for your agent stack._

[![PyPI](https://img.shields.io/pypi/v/langdoctor.svg)](https://pypi.org/project/langdoctor/)
[![Python](https://img.shields.io/pypi/pyversions/langdoctor.svg)](https://pypi.org/project/langdoctor/)
[![CI](https://github.com/elaz48/langdoctor/actions/workflows/ci.yml/badge.svg)](https://github.com/elaz48/langdoctor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![langdoctor scanning a vulnerable project](https://raw.githubusercontent.com/elaz48/langdoctor/main/assets/demo.gif)

## Quickstart

```bash
pipx run langdoctor        # or: uvx langdoctor
```

Run it in your project directory. langdoctor reads your dependency files and
source, reports issues grouped by severity, and exits non-zero when it finds
something at or above your threshold.

```bash
langdoctor                 # scan the current directory
langdoctor path/to/project # scan a specific directory
langdoctor list-checks     # every check, with IDs and severities
langdoctor --version       # tool version + advisory DB date
```

## Why

2026 has been a rough year for the agent stack:

- **Langflow is under active attack.** `CVE-2025-3248` (unauthenticated RCE) was
  added to the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  and [exploited to deploy the Flodrix botnet](https://www.trendmicro.com/en_us/research/25/f/langflow-vulnerability-flodric-botnet.html);
  `CVE-2026-5027` (path-traversal → RCE) is [being exploited across ~7,000 exposed instances](https://www.bleepingcomputer.com/news/security/path-traversal-flaw-in-ai-dev-platform-langflow-exploited-in-attacks/).
- **LangGraph checkpointer CVEs** — SQL injection and unsafe deserialization in
  the SQLite/base checkpointers can chain to RCE via forged checkpoint rows.
- **Supply-chain attacks** on the CI actions and packages the ecosystem depends
  on (the tj-actions and LiteLLM incidents) mean a pinned-to-a-tag action or an
  unpinned dependency is a real risk surface.

These are exactly the things a framework-specific linter can catch before you
ship. langdoctor ships the CVE data with the package and runs fully offline.

## What it checks

<!-- BEGIN check-table (generated from `langdoctor list-checks`) -->
| ID | Category | Severity | What it catches |
| --- | --- | --- | --- |
| `LD101` | Known CVEs | high | SQL injection via metadata filter key in SQLite checkpointer |
| `LD102` | Known CVEs | medium | Unsafe msgpack deserialization in checkpoint loading |
| `LD103` | Known CVEs | medium | Unsafe JSON deserialization in checkpoint loading |
| `LD104` | Known CVEs | high | Path traversal in legacy load_prompt functions |
| `LD105` | Known CVEs | critical | Serialization-injection secret extraction in dumps/loads |
| `LD106` | Known CVEs | critical 🔴KEV | Unauthenticated RCE in /api/v1/validate/code (Langflow) |
| `LD107` | Known CVEs | medium | BaseCache deserialization of untrusted data may lead to RCE |
| `LD108` | Known CVEs | high | RCE in "json" mode of JsonPlusSerializer |
| `LD109` | Known CVEs | high | SQL injection in the SQLite store implementation |
| `LD110` | Known CVEs | high | SQL injection via filter key in SqliteStore |
| `LD111` | Known CVEs | high 🔴KEV | Path traversal → RCE via /api/v2/files upload (Langflow) |
| `LD112` | Known CVEs | medium | Unsafe URL path construction in the LangGraph SDK |
| `LD113` | Known CVEs | high | Template injection via attribute access in prompt templates |
| `LD114` | Known CVEs | medium | Path traversal and sandbox escape in file-search middleware |
| `LD115` | Known CVEs | low | SSRF via image_url token counting |
| `LD116` | Known CVEs | medium | Incomplete f-string validation in prompt templates |
| `LD117` | Known CVEs | high | Unsafe deserialization via overly broad load() allowlists |
| `LD118` | Known CVEs | medium | Namespace prefix matching crosses segments (SQLite store) |
| `LD119` | Known CVEs | medium | Namespace prefix matching crosses segments (Postgres store) |
| `LD120` | Known CVEs | high 🔴KEV | CORS + SameSite token hijack → account takeover (Langflow) |
| `LD121` | Known CVEs | critical 🔴KEV | Unauthenticated RCE via exec_globals in validate (Langflow) |
| `LD122` | Known CVEs | critical 🔴KEV | Unauthenticated RCE via build_public_tmp flow data (Langflow) |
| `LD123` | Known CVEs | high 🔴KEV | IDOR in /api/v1/responses runs another user's flow (Langflow) |
| `LD124` | Known CVEs | critical 🔴KEV | auto_login + validate/code chain → unauth RCE (Langflow) |
| `LD150` | Known CVEs | high | Langflow older than the current secure baseline (1.11.0) |
| `LD201` | Checkpointer & state | high | MemorySaver used in a production-bound project |
| `LD202` | Checkpointer & state | medium | SqliteSaver may collapse under write concurrency |
| `LD203` | Checkpointer & state | high (heuristic) | Checkpoint history filtered by user-controlled input |
| `LD204` | Checkpointer & state | medium | Compiled graph with interrupts has no checkpointer |
| `LD301` | Graph & runtime config | medium | No recursion_limit configured for a LangGraph run |
| `LD302` | Graph & runtime config | low (heuristic) | LLM client created without a timeout |
| `LD303` | Graph & runtime config | info | Deprecated pre-1.0 LangChain import |
| `LD304` | Graph & runtime config | high | Legacy load_prompt() usage |
| `LD401` | Secrets & exposure | critical | Hardcoded API key in source |
| `LD402` | Secrets & exposure | high | .env file present but not gitignored |
| `LD403` | Secrets & exposure | critical | Langflow auto-login not explicitly disabled |
| `LD501` | Hygiene | medium | Dependencies are not pinned |
| `LD502` | Hygiene | medium | GitHub Actions uses an unpinned third-party action |
<!-- END check-table -->

Severities for CVE checks are derived from the CVSS score; `🔴KEV` marks
[Known-Exploited](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
vulnerabilities, which are always surfaced first.

## CI integration

### GitHub Action

```yaml
# .github/workflows/langdoctor.yml
name: langdoctor
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: elaz48/langdoctor@v1
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: langdoctor.sarif
```

Findings show up in your repo's **Security → Code scanning** tab.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/elaz48/langdoctor
    rev: v0.1.0
    hooks:
      - id: langdoctor
```

### GitLab CI

```yaml
langdoctor:
  image: python:3.12-slim
  script:
    - pip install langdoctor
    - langdoctor --format sarif > gl-langdoctor.sarif
  artifacts:
    reports:
      sast: gl-langdoctor.sarif
```

## Configuration

Configure defaults in `pyproject.toml`; command-line flags take precedence.

```toml
[tool.langdoctor]
fail-on = "high"            # critical | high | medium | low | never
ignore  = ["LD203", "LD302"]
exclude = ["examples", "vendor"]
```

Suppress a single finding inline — by LD id, CVE, or any alias:

```python
API_KEY = get_key()  # langdoctor: ignore=LD401
```

```text
langgraph==1.0.5  # langdoctor: ignore=LD102
```

Suppressed findings are always reported as a `suppressed: N` count so nothing
disappears silently.

## Output formats

`--format console` (default) · `json` · `sarif` · `markdown`

- **sarif** — GitHub code scanning; `security-severity` carries the real CVSS.
- **markdown** — paste straight into a PR or issue.
- **json** — machine-readable, with a per-severity summary.

Exit codes: `0` clean (or below `--fail-on`), `1` findings at/above threshold,
`2` scan error. Heuristic checks never affect the exit code unless `--strict`.

## What langdoctor is NOT

- ❌ **Not a runtime guard.** It scans code and dependencies; it does not sit in
  your request path.
- ❌ **Not an LLM firewall.** It does no prompt-injection or content analysis.
- ❌ **Not a replacement for Semgrep/Snyk.** It's the *framework-specific* layer
  those miss — LangGraph/LangChain/Langflow footguns, by ID, with fixes.

It is deterministic (no AI calls), offline (CVE data ships in the package), and
zero-config.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Requires Python 3.10+. See [`CLAUDE.md`](CLAUDE.md) for design principles, the
check-ID conventions, and the "advisories are data" model.

## License

MIT © 2026 elaz48

<sub>Topics: langgraph · langchain · langflow · security · sast · ai-agents · llm-security · devsecops · cli</sub>
