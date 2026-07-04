# langdoctor 🩺

> Scan your LangGraph/LangChain project for known CVEs, insecure configs, and
> production footguns — in seconds, offline, no API key.
>
> _brew doctor for your agent stack._

**Status:** early development (Phase 1 skeleton). The full README — hero GIF,
"why", check table, CI snippets — lands in Phase 4 (see `langdoctor-spec.md` §8).

## Quickstart

```bash
pipx run langdoctor       # or: uvx langdoctor
```

Run it in a project directory. It scans your dependency files, reports known
CVEs and misconfigurations grouped by severity, and exits non-zero when
something at or above your threshold is found.

```bash
langdoctor                # scan current directory
langdoctor path/to/proj   # scan a specific directory
langdoctor list-checks    # list every check / advisory
langdoctor --version      # tool version + advisory DB date
```

## What it is / is NOT

- ✅ A deterministic, offline, framework-specific audit for
  LangGraph / LangChain / Langflow.
- ❌ Not a runtime guard, not an LLM firewall, not a replacement for
  Semgrep/Snyk — it's the framework-specific layer they miss.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Requires Python 3.10+. See `CLAUDE.md` for design principles and conventions.

MIT © 2026 elaz48
