# langdoctor — Project Specification v1

> Production-readiness and security audit CLI for LangGraph / LangChain projects.
> "brew doctor for your agent stack."
>
> This document is the master brief for building langdoctor with Claude Code.
> Work in phases. Do not skip Phase 0.

---

## 1. Positioning

- One-line pitch: **Scan your LangGraph/LangChain project for known CVEs, insecure configs, and production footguns — in 5 seconds, offline, no API key.**
- Audience: developers running LangGraph/LangChain agents in production or preparing to.
- Non-goals (v1): runtime monitoring, prompt-injection detection, LLM-based analysis, frameworks other than LangChain/LangGraph/Langflow.
- Design principles:
  1. **Deterministic.** No AI API calls. Same input, same output, always.
  2. **Offline-first.** Zero network calls during a scan. CVE data ships with the package.
  3. **Zero-config.** `pipx run langdoctor` in a project directory must produce useful output with no setup.
  4. **CI-native.** Exit codes, JSON/SARIF output, quiet mode.
  5. **Fast.** Full scan of a typical project under 2 seconds.

---

## 2. Tech stack

- **Python 3.10+** (matches LangChain's supported floor; verify current floor at build time).
- Dependencies: keep minimal and pure-Python so it runs anywhere:
  - `rich` (terminal output)
  - `packaging` (version comparison)
  - `tomli` (only for Python < 3.11; use stdlib `tomllib` on 3.11+)
  - stdlib `ast` for Python source analysis (no tree-sitter in v1)
- **Platform independence: YES, and it is nearly free.** This is a text-processing CLI, so cross-platform costs almost nothing if these rules are followed:
  - Use `pathlib` everywhere, never string-concatenated paths.
  - No `os.system`, no shelling out.
  - Respect `NO_COLOR` env var and non-TTY output (rich handles this; verify).
  - Handle UTF-8 explicitly when reading files (`encoding="utf-8", errors="replace"`).
  - CI test matrix: ubuntu-latest, macos-latest, windows-latest × Python 3.10 / 3.12 / 3.13.

---

## 3. Architecture

```
langdoctor/
├── pyproject.toml            # PEP 621, hatchling or uv build backend
├── README.md                 # see section 8
├── LICENSE                   # MIT
├── CHANGELOG.md              # Keep a Changelog format
├── src/langdoctor/
│   ├── __init__.py           # __version__
│   ├── cli.py                # argparse or typer-free argparse; keep deps low
│   ├── scanner.py            # project discovery: find pyproject/requirements/lockfiles, python sources
│   ├── engine.py             # runs all registered checks, collects Findings
│   ├── finding.py            # Finding dataclass: id, severity, title, detail, file, line, fix, refs
│   ├── checks/
│   │   ├── __init__.py       # check registry (decorator-based registration)
│   │   ├── versions.py       # CVE / version-threshold checks (data-driven)
│   │   ├── checkpointer.py   # checkpointer config checks
│   │   ├── config.py         # graph config checks (recursion limit, timeouts)
│   │   ├── secrets.py        # hardcoded API key detection
│   │   └── exposure.py       # untrusted-input / endpoint exposure heuristics
│   ├── data/
│   │   └── advisories.json   # THE CVE DATABASE — see section 5
│   └── output/
│       ├── console.py        # rich human output
│       ├── json_out.py       # machine-readable
│       └── sarif.py          # GitHub code scanning integration
└── tests/
    ├── fixtures/             # sample vulnerable + clean projects
    └── test_*.py
```

Key design decision: **checks are data-driven where possible.** Version/CVE checks read `advisories.json`; adding a new CVE means editing one JSON file and shipping a patch release. Code-pattern checks are Python functions registered via decorator:

```python
@register_check(id="LD201", severity="high", category="checkpointer")
def memory_saver_in_prod(project: Project) -> list[Finding]: ...
```

Every check has a stable ID (`LD###`), so users can suppress individual checks and docs can deep-link.

---

## 4. Check catalog (v1)

Severity levels: `critical` / `high` / `medium` / `low` / `info`.

### Category 1xx — Known vulnerabilities (data-driven from advisories.json)
> **Phase 0 verification (2026-07-04):** every threshold/CVE below was verified against OSV.dev, NVD, PyPI, and vendor advisories. `✓` = confirmed as originally written; `⚠` = corrected. Full v0.1.0 machine data (CVSS vectors/scores, aliases, KEV flags) lives in `advisories.json` (§5); this list is the human index.
>
> **Lesson learned (encode in CLAUDE.md):** OSV.dev *lags* NVD/vendor advisories. CVE-2026-5027 (LD111) is real and actively exploited but is not yet in OSV — it surfaced only via NVD + Tenable TRA-2026-26. Always cross-check ≥2 sources, and use the `aliases` array so a vuln is findable under any of its identifiers.

**Checkpointer / serializer / core CVEs** (data-driven version checks):
- **LD101** `langgraph-checkpoint-sqlite` < 3.0.1 → SQL injection via metadata filter key, CVE-2025-67644 ✓
- **LD102** `langgraph` < 1.0.10 → unsafe msgpack checkpoint deserialization RCE, CVE-2026-28277 ✓
- **LD103** ⚠ `langgraph-checkpoint` < 4.1.1 → unsafe JSON deserialization in checkpoint loading, CVE-2026-48775 — *corrected: original `langgraph-checkpoint-redis` < 1.0.2 / CVE-2026-27022 is fictional (that package's highest release ever is 0.5.0; zero advisories). Repointed to the real base-package CVE.*
- **LD104** ⚠ `langchain-core` < 1.2.22 → path traversal in legacy `load_prompt`, CVE-2026-34070 — *corrected: no `< 0.3.86` backport; single fix at 1.2.22.*
- **LD105** `langchain-core` < 1.2.5 (1.x line) **or** < 0.3.81 (0.3.x line) → serialization-injection secret extraction in `dumps`, CVE-2025-68664 ✓ *(dual-line fix confirmed — see `affected_ranges` in §5)*
- **LD107** `langgraph-checkpoint` < 4.0.0 → `BaseCache` deserialization of untrusted data → RCE, CVE-2026-27794 *(added per decision 1)*
- **LD108** `langgraph-checkpoint` < 3.0.0 → RCE in "json" mode of `JsonPlusSerializer`, CVE-2025-64439 *(added per decision 1)*
- **LD109** `langgraph-checkpoint-sqlite` < 2.0.11 → SQL injection in SQLite store, CVE-2025-8709 *(added per decision 2)*
- **LD110** `langgraph-checkpoint-sqlite` < 2.0.11 → SQL injection via filter key in `SqliteStore`, CVE-2025-64104 *(added per decision 2)*

> LD101/LD109/LD110 share the SQLite-checkpointer package but carry **independent thresholds** (3.0.1 vs 2.0.11) so a project pinned between 2.0.11 and 3.0.1 gets accurate per-CVE results.

**Langflow** (decision 3 — KEV/exploited entries individually; long tail deferred to post-v0.1 patches):
- **LD106** `langflow` < 1.3.0 → unauthenticated RCE in `/api/v1/validate/code`, **CVE-2025-3248** — CVSS 9.8, **CISA KEV** (added 2025-05-05), exploited by the Flodrix botnet. `exploited_in_the_wild: true`. *(reassigned from the interim CVE-2026-48520, which moves to the long tail.)*
- **LD111** `langflow` < 1.9.0 (and `langflow-base` < 0.8.3) → path traversal → RCE via `/api/v2/files` `upload_user_file()`, **CVE-2026-5027** — CVSS 8.8, VulnCheck-confirmed active exploitation, the "~7,000 exposed instances" incident (Tenable TRA-2026-26). `exploited_in_the_wild: true`. *(Not in OSV yet; likely the same root cause as OSV's CVE-2026-33309 "arbitrary file write via v2 API, fixed 1.9.0" — record that as an alias candidate but do not hard-merge without confirmation.)*
- **LD150** `langflow` < 1.10.1 → **catch-all**: "Langflow older than the current secure baseline (1.10.1) — N known vulnerabilities, upgrade recommended." Aggregate advisory covering the long tail not yet enumerated as individual LD entries. Engine must present it without double-counting the individual Langflow findings above.

> **Post-v0.1 pipeline (not in v0.1.0):** the ~25 remaining individual Langflow CVEs (e.g. CVE-2026-48520, CVE-2026-48519, CVE-2026-33017, CVE-2026-0770, CVE-2026-21445 …) are enumerated one-per-patch-release via the recurring update loop in §9.

- **IMPORTANT for Claude Code:** advisory data is a moving target. Re-verify every threshold/CVE against OSV.dev **+ NVD + vendor advisories** at each release. Numbers are verified-as-of the date noted, not permanent.

### Category 2xx — Checkpointer & state
- **LD201** `MemorySaver` used while project looks production-bound (Dockerfile, k8s manifests, or fly/render config present) (high)
- **LD202** `SqliteSaver` used — warn about write-throughput collapse under concurrency, recommend `PostgresSaver` (medium)
- **LD203** Checkpoint store reachable from user-controlled filter input: heuristic — `get_state_history(` called with a variable that flows from a FastAPI/Flask request parameter in the same file (high; mark as heuristic in output)
- **LD204** No checkpointer configured at all on a compiled graph that has interrupts/HITL nodes (medium)

### Category 3xx — Graph & runtime config
- **LD301** No `recursion_limit` set anywhere → runaway-loop cost risk (medium)
- **LD302** No timeout on LLM/tool calls detected (low, heuristic)
- **LD303** Deprecated pre-1.0 imports (`langchain.agents.AgentExecutor` etc.) (info)
- **LD304** `load_prompt()` legacy API usage (ties into LD104) (high)

### Category 4xx — Secrets & exposure
- **LD401** Hardcoded API keys in source (regex for `sk-ant-`, `sk-proj-`, `sk-` + entropy, AWS patterns) (critical)
- **LD402** `.env` file present but missing from `.gitignore` (high)
- **LD403** Langflow present with auto-login not explicitly disabled (`LANGFLOW_AUTO_LOGIN` not set to false in env/config) (critical — this is the actively exploited default)

### Category 5xx — Hygiene
- **LD501** Dependencies not pinned (no lockfile: uv.lock/poetry.lock/requirements with ==) — supply-chain hardening (medium)
- **LD502** GitHub Actions workflows use unpinned third-party actions (tag instead of SHA) (medium; motivated by the LiteLLM/Trivy supply-chain attack)

False-positive policy: heuristic checks (LD203, LD302) must say "heuristic" in output and never fail CI by default (only with `--strict`).

---

## 5. advisories.json format (schema_version 2)

```json
{
  "schema_version": 2,
  "updated": "2026-07-04",
  "severity_buckets": { "critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1 },
  "advisories": [
    {
      "id": "LD106",
      "package": "langflow",
      "cve": "CVE-2025-3248",
      "aliases": ["GHSA-rvqx-wpfh-mfx7", "PYSEC-2025-36", "PYSEC-2026-380"],
      "affected_ranges": [ { "introduced": "0", "fixed": "1.3.0" } ],
      "fixed_in": "1.3.0",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity_override": null,
      "exploited_in_the_wild": true,
      "title": "Unauthenticated RCE in /api/v1/validate/code",
      "detail": "Missing authentication on the code-validation endpoint lets a remote, unauthenticated attacker execute arbitrary code via crafted HTTP requests (Python decorator / default-argument abuse). Exploited in the wild to deploy the Flodrix botnet; added to CISA KEV 2025-05-05.",
      "refs": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-3248",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://github.com/advisories/GHSA-rvqx-wpfh-mfx7"
      ]
    },
    {
      "id": "LD105",
      "package": "langchain-core",
      "cve": "CVE-2025-68664",
      "aliases": ["GHSA-c67j-w6g6-q2cm", "PYSEC-2026-373"],
      "affected_ranges": [
        { "introduced": "0",     "fixed": "0.3.81" },
        { "introduced": "1.0.0", "fixed": "1.2.5"  }
      ],
      "fixed_in": "1.2.5 (1.x line) / 0.3.81 (0.3.x line)",
      "cvss_score": 9.3,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
      "severity_override": null,
      "exploited_in_the_wild": false,
      "title": "Serialization-injection secret extraction in dumps/loads",
      "detail": "Crafted serialized payloads can inject attributes during load, enabling extraction of secrets embedded in serialized objects. Note: CNA scores this 9.3, NVD scores it 8.2 — an example of when severity_override may be warranted.",
      "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2025-68664", "https://github.com/advisories/GHSA-c67j-w6g6-q2cm"]
    }
  ]
}
```

### Schema rules (v2)

- **Versioned + forward-compatible.** `schema_version` gates parsing; the engine MUST ignore unknown fields so a newer advisory DB loads on an older tool build (and vice-versa).
- **Version applicability via `affected_ranges`** — OSV-style list of `{introduced, fixed}` pairs. A target version is *affected* if it satisfies any range `introduced <= v < fixed` (compared with `packaging.version`, pre-releases included). This correctly models **dual-line fixes** (LD105: patched on both the 0.3.x and 1.x lines) and non-zero `introduced` boundaries (e.g. LD108). `fixed_in` is a **human-readable summary only** — never the comparison source of truth.
- **Severity is derived, not hand-authored.** Bucket = the highest key in `severity_buckets` whose threshold `cvss_score` meets (≥9.0 → critical, ≥7.0 → high, ≥4.0 → medium, ≥0.1 → low). `severity_override` (nullable string) wins when set — for the CNA-vs-NVD disagreements and real-world-risk mismatches this project will hit regularly.
- **`exploited_in_the_wild` (KEV flag).** Boolean, sourced from CISA KEV + confirmed vendor/threat-intel reporting. A true value bumps the finding above all non-KEV findings regardless of CVSS and renders a distinct 🔴 KEV badge in output.
- **`aliases`.** Alternate identifiers (GHSA, PYSEC, duplicate/news-coverage CVE IDs). Output shows the primary `cve` plus aliases. **Check lookup, `--ignore`, and inline `# langdoctor: ignore=` suppression MUST match on the LD id, the primary CVE, OR any alias** — so a user who only knows the vuln under its news-coverage identifier can still reference/suppress it. (Motivating case: CVE-2026-5027 ≡ the LD111 Langflow path-traversal, which OSV had not yet indexed at build time.)
- **References.** Every advisory carries at least one `refs` URL.
- **Catch-all advisories** (e.g. LD150) may omit `cve`/`cvss_score` and instead set an explicit `severity_override`; the engine treats a missing `cvss_score` as "override required."

---

## 6. CLI / UX specification

```
langdoctor [PATH] [options]
```

- **Default run:** scans current directory, prints a rich report: summary header (X critical / Y high / ...), then findings grouped by severity, each with file:line, explanation, and a concrete fix line (e.g. `→ pip install "langgraph>=1.0.10"`).
- `--format console|json|sarif|markdown` (markdown output is great for pasting into PRs/issues)
- `--fail-on critical|high|medium|never` → exit code 1 at/above threshold (default: high). Exit 0 = clean, 1 = findings at threshold, 2 = scan error.
- `--strict` → heuristics also affect exit code
- `--ignore LD203,LD302` and inline suppression comment: `# langdoctor: ignore=LD203`
- Config file: `[tool.langdoctor]` section in pyproject.toml (ignore list, fail-on, paths to exclude)
- `--quiet` / `--verbose`
- `langdoctor list-checks` → table of all checks with IDs, severity, description
- `langdoctor --version` prints tool version **and advisory DB date** ("advisories as of 2026-07-04") — this builds trust and nudges updates.
- Delight detail: when the scan is clean, print a friendly all-clear with a stethoscope 🩺 and suggest running in CI.
- **GitHub Action:** ship `action.yml` in the repo so users can add one step: `uses: elaz48/langdoctor@v1`. SARIF output wires findings into the GitHub Security tab. This is a major adoption lever.
- **pre-commit hook:** provide `.pre-commit-hooks.yaml`.

---

## 7. Testing & quality bar

- pytest; every check gets at least one vulnerable fixture and one clean fixture.
- Fixture projects live in `tests/fixtures/` as minimal but realistic project skeletons (pyproject + a couple of .py files).
- Version-comparison edge cases: pre-releases, extras, `>=` specifiers in requirements, uv.lock and poetry.lock parsing.
- CI: GitHub Actions, 3-OS × 3-Python matrix, ruff + pytest.
- Target: entire test suite < 30s.

---

## 8. README requirements

- Hero: one-line pitch + terminal-output GIF/screencast at the very top (record with vhs or asciinema→gif).
- 10-second quickstart: `pipx run langdoctor` / `uvx langdoctor`.
- "Why" section anchored in the 2026 incident wave (Langflow exploitation, LangGraph checkpointer CVEs, LiteLLM supply-chain attack) with links.
- Full check table (generated from `list-checks`).
- CI integration snippets: GitHub Action, pre-commit, GitLab CI.
- "What langdoctor is NOT" section (not a runtime guard, not an LLM firewall, not a replacement for Semgrep) — honesty builds trust, same pattern that worked in PlaceboPay's README.
- SEO topics for the repo: `langgraph`, `langchain`, `security`, `sast`, `ai-agents`, `llm-security`, `devsecops`, `cli`.

---

## 9. Release & update process (IMPORTANT — recurring workflow)

Initial setup:
1. Reserve the `langdoctor` name on PyPI immediately with a 0.1.0 (PyPI has no name reclamation; first come, first served).
2. Configure **PyPI Trusted Publishing** (OIDC from GitHub Actions — no API token stored anywhere).
3. Release workflow: push tag `vX.Y.Z` → CI runs tests on full matrix → builds with `uv build` → publishes → creates GitHub Release with changelog section.

Versioning policy:
- Patch (0.1.x): advisory DB updates, fix tweaks. **This is the common case.**
- Minor (0.x.0): new checks, new output formats.
- Major: CLI-breaking changes only.

**The recurring update loop (this is also the marketing engine):**
1. New CVE drops for LangChain/LangGraph/Langflow (sources: GitHub Security Advisories for the langchain-ai org, NVD feed, r/LangChain, Hacker News).
2. Add one entry to `advisories.json` + one vulnerable/clean fixture pair. (~30 min)
3. Tag a patch release → auto-publish.
4. Same day: LinkedIn post + tweet: "langdoctor 0.1.x now detects CVE-XXXX-XXXXX — update and scan your agents." Link the news coverage.
- Set up a GitHub Actions **scheduled weekly job** that checks langchain-ai advisory feed and opens an issue if a new advisory isn't covered — the repo maintains itself as a to-do list.

Framework-evolution risk: post-1.0 LangGraph API churn is modest; checks target imports/config patterns that move slowly. Budget ~1-2 hours/month maintenance.

---

## 10. Website — langdoctor.dev

Style: same school as placebopay.dev — single static page, fast, dark, developer-native. No framework needed; one HTML file, self-hostable.

Sections, top to bottom:
1. **Hero:** name, stethoscope motif, one-liner, and an animated terminal (CSS/JS typewriter of a real scan output — findings appearing line by line, red/yellow/green).
2. **Install:** `pipx install langdoctor` with copy button.
3. **The problem:** 3 stat cards — "7,000 exposed Langflow servers under active attack", "60M weekly downloads across the ecosystem", "60%+ of production agent incidents tied to state management" — each linking its source.
4. **Check catalog:** compact table of LD-codes.
5. **CI section:** GitHub Action YAML snippet.
6. **FAQ:** "Does it send my code anywhere?" (No. Fully offline.) "Does it need an API key?" (No.) "Is this a replacement for Semgrep/Snyk?" (No — it's the framework-specific layer they miss.)
7. **Footer:** Built by Balazs → LinkedIn (VERIFY THE LINK BEFORE DEPLOY), GitHub repo, MIT.
- OG image: terminal screenshot with a critical finding — that's what gets shared.
- Hosting: GitHub Pages or any static host; add a `site/` directory in the repo so the page versions with the code.

---

## 11. Claude Code execution plan

Suggested phases (each a separate session or clear checkpoint):

- **Phase 0 — Verify (do first, uses web access if available):** confirm current CVE IDs + fixed versions, current LangGraph/LangChain package names and version lines, PyPI name availability. Update section 4/5 data accordingly.
- **Phase 1 — Skeleton:** pyproject, package layout, Finding model, check registry, scanner (dependency file parsing: requirements.txt, pyproject, uv.lock, poetry.lock), console output, 2 version checks working end-to-end with tests.
- **Phase 2 — Full check catalog:** all 1xx-5xx checks + fixtures + tests.
- **Phase 3 — Output & integration:** JSON, SARIF, markdown formats; exit codes; config file; ignore mechanics; GitHub Action; pre-commit hook.
- **Phase 4 — Polish:** README + GIF, CHANGELOG, CI matrix, trusted publishing, tag v0.1.0.
- **Phase 5 — Website:** single-file static page per section 10.

Put a `CLAUDE.md` in the repo root distilling: design principles (section 1), check-ID conventions, "advisories are data, not code", and the FP policy. That keeps later sessions consistent.

Definition of done for v0.1.0: fresh `pipx install langdoctor` on a clean machine, run against a deliberately vulnerable fixture project, produces correct findings with correct exit code, on Linux + macOS + Windows CI, README GIF included.
