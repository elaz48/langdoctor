# CLAUDE.md

Guidance for Claude Code working in this repository. The authoritative brief is
`langdoctor-spec.md`; this file distills the parts that must stay consistent
across sessions.

## Project

**langdoctor** — a production-readiness and security audit CLI for
LangGraph / LangChain / Langflow projects. "brew doctor for your agent stack."
Scans a project for known CVEs, insecure configs, and production footguns —
in seconds, offline, no API key. MIT licensed (© 2026 elaz48).

## Design principles (non-negotiable)

1. **Deterministic.** No AI/LLM API calls. Same input → same output, always.
2. **Offline-first.** Zero network calls during a scan. CVE data ships in the
   package (`src/langdoctor/data/advisories.json`).
3. **Zero-config.** `pipx run langdoctor` / `uvx langdoctor` in a project dir must
   produce useful output with no setup.
4. **CI-native.** Meaningful exit codes, JSON/SARIF/markdown output, quiet mode.
5. **Fast.** Full scan of a typical project under ~2s.

Non-goals (v1): runtime monitoring, prompt-injection detection, LLM-based
analysis, frameworks other than LangChain/LangGraph/Langflow.

## Architecture map

`scanner` (discover project files) → `engine` (run registered checks) →
`Finding`s → `output/` (console | json | sarif | markdown). Full tree in spec §3.

- **Checks are data-driven where possible.** Version/CVE checks read
  `advisories.json`; code-pattern checks are Python functions registered via
  `@register_check(...)`.
- **Dependency sources:** manifests anywhere in the tree (requirements files
  and their `-r` includes, pyproject, uv/poetry/pdm/Pipfile/pylock lockfiles)
  plus container images (`containers.py`: Dockerfile `FROM`, YAML `image:`).
  An image is an install of a package at the version its tag names.
- Keep dependencies minimal and pure-Python: `rich`, `packaging`,
  `tomli` (only < 3.11; use stdlib `tomllib` on 3.11+), stdlib `ast`.

## Advisories are DATA, not code

Adding a new CVE = edit `advisories.json` + add one vulnerable/clean fixture
pair + ship a **patch** release. Never hardcode a CVE threshold in Python. The
advisory DB is the product's live surface and its marketing engine (spec §9).

**Which container image means which package is data too:** the top-level
`container_images` map in `advisories.json`. Add an image only after checking
the vendor's release workflow that its tags are versions of that package:
Langflow's `base-*` tags are `langflow-base` versions, a different line, which
is why a prefixed tag is never read as a version.

`advisories.json` is **schema_version 2** (spec §5). Key rules:
- Version applicability via `affected_ranges` (OSV-style `{introduced, fixed}`
  list, compared with `packaging.version`). `fixed_in` is a human summary ONLY —
  never the comparison source of truth. This models dual-line fixes (e.g. LD105
  patched on both 0.3.x and 1.x).
- **Severity is derived from `cvss_score`** via `severity_buckets`
  (≥9.0 critical / ≥7.0 high / ≥4.0 medium / ≥0.1 low). `severity_override`
  wins when set (CNA-vs-NVD disagreements happen — see LD105).
- `exploited_in_the_wild` (KEV) bumps display priority above all non-KEV
  findings regardless of CVSS, with a 🔴 KEV badge.
- `aliases` (GHSA/PYSEC/duplicate CVE IDs): lookup, `--ignore`, and inline
  `# langdoctor: ignore=` suppression must match the LD id, primary CVE, OR any
  alias. The engine must tolerate unknown fields (forward compatibility).

## The scanned tree is untrusted input

langdoctor runs in CI on fork pull requests, so every file name and file body
is attacker-chosen. Rules that keep the gate standing:
- **Never read outside the scan root** — not via `-r` includes, not via
  symlinks (`scanner._inside_project`).
- **Parsers are total:** any TOML/JSON shape in, a list out — check types at
  each level instead of wrapping a parser in a catch-all, which would hide a
  real bug and silently drop a manifest (`test_manifest_parsers_accept_any_shape_of_data`).
- **Line patterns must be linear.** No unbounded group that can rescan to the
  end of the line; `containers.py` also skips lines over 4 KB. Time a new regex
  on a 100k-character worst case before shipping it.
- **Repository-derived text is sanitised at the output layer:** `printable()`
  for the console, `_escape()` for Markdown; JSON and SARIF are escaped by
  `json.dumps`.

## Check-ID conventions

Every advisory/check has a stable ID `LD###`, categorized by hundreds:
- `1xx` known vulnerabilities (data-driven), `2xx` checkpointer & state,
  `3xx` graph & runtime config, `4xx` secrets & exposure, `5xx` hygiene.
- IDs are permanent identifiers — never renumber a shipped ID; deprecate instead:
  set `deprecated` (ISO date) and `superseded_by` on the entry and keep it in
  `advisories.json`. It then never fires and `list-checks` marks it; its
  successor inherits its ID and aliases for matching, so existing `ignore`s keep
  working; and its identifiers keep the watcher from re-alerting.
  Example: LD112 → LD133.
- Users suppress by ID; docs deep-link by ID.

## False-positive policy

Heuristic checks (LD203, LD204, LD302) MUST print "heuristic" in output and MUST
NOT affect CI exit code by default — only under `--strict`. Trust is the product.

## Verification discipline (learned in Phase 0)

**OSV.dev lags NVD and vendor advisories.** CVE-2026-5027 (LD111) was real and
actively exploited but absent from OSV at build time. When adding/verifying an
advisory: cross-check ≥2 sources (OSV + NVD + GitHub Security Advisories /
vendor), record every identifier in `aliases`, and pull CVSS base scores from
NVD (do not hand-compute). Numbers are "verified-as-of a date," never permanent.

## Advisory watcher

`scripts/advisory_watch.py` (weekly workflow) diffs OSV and the CISA KEV catalog
against `advisories.json` and alerts on the delta. It also checks NVD for
**baseline drift** of aggregate advisories (`scripts/baseline_drift.py`): a CVE
affecting a version at/above LD150's baseline with no LD entry of its own. IBM
PSIRT's Langflow CVEs never reach OSV, so this is the only signal for them. A new
aggregate advisory needs its NVD keyword in `baseline_drift.NVD_KEYWORDS` (the
watcher warns otherwise). `scripts/watch-ignore.json` lists advisories that are
**intentionally out of scope** (pre-2025 historical langchain/langchain-core CVEs
and code paths we don't model) — do NOT "clean it up" or add planned-coverage
items (e.g. the Langflow long tail) to it; those belong in `.watch-state.json`.

## Commands

Python 3.10+ (ecosystem floor, verified). Cross-platform: `pathlib` everywhere,
no shelling out, explicit UTF-8 (`encoding="utf-8", errors="replace"`), respect
`NO_COLOR` and non-TTY.

| Task | Command |
|------|---------|
| Run | `python -m langdoctor [PATH]` (editable: `pip install -e .`) |
| Test | `pytest` (target suite < 30s) |
| Lint | `ruff check .` / `ruff format .` |
| Build | `uv build` |

## Release / deployment constraints (IMPORTANT)

- **PyPI Trusted Publishing (OIDC, no stored token).** The release workflow MUST
  match the pre-configured Trusted Publisher exactly or publishing fails:
  owner `elaz48`, repo `langdoctor`, workflow filename `release.yml`,
  environment `pypi`. Release trigger: push tag `vX.Y.Z` → full test matrix →
  `uv build` → publish → GitHub Release with changelog.
- **The Action is documented as `elaz48/langdoctor@v0`** — a moving major tag
  that `release.yml`'s `major-tag` job force-moves to the newest release of its
  line (it becomes `@v1` at 1.0). Docs
  must never name a major tag that has no release behind it;
  `tests/test_repo_consistency.py` enforces this and the README's pre-commit
  `rev`, so a version bump has to update the README in the same commit.
- **`release.yml` is split on purpose:** `test → build → publish →
  github-release / major-tag`. Only `publish` holds `id-token: write` (with
  `environment: pypi`), and it runs nothing but the artifact download and the
  PyPA publish action — never add a build step, a shell step or `contents:
  write` to it. Every action in that file is pinned to a commit SHA, and `build`
  refuses a tag whose commit is not on `main` (push `main` before the tag).
  `tests/test_repo_consistency.py` enforces all of this.
- **CI matrix:** ubuntu / macos / windows × Python 3.10 / 3.12 / 3.13; ruff + pytest.
  CI also runs `langdoctor .` on this repo and `action.yml` from the checkout.
- **Website (`langdoctor.dev`)** is a single self-contained static HTML file
  (spec §10), uploaded **manually via FTP to PHP/DirectAdmin shared hosting**.
  Do NOT set up GitHub Pages or any Actions-based site deploy.

## Working agreement

Build phase-by-phase per spec §11 (skeleton → full catalog → output/integration
→ polish/release → website). Pause for review at the end of each phase. Follow
the spec's architecture, check catalog, and CLI exactly unless there's a
concrete technical reason to deviate — then flag it, don't silently change course.
