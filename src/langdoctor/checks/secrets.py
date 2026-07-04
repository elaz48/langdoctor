"""Category 4xx (secrets): hardcoded credentials and .env hygiene."""

from __future__ import annotations

import re

from ..analysis import load_sources
from ..finding import Finding
from . import register_check

# Ordered most-specific-first so an Anthropic key is not mislabeled as generic OpenAI.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI project key", re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
]


@register_check(
    id="LD401", category="secrets", severity="critical",
    title="Hardcoded API key in source",
)
def hardcoded_secrets(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        for lineno, line in enumerate(sf.lines, start=1):
            # Inline `# langdoctor: ignore` is applied centrally by the engine.
            for label, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id="LD401", severity="critical",
                        title=f"Hardcoded {label} in source",
                        detail=(
                            "A credential appears hardcoded in source. Move it to an environment "
                            "variable or secret manager and rotate the exposed key."
                        ),
                        file=sf.rel, line=lineno,
                        fix="Remove the secret, load it from the environment, and rotate it",
                    ))
                    break  # one finding per line
    return findings


@register_check(
    id="LD402", category="secrets", severity="high",
    title=".env file present but not gitignored",
)
def env_not_gitignored(project) -> list[Finding]:
    env_files = [f for f in project.present_files if f == ".env" or f.endswith("/.env")]
    if not env_files:
        return []
    patterns = _gitignore_patterns(project)
    findings = []
    for env_file in env_files:
        if not _is_ignored(env_file, patterns):
            findings.append(Finding(
                id="LD402", severity="high",
                title=".env file present but not gitignored",
                detail=(
                    f"{env_file} is present but not covered by .gitignore — a stray commit would "
                    "leak its secrets."
                ),
                file=env_file,
                fix="Add .env to .gitignore",
            ))
    return findings


def _gitignore_patterns(project) -> list[str]:
    gitignore = project.root / ".gitignore"
    if not gitignore.is_file():
        return []
    text = gitignore.read_text(encoding="utf-8", errors="replace")
    return [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _is_ignored(env_file: str, patterns: list[str]) -> bool:
    base = env_file.split("/")[-1]
    for raw in patterns:
        pat = raw.lstrip("/").rstrip("/")
        if pat in (base, env_file, "*.env") or pat.endswith(".env"):
            return True
    return False
