"""Category 5xx (hygiene): supply-chain hardening checks.

Note: the spec's §3 file list did not name a hygiene module; this file houses
the 5xx catalog (LD501/LD502). Flagged as a minor, additive layout choice.
"""

from __future__ import annotations

import re

from ..analysis import read_project_file
from ..finding import Finding
from ..scanner import is_lockfile
from . import register_check

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# `uses: owner/repo@ref` — capture owner, repo path, and the ref. Anchored to a
# `uses:` KEY at the start of the line (after an optional list dash), so a
# commented-out step or a comment that quotes a `uses:` line is not an action.
_USES_RE = re.compile(
    r"""^\s*(?:-\s+)?uses:\s*["']?([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)@([^\s"']+)"""
)
# First-party / trusted orgs whose tag pins we don't flag.
_TRUSTED_ORGS = {"actions", "github"}


@register_check(
    id="LD501", category="hygiene", severity="medium",
    title="Dependencies are not pinned",
)
def unpinned_dependencies(project) -> list[Finding]:
    """One finding per manifest directory that no lockfile covers."""
    locked_dirs = {
        _parent(rel) for rel in project.present_files if is_lockfile(rel.rsplit("/", 1)[-1])
    }
    unpinned_by_dir: dict[str, list] = {}
    for dep in project.dependencies:
        # A container image is not a Python dependency; no lockfile pins it.
        if dep.version is None and not getattr(dep, "image", None):
            unpinned_by_dir.setdefault(_parent(dep.source), []).append(dep)

    findings = []
    for directory in sorted(unpinned_by_dir):
        if _is_locked(directory, locked_dirs):
            continue
        unpinned = unpinned_by_dir[directory]
        names = ", ".join(sorted({d.name for d in unpinned})[:5])
        where = f"{directory}/ has no lockfile" if directory else "No lockfile"
        findings.append(Finding(
            id="LD501", severity="medium",
            title="Dependencies are not pinned",
            detail=(
                f"{where} (uv.lock/poetry.lock) and {len(unpinned)} dependency(ies) are "
                f"unpinned ({names}). Unpinned dependencies weaken supply-chain reproducibility."
            ),
            file=unpinned[0].source,
            fix="Commit a uv.lock/poetry.lock, or pin versions with ==",
        ))
    return findings


def _parent(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _is_locked(directory: str, locked_dirs: set[str]) -> bool:
    """A lockfile covers its own directory and everything below it: a uv
    workspace keeps one uv.lock at the root for all of its members."""
    while True:
        if directory in locked_dirs:
            return True
        if not directory:
            return False
        directory = _parent(directory)


@register_check(
    id="LD502", category="hygiene", severity="medium",
    title="GitHub Actions uses an unpinned third-party action",
)
def unpinned_github_actions(project) -> list[Finding]:
    findings = []
    for rel in sorted(project.present_files):
        if not (rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml"))):
            continue
        text = read_project_file(project, rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _USES_RE.match(line)
            if not match:
                continue
            owner, repo, ref = match.groups()
            if owner.lower() in _TRUSTED_ORGS:
                continue
            if _SHA_RE.match(ref):
                continue  # already pinned to a full commit SHA
            findings.append(Finding(
                id="LD502", severity="medium",
                title="GitHub Actions uses an unpinned third-party action",
                detail=(
                    f"{owner}/{repo} is pinned to '{ref}' (a mutable tag/branch), not a commit "
                    "SHA. A compromised tag can inject code into CI (cf. the tj-actions/Trivy "
                    "supply-chain attacks). Pin to a full 40-char SHA."
                ),
                file=rel, line=lineno,
                fix=f"Pin {owner}/{repo} to a full commit SHA instead of @{ref}",
            ))
    return findings
