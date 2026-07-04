"""Category 5xx (hygiene): supply-chain hardening checks.

Note: the spec's §3 file list did not name a hygiene module; this file houses
the 5xx catalog (LD501/LD502). Flagged as a minor, additive layout choice.
"""

from __future__ import annotations

import re

from ..analysis import read_project_file
from ..finding import Finding
from . import register_check

_LOCKFILES = {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# `uses: owner/repo@ref` — capture owner, repo path, and the ref.
_USES_RE = re.compile(r"""uses:\s*["']?([A-Za-z0-9._-]+)/([A-Za-z0-9._/-]+)@([^\s"']+)""")
# First-party / trusted orgs whose tag pins we don't flag.
_TRUSTED_ORGS = {"actions", "github"}


@register_check(
    id="LD501", category="hygiene", severity="medium",
    title="Dependencies are not pinned",
)
def unpinned_dependencies(project) -> list[Finding]:
    if not project.dependencies:
        return []
    if _LOCKFILES & project.present_files:
        return []
    unpinned = [d for d in project.dependencies if d.version is None]
    if not unpinned:
        return []
    names = ", ".join(sorted({d.name for d in unpinned})[:5])
    return [Finding(
        id="LD501", severity="medium",
        title="Dependencies are not pinned",
        detail=(
            f"No lockfile (uv.lock/poetry.lock) and {len(unpinned)} dependency(ies) are unpinned "
            f"({names}). Unpinned dependencies weaken supply-chain reproducibility."
        ),
        fix="Commit a uv.lock/poetry.lock, or pin versions with ==",
    )]


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
            match = _USES_RE.search(line)
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
