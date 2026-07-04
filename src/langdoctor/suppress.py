"""Inline suppression via `# langdoctor: ignore` comments.

- `# langdoctor: ignore` on a finding's line suppresses every finding there.
- `# langdoctor: ignore=LD203,LD302` suppresses only the listed IDs (matched
  against the LD id, the primary CVE, or any alias).

The directive is matched against the *finding's* file+line, so it works in
source files (the reported line) and in requirements.txt (the dependency line).
"""

from __future__ import annotations

import re

from .finding import Finding

_DIRECTIVE = re.compile(r"#\s*langdoctor:\s*ignore(?:\s*=\s*([\w,\-. ]+))?", re.IGNORECASE)


def line_ignore_tokens(line: str) -> frozenset[str] | None:
    """None = no directive; empty set = ignore-all; else the listed tokens (lowercased)."""
    match = _DIRECTIVE.search(line)
    if not match:
        return None
    group = match.group(1)
    if not group:
        return frozenset()
    return frozenset(t.strip().lower() for t in group.split(",") if t.strip())


def inline_suppressed(project, finding: Finding, cache: dict) -> bool:
    if not finding.file or not finding.line:
        return False
    lines = cache.get(finding.file)
    if lines is None:
        try:
            text = (project.root / finding.file).read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except OSError:
            lines = []
        cache[finding.file] = lines
    idx = finding.line - 1
    if idx < 0 or idx >= len(lines):
        return False
    tokens = line_ignore_tokens(lines[idx])
    if tokens is None:
        return False
    if not tokens:  # bare `# langdoctor: ignore` -> suppress everything on this line
        return True
    return any(finding.matches_id(token) for token in tokens)
