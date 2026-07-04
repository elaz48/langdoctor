"""The Finding model — one issue detected by one check."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Finding:
    """An immutable record of a single detected issue.

    Findings are values: checks return them, the engine sorts/suppresses them,
    and the output layer renders them. Nothing mutates a Finding in place.
    """

    id: str
    severity: str
    title: str
    detail: str = ""
    file: str | None = None
    line: int | None = None
    fix: str | None = None
    cve: str | None = None
    aliases: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()
    heuristic: bool = False
    exploited_in_the_wild: bool = False
    cvss_score: float | None = None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def matches_id(self, token: str) -> bool:
        """True if `token` names this finding by LD id, primary CVE, or any alias.

        Used by suppression (`--ignore`, inline comments, pyproject config) so a
        vuln stays suppressible under whichever identifier the user knows it by.
        """
        token = token.strip().lower()
        if not token:
            return False
        candidates = {self.id.lower()}
        if self.cve:
            candidates.add(self.cve.lower())
        candidates.update(a.lower() for a in self.aliases)
        return token in candidates
