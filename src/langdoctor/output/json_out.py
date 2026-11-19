"""Machine-readable JSON output."""

from __future__ import annotations

import json

from .. import __version__
from ..finding import Finding
from . import finding_to_dict, summarize


def render_json(
    findings: list[Finding], project_root, db_date: str, suppressed: int = 0,
    not_counted: int = 0, errors: list[str] | None = None,
) -> str:
    doc = {
        "tool": "langdoctor",
        "version": __version__,
        "advisories_updated": db_date,
        # not_counted: findings --allow-unimported kept from failing the run
        "summary": {**summarize(findings, suppressed), "not_counted": not_counted},
        "findings": [finding_to_dict(f) for f in findings],
        # checks that crashed: non-empty means the findings are incomplete
        "errors": list(errors or ()),
    }
    return json.dumps(doc, indent=2)
