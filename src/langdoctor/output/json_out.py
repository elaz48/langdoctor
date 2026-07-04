"""Machine-readable JSON output."""

from __future__ import annotations

import json

from .. import __version__
from ..finding import Finding
from . import finding_to_dict, summarize


def render_json(findings: list[Finding], project_root, db_date: str, suppressed: int = 0) -> str:
    doc = {
        "tool": "langdoctor",
        "version": __version__,
        "advisories_updated": db_date,
        "summary": summarize(findings, suppressed),
        "findings": [finding_to_dict(f) for f in findings],
    }
    return json.dumps(doc, indent=2)
