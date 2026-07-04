"""SARIF 2.1.0 output for GitHub code scanning (Security tab integration)."""

from __future__ import annotations

import json

from .. import __version__
from ..finding import Finding
from . import security_severity

_HOME = "https://langdoctor.dev"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF levels: error / warning / note / none.
_SEVERITY_TO_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"
}


def render_sarif(findings: list[Finding], project_root, db_date: str, suppressed: int = 0) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rules.setdefault(f.id, _rule(f))
        results.append(_result(f))

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "langdoctor",
                        "informationUri": _HOME,
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"advisoriesUpdated": db_date, "suppressed": suppressed},
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _rule(f: Finding) -> dict:
    rule = {
        "id": f.id,
        "name": f.id,
        "shortDescription": {"text": f.title},
        "helpUri": f.refs[0] if f.refs else _HOME,
        "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(f.severity, "note")},
        "properties": {"security-severity": security_severity(f)},
    }
    if f.detail:
        rule["fullDescription"] = {"text": f.detail}
    return rule


def _result(f: Finding) -> dict:
    parts = [f.title]
    if f.cve:
        parts.append(f"({f.cve})")
    if f.fix:
        parts.append(f"Fix: {f.fix}")
    result = {
        "ruleId": f.id,
        "level": _SEVERITY_TO_LEVEL.get(f.severity, "note"),
        "message": {"text": " ".join(parts)},
    }
    if f.file:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line or 1},
                }
            }
        ]
    return result
