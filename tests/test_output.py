import json
from pathlib import Path

from langdoctor.engine import run_checks
from langdoctor.output.json_out import render_json
from langdoctor.output.markdown import render_markdown
from langdoctor.output.sarif import render_sarif
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _findings():
    return run_checks(scan(FIX / "vulnerable_project"))


def test_json_is_valid_and_structured():
    doc = json.loads(render_json(_findings(), "/proj", "2026-07-04"))
    assert doc["tool"] == "langdoctor"
    assert doc["advisories_updated"] == "2026-07-04"
    assert doc["summary"]["total"] == len(doc["findings"])
    assert doc["summary"]["kev"] >= 2
    ld106 = next(f for f in doc["findings"] if f["id"] == "LD106")
    assert ld106["cve"] == "CVE-2025-3248"
    assert ld106["exploited_in_the_wild"] is True
    assert "GHSA-rvqx-wpfh-mfx7" in ld106["aliases"]


def test_json_clean_project():
    doc = json.loads(render_json(run_checks(scan(FIX / "clean_project")), "/p", "2026-07-04"))
    assert doc["summary"]["total"] == 0
    assert doc["findings"] == []


def test_sarif_structure_and_levels():
    doc = json.loads(render_sarif(_findings(), "/proj", "2026-07-04"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "langdoctor"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "LD106" in rule_ids
    # critical/high -> error, medium -> warning
    levels = {res["ruleId"]: res["level"] for res in run["results"]}
    assert levels["LD106"] == "error"
    assert levels["LD102"] == "warning"  # medium
    # security-severity uses the real CVSS score for advisories...
    ld106_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "LD106")
    assert ld106_rule["properties"]["security-severity"] == "9.8"
    # ...and falls back to the severity-bucket threshold for CVSS-less code checks
    ld403_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "LD403")
    assert ld403_rule["properties"]["security-severity"] == "9.0"


def test_sarif_dedupes_rules():
    # LD109 and LD110 are distinct rules; rules list has no duplicate ids
    doc = json.loads(render_sarif(_findings(), "/proj", "2026-07-04"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))


def test_markdown_has_table_and_ids():
    md = render_markdown(_findings(), "/proj", "2026-07-04")
    assert md.startswith("## 🩺 langdoctor")
    assert "| Severity | ID | Location | Issue | Fix |" in md
    assert "LD106" in md
    assert "🔴KEV" in md


def test_markdown_all_clear():
    md = render_markdown([], "/proj", "2026-07-04")
    assert "All clear" in md
    assert "advisories as of 2026-07-04" in md


def test_json_summary_reports_suppressed_count():
    doc = json.loads(render_json(_findings(), "/p", "2026-07-04", suppressed=3))
    assert doc["summary"]["suppressed"] == 3


def test_markdown_shows_suppressed_in_all_clear():
    md = render_markdown([], "/p", "2026-07-04", suppressed=2)
    assert "2 suppressed" in md
