from pathlib import Path

from langdoctor.engine import exit_code_for, run_checks
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _ids(findings):
    return {f.id for f in findings}


def test_kev_findings_sort_first():
    findings = run_checks(scan(FIX / "vulnerable_project"))
    assert findings[0].exploited_in_the_wild is True
    # highest-severity KEV (LD106, critical) should lead over the high KEV (LD111)
    assert findings[0].id == "LD106"


def test_ignore_by_ld_id():
    findings = run_checks(scan(FIX / "vulnerable_project"), ignore=["LD101"])
    assert "LD101" not in _ids(findings)


def test_ignore_by_cve_and_alias():
    base = run_checks(scan(FIX / "vulnerable_project"))
    assert "LD106" in _ids(base)

    by_cve = run_checks(scan(FIX / "vulnerable_project"), ignore=["CVE-2025-3248"])
    assert "LD106" not in _ids(by_cve)

    by_alias = run_checks(scan(FIX / "vulnerable_project"), ignore=["GHSA-rvqx-wpfh-mfx7"])
    assert "LD106" not in _ids(by_alias)


def test_exit_code_thresholds():
    findings = run_checks(scan(FIX / "vulnerable_project"))
    assert exit_code_for(findings, fail_on="high") == 1
    assert exit_code_for(findings, fail_on="critical") == 1
    assert exit_code_for(findings, fail_on="never") == 0


def test_clean_project_exits_zero():
    findings = run_checks(scan(FIX / "clean_project"))
    assert findings == []
    assert exit_code_for(findings, fail_on="high") == 0


def test_heuristic_only_findings_need_strict(tmp_path):
    (tmp_path / "requirements.txt").write_text("langgraph<1.0.0\n", encoding="utf-8")
    findings = run_checks(scan(tmp_path))
    assert all(f.heuristic for f in findings)
    # LD102 is medium severity and heuristic: default fail-on=high ignores it anyway,
    # but even fail-on=medium must not trip without --strict.
    assert exit_code_for(findings, fail_on="medium", strict=False) == 0
    assert exit_code_for(findings, fail_on="medium", strict=True) == 1
