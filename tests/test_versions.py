from pathlib import Path

from langdoctor.checks.versions import check_versions
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _ids(findings):
    return {f.id for f in findings}


def test_vulnerable_project_triggers_expected_advisories():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    got = _ids(findings)
    # langgraph-checkpoint-sqlite 2.0.5 -> LD101, LD109, LD110
    assert {"LD101", "LD109", "LD110"} <= got
    # langflow 1.2.0 -> LD106 (KEV), LD111 (KEV)
    assert {"LD106", "LD111"} <= got
    # langchain-core 1.2.0 -> LD104, LD105
    assert {"LD104", "LD105"} <= got
    # langgraph 1.0.5 -> LD102
    assert "LD102" in got


def test_clean_project_has_no_findings():
    assert check_versions(scan(FIX / "clean_project")) == []


def test_findings_carry_derived_severity_and_fix():
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD106"].severity == "critical"
    assert findings["LD106"].exploited_in_the_wild is True
    assert findings["LD106"].fix == 'pip install "langflow>=1.3.0"'
    # exact-version hits are precise, not heuristic
    assert findings["LD106"].heuristic is False


def test_dual_line_fix_targets_matching_line():
    # langchain-core 1.2.0 is on the 1.x line -> recommend 1.2.5, not 0.3.81
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD105"].fix == 'pip install "langchain-core>=1.2.5"'


def test_aggregate_suppressed_when_specific_langflow_finding_fires():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    assert "LD150" not in _ids(findings)  # LD106/LD111 already cover this langflow


def test_aggregate_fires_when_no_specific_langflow_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("langflow==1.9.5\n", encoding="utf-8")
    findings = check_versions(scan(tmp_path))
    assert _ids(findings) == {"LD150"}  # 1.9.5 dodges LD106/LD111 but not the baseline


def test_specifier_capped_below_fix_is_heuristic(tmp_path):
    (tmp_path / "requirements.txt").write_text("langgraph<1.0.0\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert "LD102" in findings
    assert findings["LD102"].heuristic is True


def test_open_specifier_not_flagged(tmp_path):
    # >=1.0 can resolve to a patched release, so don't cry wolf
    (tmp_path / "requirements.txt").write_text("langgraph>=1.0\n", encoding="utf-8")
    findings = check_versions(scan(tmp_path))
    assert "LD102" not in _ids(findings)
