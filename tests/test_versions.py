from pathlib import Path

from langdoctor.checks.versions import check_versions
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _ids(findings):
    return {f.id for f in findings}


def test_vulnerable_project_triggers_expected_advisories():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    got = _ids(findings)
    # langgraph-checkpoint-sqlite 2.0.5 -> LD101, LD109, LD110, LD118
    assert {"LD101", "LD109", "LD110", "LD118"} <= got
    # langgraph-checkpoint-postgres 3.1.0 -> LD119 (same CVE as LD118, other package)
    assert "LD119" in got
    # langflow 1.2.0 -> every KEV Langflow advisory
    assert {"LD106", "LD111", "LD120", "LD121", "LD122", "LD123", "LD124"} <= got
    # langchain-core 1.0.5 (1.x line) -> LD104, LD105, LD113, LD115, LD116, LD117
    assert {"LD104", "LD105", "LD113", "LD115", "LD116", "LD117"} <= got
    # langchain 1.3.0 -> LD114
    assert "LD114" in got
    # langgraph 1.0.5 -> LD102
    assert "LD102" in got


def test_clean_project_has_no_findings():
    assert check_versions(scan(FIX / "clean_project")) == []


def test_one_cve_two_packages_reports_per_package_fix():
    # CVE-2026-71433 affects both stores; each finding must name its own package.
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD118"].cve == findings["LD119"].cve == "CVE-2026-71433"
    assert findings["LD118"].fix == 'pip install "langgraph-checkpoint-sqlite>=3.1.1"'
    assert findings["LD119"].fix == 'pip install "langgraph-checkpoint-postgres>=3.1.1"'


def test_suppressing_the_shared_cve_hits_both_entries():
    # Suppression matches on CVE, so one --ignore silences both packages.
    findings = check_versions(scan(FIX / "vulnerable_project"))
    shared = [f for f in findings if f.matches_id("cve-2026-71433")]
    assert {f.id for f in shared} == {"LD118", "LD119"}


def test_findings_carry_derived_severity_and_fix():
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD106"].severity == "critical"
    assert findings["LD106"].exploited_in_the_wild is True
    assert findings["LD106"].fix == 'pip install "langflow>=1.3.0"'
    # exact-version hits are precise, not heuristic
    assert findings["LD106"].heuristic is False


def test_dual_line_fix_targets_matching_line():
    # langchain-core 1.0.5 is on the 1.x line -> recommend 1.2.5, not 0.3.81
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD105"].fix == 'pip install "langchain-core>=1.2.5"'
    # LD113 is also dual-line; the 1.x line is fixed at 1.0.7
    assert findings["LD113"].fix == 'pip install "langchain-core>=1.0.7"'
    # v0.1.2 langchain-core advisories, all resolved on the 1.x line for 1.0.5
    assert findings["LD115"].fix == 'pip install "langchain-core>=1.2.11"'
    assert findings["LD116"].fix == 'pip install "langchain-core>=1.2.28"'
    assert findings["LD117"].fix == 'pip install "langchain-core>=1.3.3"'
    assert findings["LD117"].severity == "high"  # CVSS 8.2, the notable one


def test_ld112_only_affects_the_0x_line(tmp_path):
    # CVE-2026-48776: langgraph SDK URL construction, fixed 0.3.15 (0.x only).
    (tmp_path / "requirements.txt").write_text("langgraph==0.3.14\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert "LD112" in findings
    assert findings["LD112"].severity == "medium"  # CNA 4.2, not the NVD-secondary 9.1
    assert findings["LD112"].fix == 'pip install "langgraph>=0.3.15"'
    assert findings["LD112"].heuristic is False


def test_ld112_not_flagged_on_1x(tmp_path):
    # 1.x is past the 0.3.15 fix, so a modern langgraph pin must not trip LD112.
    (tmp_path / "requirements.txt").write_text("langgraph==1.0.5\n", encoding="utf-8")
    assert "LD112" not in _ids(check_versions(scan(tmp_path)))


def test_aggregate_suppressed_when_specific_langflow_finding_fires():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    assert "LD150" not in _ids(findings)  # LD106/LD111 already cover this langflow


def test_aggregate_fires_when_no_specific_langflow_finding():
    # 1.10.3 is past every individual Langflow advisory but below the baseline.
    findings = check_versions(scan(FIX / "langflow_baseline_project"))
    assert _ids(findings) == {"LD150"}


def test_langflow_baseline_recommends_the_current_secure_line():
    """Regression: the LD150 baseline was stuck at 1.10.1 while IBM PSIRT
    published 24 further CVEs on 2026-08-05, all fixed in 1.11.0 and none of
    them indexed by OSV. A 1.10.2/1.10.3 pin scanned completely clean."""
    findings = {f.id: f for f in check_versions(scan(FIX / "langflow_baseline_project"))}
    assert findings["LD150"].fix == 'pip install "langflow>=1.11.0"'
    assert findings["LD150"].severity == "high"


def test_langflow_on_the_current_baseline_is_clean():
    assert check_versions(scan(FIX / "langflow_patched_project")) == []


def test_kev_langflow_advisories_carry_their_own_thresholds(tmp_path):
    # Each KEV entry has an independent fix line, so a version between two of
    # them gets an accurate per-CVE answer rather than one blunt verdict.
    (tmp_path / "requirements.txt").write_text("langflow==1.9.0\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    # 1.9.0 is past LD120 (1.7.0), LD121 (1.8.0) and LD122 (1.9.0)...
    assert {"LD120", "LD121", "LD122"} & findings.keys() == set()
    # ...but still short of LD123 (1.9.1) and LD124 (1.10.1).
    assert findings["LD123"].fix == 'pip install "langflow>=1.9.1"'
    assert findings["LD124"].fix == 'pip install "langflow>=1.10.1"'
    assert findings["LD124"].exploited_in_the_wild is True
    assert "LD150" not in findings  # specific findings suppress the aggregate


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
