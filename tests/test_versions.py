from pathlib import Path

from langdoctor.checks.versions import check_versions
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _ids(findings):
    return {f.id for f in findings}


def test_vulnerable_project_triggers_expected_advisories():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    got = _ids(findings)
    # langgraph-checkpoint-sqlite 2.0.5 -> LD101, LD109, LD110, LD118, LD128
    assert {"LD101", "LD109", "LD110", "LD118", "LD128"} <= got
    # langgraph-checkpoint-postgres 3.1.0 -> LD119, LD129 (shared CVEs, other package)
    assert {"LD119", "LD129"} <= got
    # langgraph-sdk 0.4.3 -> LD130 (v3 streaming paths), LD132 (auth decorators)
    assert {"LD130", "LD132"} <= got
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
    # 1.12.8 is past every individual Langflow advisory but below the baseline.
    findings = check_versions(scan(FIX / "langflow_baseline_project"))
    assert _ids(findings) == {"LD150"}


def test_langflow_baseline_recommends_the_current_secure_line():
    """Regression (twice over): the LD150 baseline drifts whenever IBM PSIRT
    publishes Langflow CVEs that OSV does not index.

    0.1.4: stuck at 1.10.1 while 24 CVEs fixed in 1.11.0 landed — a 1.10.3 pin
    scanned clean. 0.1.6: stuck at 1.11.0 while ~99 more (16 of them CVSS >= 9.0)
    were fixed between 1.11.2 and 1.13.0 — a 1.12.8 pin scanned clean."""
    findings = {f.id: f for f in check_versions(scan(FIX / "langflow_baseline_project"))}
    assert findings["LD150"].fix == 'pip install "langflow>=1.13.0"'
    assert findings["LD150"].severity == "high"


def test_the_previous_langflow_baseline_is_now_flagged(tmp_path):
    # 1.11.0 was the "patched" fixture in 0.1.4/0.1.5; it is no longer safe.
    (tmp_path / "requirements.txt").write_text("langflow==1.11.0\n", encoding="utf-8")
    assert _ids(check_versions(scan(tmp_path))) == {"LD150"}


def test_late_1_12_maintenance_releases_are_still_below_the_baseline(tmp_path):
    # 1.12.9/1.12.10 shipped after 1.13.0, but branch from release-1.12.8 and
    # backport only the 1.13.0 -> 1.13.1 delta (langflow PR #16119).
    (tmp_path / "requirements.txt").write_text("langflow==1.12.10\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert findings["LD150"].fix == 'pip install "langflow>=1.13.0"'


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


def test_community_project_trips_every_langchain_community_advisory():
    findings = {f.id: f for f in check_versions(scan(FIX / "community_project"))}
    assert {"LD125", "LD126", "LD127"} <= findings.keys()
    assert findings["LD125"].fix == 'pip install "langchain-community>=0.0.28"'
    assert findings["LD126"].fix == 'pip install "langchain-community>=0.3.27"'


def test_unfixed_advisory_still_fires_on_the_newest_release_without_a_fix_line():
    """LD127 has no released fix, so the newest langchain-community is still
    affected and langdoctor must report it with no upgrade to recommend rather
    than inventing one or staying silent."""
    findings = check_versions(scan(FIX / "community_latest_project"))
    assert _ids(findings) == {"LD127"}
    assert findings[0].fix is None
    assert findings[0].severity == "high"
    assert findings[0].cve == "CVE-2026-72848"


def test_community_name_normalization(tmp_path):
    # PEP 503: the underscore spelling has to resolve to the same advisories.
    (tmp_path / "requirements.txt").write_text("langchain_community==0.3.26\n", encoding="utf-8")
    assert {"LD126", "LD127"} <= _ids(check_versions(scan(tmp_path)))


# --- 0.1.6: LangGraph store follow-up + langgraph-sdk ----------------------

def test_store_fix_line_names_each_package_and_its_own_version():
    # CVE-2026-115883 is fixed in sqlite 3.1.2 but postgres 3.1.3, so the two
    # findings must not share a fix line.
    findings = {f.id: f for f in check_versions(scan(FIX / "vulnerable_project"))}
    assert findings["LD128"].cve == findings["LD129"].cve == "CVE-2026-115883"
    assert findings["LD128"].fix == 'pip install "langgraph-checkpoint-sqlite>=3.1.2"'
    assert findings["LD129"].fix == 'pip install "langgraph-checkpoint-postgres>=3.1.3"'


def test_stores_on_the_ld118_fix_are_still_affected(tmp_path):
    """Regression: 3.1.1 fixed CVE-2026-71433 (LD118/LD119) and was the clean
    fixture's pin — but CVE-2026-115883 affects it, so it scanned clean while
    vulnerable."""
    (tmp_path / "requirements.txt").write_text(
        "langgraph-checkpoint-sqlite==3.1.1\nlanggraph-checkpoint-postgres==3.1.1\n",
        encoding="utf-8",
    )
    assert _ids(check_versions(scan(tmp_path))) == {"LD128", "LD129"}


def test_suppressing_cve_2026_115883_hits_both_stores():
    findings = check_versions(scan(FIX / "vulnerable_project"))
    shared = [f for f in findings if f.matches_id("GHSA-6hmw-9432-67qq")]
    assert {f.id for f in shared} == {"LD128", "LD129"}


def test_remotegraph_on_langgraph_1_2_x_is_flagged(tmp_path):
    # Regression: the clean fixture pinned langgraph 1.2.7, inside the
    # CVE-2026-118667 RemoteGraph range, and scanned clean.
    (tmp_path / "requirements.txt").write_text("langgraph==1.2.7\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert _ids(findings.values()) == {"LD131"}
    assert findings["LD131"].fix == 'pip install "langgraph>=1.2.14"'
    assert findings["LD131"].severity == "medium"


def test_sdk_v3_streaming_is_flagged_on_the_04_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("langgraph-sdk==0.4.5\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert _ids(findings.values()) == {"LD130"}  # 0.4.5 is past LD132's 0.4.4 fix
    assert findings["LD130"].fix == 'pip install "langgraph-sdk>=0.4.6"'


def test_suppressing_cve_2026_118667_hits_sdk_and_langgraph(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langgraph==1.2.7\nlanggraph-sdk==0.4.5\n", encoding="utf-8"
    )
    shared = [f for f in check_versions(scan(tmp_path)) if f.matches_id("CVE-2026-118667")]
    assert {f.id for f in shared} == {"LD130", "LD131"}


def test_sdk_auth_decorator_bypass_is_high(tmp_path):
    (tmp_path / "requirements.txt").write_text("langgraph-sdk==0.4.3\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert findings["LD132"].severity == "high"
    assert findings["LD132"].fix == 'pip install "langgraph-sdk>=0.4.4"'


def test_old_sdk_trips_the_url_construction_cve_on_its_own_package(tmp_path):
    # CVE-2026-48776 lives in langgraph-sdk; LD112 only matched the langgraph
    # package, so an old SDK pinned next to a modern langgraph went unflagged.
    (tmp_path / "requirements.txt").write_text(
        "langgraph==1.2.14\nlanggraph-sdk==0.3.14\n", encoding="utf-8"
    )
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert "LD112" not in findings
    assert findings["LD133"].fix == 'pip install "langgraph-sdk>=0.3.15"'
    assert "LD132" in findings  # 0.3.14 is also inside 0.1.45 .. 0.4.4
    assert "LD130" not in findings  # no v3 streaming module on the 0.3.x line


def test_specifier_capped_below_the_introduced_bound_is_not_flagged(tmp_path):
    # LD131 only affects 1.2.3 <= v < 1.2.14. A pin capped below 1.0 can never
    # resolve into that window, so even a heuristic finding would be a false
    # positive — while LD102 (introduced 0, fixed 1.0.10) still fires.
    (tmp_path / "requirements.txt").write_text("langgraph<1.0.0\n", encoding="utf-8")
    got = _ids(check_versions(scan(tmp_path)))
    assert "LD102" in got
    assert "LD131" not in got


def test_specifier_inside_an_introduced_window_is_still_heuristic(tmp_path):
    (tmp_path / "requirements.txt").write_text("langgraph<1.2.10\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert findings["LD131"].heuristic is True


def test_specifier_whose_lower_bound_sits_inside_the_window_is_flagged(tmp_path):
    # >=1.2.5,<1.2.10 excludes the introduced version 1.2.3 itself, yet every
    # version it admits is affected — it must not slip through.
    (tmp_path / "requirements.txt").write_text("langgraph>=1.2.5,<1.2.10\n", encoding="utf-8")
    findings = {f.id: f for f in check_versions(scan(tmp_path))}
    assert findings["LD131"].heuristic is True


def test_specifier_excluding_only_the_introduced_version_is_flagged(tmp_path):
    # Review finding: `>1.2.3` / `!=1.2.3` exclude the first affected release but
    # still admit 1.2.4 .. 1.2.13, so the window stays reachable.
    for spec in ("langgraph>1.2.3,<1.2.14", "langgraph!=1.2.3,<1.2.14"):
        (tmp_path / "requirements.txt").write_text(spec + "\n", encoding="utf-8")
        findings = {f.id: f for f in check_versions(scan(tmp_path))}
        assert findings["LD131"].heuristic is True, spec


def test_compatible_release_below_the_window_is_not_flagged(tmp_path):
    # ~=1.1.0 resolves within 1.1.x only, entirely below LD131's 1.2.3 floor.
    (tmp_path / "requirements.txt").write_text("langgraph~=1.1.0\n", encoding="utf-8")
    assert "LD131" not in _ids(check_versions(scan(tmp_path)))
