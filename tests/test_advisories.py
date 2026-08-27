from langdoctor.advisories import (
    DEFAULT_BUCKETS,
    derive_severity,
    load_db,
    normalize_name,
    version_affected,
)


def test_db_loads_schema_v2():
    db = load_db()
    assert db.schema_version == 2
    assert db.updated == "2026-08-27"
    ids = {a.id for a in db.advisories}
    assert {"LD101", "LD105", "LD106", "LD111", "LD112", "LD113", "LD114",
            "LD115", "LD116", "LD117", "LD118", "LD119", "LD120", "LD121",
            "LD122", "LD123", "LD124", "LD125", "LD126", "LD127", "LD150"} <= ids


def test_normalize_name():
    assert normalize_name("LangGraph_Checkpoint.Sqlite") == "langgraph-checkpoint-sqlite"
    assert normalize_name("langchain-core") == "langchain-core"


def test_severity_derivation_from_cvss():
    assert derive_severity(9.8, None, DEFAULT_BUCKETS) == "critical"
    assert derive_severity(7.3, None, DEFAULT_BUCKETS) == "high"
    assert derive_severity(6.6, None, DEFAULT_BUCKETS) == "medium"
    assert derive_severity(2.0, None, DEFAULT_BUCKETS) == "low"
    assert derive_severity(0.0, None, DEFAULT_BUCKETS) == "info"


def test_severity_override_wins_over_score():
    assert derive_severity(2.0, "high", DEFAULT_BUCKETS) == "high"
    assert derive_severity(None, "high", DEFAULT_BUCKETS) == "high"


def test_advisory_derived_severities():
    db = load_db()
    by = {a.id: a for a in db.advisories}
    assert by["LD106"].severity(db.buckets) == "critical"  # 9.8
    assert by["LD101"].severity(db.buckets) == "high"      # 7.3
    assert by["LD107"].severity(db.buckets) == "medium"    # 6.6
    assert by["LD150"].severity(db.buckets) == "high"      # override, no score


def test_kev_flags_present():
    by = {a.id: a for a in load_db().advisories}
    assert by["LD106"].exploited_in_the_wild is True
    assert by["LD111"].exploited_in_the_wild is True
    assert by["LD101"].exploited_in_the_wild is False


def test_every_kev_langflow_cve_is_covered_and_flagged():
    """The six CISA KEV Langflow entries must each map to a KEV-flagged advisory.

    Verified against the KEV catalog on 2026-08-27. An uncovered KEV CVE is the
    worst kind of miss: langdoctor sorts KEV above everything else, so a gap
    here is invisible exactly where it matters most.
    """
    kev_cves = {
        "CVE-2025-3248",    # KEV 2025-05-05 -> LD106
        "CVE-2026-5027",    # exploited in the wild (VulnCheck) -> LD111
        "CVE-2025-34291",   # KEV 2026-05-21 -> LD120
        "CVE-2026-0770",    # KEV 2026-07-21 -> LD121
        "CVE-2026-33017",   # KEV 2026-03-25 -> LD122
        "CVE-2026-55255",   # KEV 2026-07-07 -> LD123
        "CVE-2026-9198",    # KEV 2026-08-04 -> LD124
    }
    by_cve = {a.cve: a for a in load_db().advisories if a.cve}
    missing = kev_cves - by_cve.keys()
    assert not missing, f"KEV CVEs missing from the advisory DB: {sorted(missing)}"
    for cve in kev_cves:
        assert by_cve[cve].exploited_in_the_wild is True, f"{cve} not KEV-flagged"


def test_ld124_is_not_in_osv_so_it_carries_no_ghsa_alias():
    # CVE-2026-9198 reached us via NVD + CISA KEV only (OSV had no record on
    # 2026-08-27), which is why the OSV-only watcher never surfaced it.
    ld124 = {a.id: a for a in load_db().advisories}["LD124"]
    assert ld124.cve == "CVE-2026-9198"
    assert ld124.aliases == ()
    assert ld124.severity() == "critical"  # CVSS 9.8


def test_aliases_recorded():
    by = {a.id: a for a in load_db().advisories}
    assert "GHSA-rvqx-wpfh-mfx7" in by["LD106"].aliases
    assert "TRA-2026-26" in by["LD111"].aliases


def test_version_affected_single_range():
    ld106 = {a.id: a for a in load_db().advisories}["LD106"]  # langflow < 1.3.0
    assert version_affected("1.2.0", ld106.ranges)
    assert not version_affected("1.3.0", ld106.ranges)
    assert not version_affected("1.10.1", ld106.ranges)


def test_dual_line_ranges_ld105():
    ld105 = {a.id: a for a in load_db().advisories}["LD105"]
    # 1.x line: fixed at 1.2.5
    assert version_affected("1.2.0", ld105.ranges)
    assert not version_affected("1.2.5", ld105.ranges)
    # 0.3.x line: fixed at 0.3.81
    assert version_affected("0.3.80", ld105.ranges)
    assert not version_affected("0.3.81", ld105.ranges)


def test_dual_line_ranges_ld113():
    ld113 = {a.id: a for a in load_db().advisories}["LD113"]
    # 1.x line: fixed at 1.0.7
    assert version_affected("1.0.6", ld113.ranges)
    assert not version_affected("1.0.7", ld113.ranges)
    # 0.3.x line: fixed at 0.3.80
    assert version_affected("0.3.79", ld113.ranges)
    assert not version_affected("0.3.80", ld113.ranges)


def test_dual_line_ranges_ld117():
    ld117 = {a.id: a for a in load_db().advisories}["LD117"]
    # 1.x line: fixed at 1.3.3
    assert version_affected("1.3.2", ld117.ranges)
    assert not version_affected("1.3.3", ld117.ranges)
    # 0.3.x line: fixed at 0.3.85
    assert version_affected("0.3.84", ld117.ranges)
    assert not version_affected("0.3.85", ld117.ranges)


def test_every_advisory_has_a_reference():
    for adv in load_db().advisories:
        assert adv.refs, f"{adv.id} has no refs"


# --- langchain-community ---------------------------------------------------

def test_langchain_community_advisories_present():
    by = {a.id: a for a in load_db().advisories}
    assert by["LD125"].package == "langchain-community"
    assert by["LD126"].package == "langchain-community"
    assert by["LD127"].package == "langchain-community"
    assert by["LD125"].severity() == "critical"  # NVD primary 10.0
    assert by["LD126"].severity() == "high"      # huntr CNA 7.5
    assert by["LD127"].severity() == "high"      # VulnCheck 8.6


def test_ld127_has_no_fix_because_upstream_has_not_released_one():
    """CVE-2026-72848 is fixed in main but no release carries it, so the
    advisory deliberately has an open-ended range and no fix version."""
    ld127 = {a.id: a for a in load_db().advisories}["LD127"]
    assert ld127.fixed_in is None
    assert len(ld127.ranges) == 1
    assert ld127.ranges[0].fixed is None
    # An unbounded range means every version is affected, including the newest.
    assert version_affected("0.4.2", ld127.ranges)
    assert version_affected("99.0.0", ld127.ranges)
