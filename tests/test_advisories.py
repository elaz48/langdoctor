import pytest

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
    assert db.updated == "2026-11-19"
    ids = {a.id for a in db.advisories}
    assert {"LD101", "LD105", "LD106", "LD111", "LD112", "LD113", "LD114",
            "LD115", "LD116", "LD117", "LD118", "LD119", "LD120", "LD121",
            "LD122", "LD123", "LD124", "LD125", "LD126", "LD127", "LD128",
            "LD129", "LD130", "LD131", "LD132", "LD133", "LD150"} <= ids


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

    Verified against the KEV catalog on 2026-08-27 and re-checked on 2026-11-18
    (no new ecosystem entries since). An uncovered KEV CVE is the
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


# --- 0.1.6: LangGraph store follow-up + langgraph-sdk ----------------------

def _by():
    return {a.id: a for a in load_db().advisories}


def test_ld128_ld129_share_a_cve_but_not_a_fix_version():
    # CVE-2026-115883: one CVE, two packages, and — unlike LD118/LD119 — two
    # different fix versions (sqlite 3.1.2, postgres 3.1.3).
    by = _by()
    assert by["LD128"].package == "langgraph-checkpoint-sqlite"
    assert by["LD129"].package == "langgraph-checkpoint-postgres"
    assert by["LD128"].cve == by["LD129"].cve == "CVE-2026-115883"
    assert "GHSA-6hmw-9432-67qq" in by["LD128"].aliases
    assert "GHSA-6hmw-9432-67qq" in by["LD129"].aliases
    # 3.1.1 fixed LD118/LD119 but is still affected here
    assert version_affected("3.1.1", by["LD128"].ranges)
    assert not version_affected("3.1.2", by["LD128"].ranges)
    assert version_affected("3.1.2", by["LD129"].ranges)
    assert not version_affected("3.1.3", by["LD129"].ranges)
    assert by["LD128"].severity() == by["LD129"].severity() == "medium"  # CNA 6.0


def test_ld130_only_affects_the_sdk_04_line():
    # The v3 stream module does not exist in langgraph-sdk 0.3.x.
    ld130 = _by()["LD130"]
    assert ld130.package == "langgraph-sdk"
    assert ld130.cve == "CVE-2026-118667"
    assert not version_affected("0.3.15", ld130.ranges)
    assert version_affected("0.4.0", ld130.ranges)
    assert version_affected("0.4.5", ld130.ranges)
    assert not version_affected("0.4.6", ld130.ranges)
    assert ld130.severity() == "medium"  # CNA 4.3


def test_ld131_covers_remotegraph_from_langgraph_1_2_3():
    ld131 = _by()["LD131"]
    assert ld131.package == "langgraph"
    assert ld131.cve == "CVE-2026-118667"
    assert not version_affected("1.2.2", ld131.ranges)
    assert version_affected("1.2.3", ld131.ranges)
    assert version_affected("1.2.13", ld131.ranges)
    assert not version_affected("1.2.14", ld131.ranges)


def test_ld132_auth_decorator_bypass_range():
    ld132 = _by()["LD132"]
    assert ld132.package == "langgraph-sdk"
    assert ld132.cve == "CVE-2026-104873"
    assert {"GHSA-fvww-7h3r-vfhp", "PYSEC-2026-4240"} <= set(ld132.aliases)
    assert not version_affected("0.1.44", ld132.ranges)
    assert version_affected("0.1.45", ld132.ranges)
    assert version_affected("0.4.3", ld132.ranges)
    assert not version_affected("0.4.4", ld132.ranges)
    assert ld132.severity() == "high"  # CNA 7.6 (CVSS 4.0)


def test_ld133_puts_cve_2026_48776_on_the_package_the_vendor_names():
    """GHSA-w39p (vendor) and PYSEC-2026-2575 attribute CVE-2026-48776 to
    langgraph-sdk; LD112 followed PYSEC-2026-2194, which files it under langgraph.
    LD112 stays in the DB as a deprecated ID; LD133 covers the SDK itself."""
    by = _by()
    ld133 = by["LD133"]
    assert ld133.package == "langgraph-sdk"
    assert ld133.cve == by["LD112"].cve == "CVE-2026-48776"
    assert "PYSEC-2026-2575" in ld133.aliases
    assert version_affected("0.3.14", ld133.ranges)
    assert not version_affected("0.3.15", ld133.ranges)
    assert ld133.severity() == by["LD112"].severity() == "medium"


def test_langflow_baseline_is_1_13_0():
    ld150 = _by()["LD150"]
    assert ld150.fixed_in == "1.13.0"
    assert version_affected("1.12.8", ld150.ranges)
    # 1.12.9/1.12.10 are later maintenance releases, but their backport covers
    # the 1.13.0 -> 1.13.1 delta, not the fixes IBM attributes to 1.13.0.
    assert version_affected("1.12.10", ld150.ranges)
    assert not version_affected("1.13.0", ld150.ranges)


# --- deprecation (LD112 -> LD133) -------------------------------------------

def test_ld112_is_deprecated_in_favor_of_ld133():
    by = _by()
    assert by["LD112"].deprecated == "2026-11-19"
    assert by["LD112"].superseded_by == ("LD133",)
    # The ID is permanent: it keeps its CVE and aliases, so suppression by ID,
    # CVE or alias still parses and the watcher still counts it as covered.
    assert by["LD112"].cve == "CVE-2026-48776"
    assert "PYSEC-2026-2194" in by["LD112"].aliases


def test_live_advisories_are_not_deprecated():
    by = _by()
    assert by["LD133"].deprecated is None
    assert by["LD133"].superseded_by == ()


def test_every_superseded_by_target_exists_and_is_live():
    by = _by()
    for adv in by.values():
        for target in adv.superseded_by:
            assert target and target != adv.id, f"{adv.id} -> bad target {target!r}"
            assert target in by, f"{adv.id} -> unknown {target}"
            assert by[target].deprecated is None, f"{adv.id} -> deprecated {target}"
        if adv.superseded_by:
            assert adv.deprecated, f"{adv.id} has superseded_by but is not deprecated"


def test_deprecated_flag_tolerates_a_bare_boolean():
    from langdoctor.advisories import _parse_advisory

    raw = {"id": "LD999", "package": "x", "deprecated": True}
    assert _parse_advisory(raw).deprecated == "yes"
    assert _parse_advisory({"id": "LD998", "package": "x"}).deprecated is None


@pytest.mark.parametrize("value", [False, None, "", "false", "False", "no", "0"])
def test_deprecated_falsy_spellings_keep_the_entry_live(value):
    from langdoctor.advisories import _parse_advisory

    assert _parse_advisory({"id": "LD999", "package": "x", "deprecated": value}).deprecated is None


def test_superseded_by_accepts_a_single_string():
    # A hand-edited `"superseded_by": "LD133"` must not split into characters.
    from langdoctor.advisories import _parse_advisory

    adv = _parse_advisory({"id": "LD999", "package": "x", "deprecated": "2026-11-19",
                           "superseded_by": "LD133"})
    assert adv.superseded_by == ("LD133",)


def test_successor_inherits_the_deprecated_identifiers():
    from langdoctor.advisories import inherited_identifiers

    inherited = inherited_identifiers(load_db())
    assert {"LD112", "PYSEC-2026-2194"} <= set(inherited["LD133"])
    # nothing the successor already carries is duplicated
    assert "CVE-2026-48776" not in inherited["LD133"]
    assert "GHSA-w39p-vh2g-g8g5" not in inherited["LD133"]
