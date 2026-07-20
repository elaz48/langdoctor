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
    assert db.updated == "2026-07-20"
    ids = {a.id for a in db.advisories}
    assert {"LD101", "LD105", "LD106", "LD111", "LD112", "LD113", "LD114",
            "LD115", "LD116", "LD117", "LD150"} <= ids


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
