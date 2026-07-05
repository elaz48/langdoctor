import sys
from pathlib import Path
from types import SimpleNamespace

# The watcher lives in scripts/ (not part of the installed package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import advisory_watch as aw  # noqa: E402


def _adv(id, cve=None, aliases=()):
    return SimpleNamespace(id=id, cve=cve, aliases=tuple(aliases))


COVERED = {"LD106", "CVE-2025-3248", "GHSA-RVQX-WPFH-MFX7"}


def test_covered_identifiers_uppercases_id_cve_aliases():
    db = SimpleNamespace(advisories=[
        _adv("LD106", "CVE-2025-3248", ("GHSA-rvqx-wpfh-mfx7", "PYSEC-2025-36")),
        _adv("LD150", None, ()),
    ])
    covered = aw.covered_identifiers(db)
    assert "LD106" in covered
    assert "CVE-2025-3248" in covered
    assert "GHSA-RVQX-WPFH-MFX7" in covered  # normalized to upper
    assert "PYSEC-2025-36" in covered
    assert "LD150" in covered


def test_vuln_identifiers_includes_id_and_aliases():
    v = {"id": "GHSA-abc", "aliases": ["CVE-2099-1", "PYSEC-2099-1"]}
    assert aw.vuln_identifiers(v) == {"GHSA-ABC", "CVE-2099-1", "PYSEC-2099-1"}


def test_new_advisory_is_flagged_with_fields():
    osv = {
        "langflow": [
            {
                "id": "CVE-2099-0001",
                "aliases": ["GHSA-newnew"],
                "summary": "Brand new unauthenticated RCE",
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}],
            }
        ],
    }
    result = aw.uncovered_advisories(osv, COVERED)
    assert len(result) == 1
    r = result[0]
    assert r["package"] == "langflow"
    assert r["id"] == "CVE-2099-0001"
    assert r["aliases"] == ["GHSA-newnew"]
    assert r["fixed"] == ["9.9.9"]
    assert "Brand new" in r["summary"]


def test_covered_by_id_is_excluded():
    osv = {"langflow": [{"id": "GHSA-rvqx-wpfh-mfx7", "aliases": ["CVE-2025-3248"]}]}
    assert aw.uncovered_advisories(osv, COVERED) == []


def test_covered_by_alias_even_if_osv_id_differs():
    # OSV lists it under a different primary id, but an alias is one we cover.
    osv = {"langflow": [{"id": "OSV-INTERNAL-123", "aliases": ["CVE-2025-3248"]}]}
    assert aw.uncovered_advisories(osv, COVERED) == []


def test_matching_is_case_insensitive():
    osv = {"pkg": [{"id": "osv-1", "aliases": ["cve-2025-3248"]}]}
    assert aw.uncovered_advisories(osv, COVERED) == []


def test_deduped_across_packages():
    osv = {
        "langgraph-checkpoint": [{"id": "CVE-2099-DUP"}],
        "langgraph-checkpoint-sqlite": [{"id": "CVE-2099-DUP"}],
    }
    result = aw.uncovered_advisories(osv, COVERED)
    assert [r["id"] for r in result] == ["CVE-2099-DUP"]


def test_failed_fetch_none_is_skipped():
    # A package whose OSV query failed comes through as None — must not crash.
    osv = {"langflow": None, "langgraph": [{"id": "CVE-2099-2"}]}
    result = aw.uncovered_advisories(osv, COVERED)
    assert [r["id"] for r in result] == ["CVE-2099-2"]


def test_render_issue_lists_advisory():
    body = aw.render_issue([
        {"package": "langflow", "id": "CVE-2099-0001", "aliases": ["GHSA-x"],
         "summary": "new RCE", "fixed": ["9.9.9"]}
    ])
    assert "CVE-2099-0001" in body
    assert "langflow" in body
    assert "advisories.json" in body


def test_covered_identifiers_from_real_db():
    # Integration: the shipped advisory DB really covers the KEV Langflow CVE.
    from langdoctor.advisories import load_db

    covered = aw.covered_identifiers(load_db())
    assert "CVE-2025-3248" in covered
    assert "GHSA-RVQX-WPFH-MFX7" in covered
    assert "LD106" in covered
