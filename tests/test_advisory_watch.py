import io
import json
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

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


# --- ignore list -----------------------------------------------------------

def test_load_ignore_normalizes(tmp_path):
    p = tmp_path / "ig.json"
    p.write_text(json.dumps({"ignore": {"cve-2023-1": "x", "GHSA-yy": "y"}}), encoding="utf-8")
    assert aw.load_ignore(p) == {"CVE-2023-1", "GHSA-YY"}


def test_load_ignore_missing_file_is_empty(tmp_path):
    assert aw.load_ignore(tmp_path / "nope.json") == set()


def test_ignoring_a_cve_suppresses_its_ghsa_and_pysec_records():
    # OSV returns the same CVE as separate GHSA + PYSEC records; ignoring the CVE
    # must drop both, since matching is by any identifier.
    ignore = {"CVE-2023-99999"}
    osv = {"langchain": [
        {"id": "GHSA-aaa", "aliases": ["CVE-2023-99999", "PYSEC-2023-1"]},
        {"id": "PYSEC-2023-1", "aliases": ["CVE-2023-99999", "GHSA-aaa"]},
        {"id": "GHSA-bbb", "aliases": ["CVE-2026-11111"]},  # unrelated, stays
    ]}
    result = aw.uncovered_advisories(osv, COVERED | ignore)
    assert [r["id"] for r in result] == ["GHSA-bbb"]


def test_real_ignore_file_lists_historical_langchain():
    ignore = aw.load_ignore(aw.IGNORE_PATH)
    assert "CVE-2023-29374" in ignore   # a pre-2025 langchain code-injection CVE
    assert len(ignore) >= 20


# --- delta state -----------------------------------------------------------

def test_new_advisories_filters_known_case_insensitively():
    uncovered = [{"id": "CVE-A"}, {"id": "CVE-B"}, {"id": "GHSA-C"}]
    known = {"CVE-A", "ghsa-c"}
    assert [u["id"] for u in aw.new_advisories(uncovered, known)] == ["CVE-B"]


def test_advisory_ids_sorted_and_deduped():
    uncovered = [{"id": "CVE-B"}, {"id": "CVE-A"}, {"id": "CVE-A"}, {"id": None}]
    assert aw.advisory_ids(uncovered) == ["CVE-A", "CVE-B"]


def test_state_roundtrip(tmp_path):
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"CVE-B", "CVE-A"})
    assert aw.load_state(p) == {"CVE-A", "CVE-B"}


def test_load_state_missing_file_is_empty(tmp_path):
    assert aw.load_state(tmp_path / "none.json") == set()


# --- CISA KEV source -------------------------------------------------------

def _kev(cve, vendor="Langflow", product="Langflow", name="Langflow RCE",
         added="2026-08-04", due="2026-08-07", ransomware="Unknown", short="boom"):
    return {
        "cveID": cve, "vendorProject": vendor, "product": product,
        "vulnerabilityName": name, "dateAdded": added, "dueDate": due,
        "knownRansomwareCampaignUse": ransomware, "shortDescription": short,
    }


def test_kev_is_ours_matches_ecosystem_keywords():
    assert aw.kev_is_ours(_kev("CVE-1", vendor="Langflow", product="Langflow"))
    assert aw.kev_is_ours(_kev("CVE-2", vendor="LangChain", product="LangGraph"))
    # matched on the vulnerability name even when vendor/product are opaque
    assert aw.kev_is_ours(_kev("CVE-3", vendor="IBM", product="OSS",
                               name="IBM Langflow Code Injection"))
    assert not aw.kev_is_ours(_kev("CVE-4", vendor="Citrix", product="NetScaler",
                                   name="Citrix NetScaler Buffer Overflow"))


def test_uncovered_kev_flags_an_entry_we_do_not_cover():
    result = aw.uncovered_kev([_kev("CVE-2099-7777")], COVERED)
    assert len(result) == 1
    r = result[0]
    assert r["id"] == "CVE-2099-7777"
    assert r["product"] == "Langflow Langflow"
    assert r["date_added"] == "2026-08-04"
    assert r["due_date"] == "2026-08-07"


def test_uncovered_kev_excludes_covered_and_foreign_entries():
    kev = [
        _kev("CVE-2025-3248"),                                     # covered (LD106)
        _kev("CVE-2099-1", vendor="Oracle", product="WebLogic",
             name="Oracle WebLogic Deserialization"),              # not our ecosystem
        _kev("CVE-2099-2"),                                        # genuinely new
    ]
    assert [u["id"] for u in aw.uncovered_kev(kev, COVERED)] == ["CVE-2099-2"]


def test_uncovered_kev_matching_is_case_insensitive_and_deduped():
    kev = [_kev("cve-2025-3248"), _kev("CVE-2099-3"), _kev("CVE-2099-3")]
    assert [u["id"] for u in aw.uncovered_kev(kev, COVERED)] == ["CVE-2099-3"]


def test_uncovered_kev_tolerates_empty_and_malformed_entries():
    # A KEV fetch failure comes through as None; junk rows must not crash the run.
    assert aw.uncovered_kev(None, COVERED) == []
    assert aw.uncovered_kev([{}, {"cveID": ""}], COVERED) == []


def test_uncovered_kev_sorted_by_date_added():
    kev = [_kev("CVE-2099-B", added="2026-08-04"), _kev("CVE-2099-A", added="2026-03-25")]
    assert [u["id"] for u in aw.uncovered_kev(kev, COVERED)] == ["CVE-2099-A", "CVE-2099-B"]


def test_render_issue_puts_kev_first_and_marks_ransomware():
    body = aw.render_issue(
        [{"package": "langflow", "id": "GHSA-x", "aliases": [], "summary": "s", "fixed": []}],
        aw.uncovered_kev([_kev("CVE-2099-9", ransomware="Known")], COVERED),
    )
    assert body.index("CISA KEV") < body.index("OSV")
    assert "CVE-2099-9" in body
    assert "ransomware" in body


def test_render_issue_without_kev_is_unchanged_osv_report():
    body = aw.render_issue(
        [{"package": "langflow", "id": "GHSA-x", "aliases": [], "summary": "s", "fixed": []}]
    )
    assert "CISA KEV" not in body
    assert "advisories.json" in body


def test_every_kev_langflow_cve_in_the_real_db_is_covered():
    """Integration: replay the five KEV Langflow CVEs that 0.1.4 added.

    Before 0.1.4 the watcher only read OSV, and CVE-2026-9198 was not in OSV at
    all — so a CVSS 9.8 known-exploited RCE went unreported for weeks.
    """
    from langdoctor.advisories import load_db

    covered = aw.covered_identifiers(load_db())
    kev = [_kev(c) for c in (
        "CVE-2025-3248", "CVE-2025-34291", "CVE-2026-0770",
        "CVE-2026-33017", "CVE-2026-55255", "CVE-2026-9198",
    )]
    assert aw.uncovered_kev(kev, covered) == []


# --- dual-source delta state ----------------------------------------------

def test_state_keeps_the_two_sources_apart(tmp_path):
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"GHSA-osv"}, {"CVE-kev"})
    assert aw.load_state(p) == {"GHSA-OSV"}
    assert aw.load_kev_state(p) == {"CVE-KEV"}


def test_saving_without_kev_ids_preserves_the_kev_baseline(tmp_path):
    # A KEV fetch failure must not wipe the baseline and re-alert everything.
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"GHSA-a"}, {"CVE-kev"})
    aw.save_state(p, {"GHSA-b"})          # KEV unavailable this run
    assert aw.load_state(p) == {"GHSA-B"}
    assert aw.load_kev_state(p) == {"CVE-KEV"}


def test_saving_without_osv_ids_preserves_the_osv_baseline_verbatim(tmp_path):
    # An OSV outage must leave its entries byte-identical, not re-cased: the
    # ids stay comparable to what OSV itself returns.
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"GHSA-355v-2rjx-fpx7"}, {"CVE-kev"})
    aw.save_state(p, None, {"CVE-kev2"})   # OSV unavailable this run
    assert json.loads(p.read_text(encoding="utf-8"))["known_uncovered"] == [
        "GHSA-355v-2rjx-fpx7"
    ]
    assert aw.load_kev_state(p) == {"CVE-KEV2"}


def test_load_kev_state_missing_file_is_empty(tmp_path):
    assert aw.load_kev_state(tmp_path / "none.json") == set()


# --- langchain-community / langchain-classic coverage ----------------------

def test_packages_include_the_community_and_classic_lines():
    assert "langchain-community" in aw.PACKAGES
    assert "langchain-classic" in aw.PACKAGES
    # partner packages named by advisories that were already tracked
    assert "langchain-openai" in aw.PACKAGES
    assert "langchain-anthropic" in aw.PACKAGES


def test_every_known_langchain_community_cve_is_covered_or_ignored():
    """Every advisory OSV lists for langchain-community must be accounted for.

    Verified against the OSV record set on 2026-08-27: three carry advisories,
    the rest are pre-2025 and explicitly out of scope. A CVE in neither bucket
    would alert every week forever, so this pins the decision rather than
    leaving it to whoever reads the next watch issue.
    """
    from langdoctor.advisories import load_db

    covered = aw.covered_identifiers(load_db())
    ignored = aw.load_ignore(aw.IGNORE_PATH)

    by_advisory = {"CVE-2025-2828", "CVE-2025-6984", "CVE-2026-72848"}
    by_ignore = {"CVE-2024-2057", "CVE-2024-2965", "CVE-2024-3095",
                 "CVE-2024-5998", "CVE-2024-8309"}

    assert by_advisory <= covered
    assert by_ignore <= ignored
    # and none of them silently sits in both buckets
    assert not (by_ignore & covered)


def test_langchain_classic_only_advisory_is_already_out_of_scope():
    # langchain-classic joins the watch list at zero data cost: its sole OSV
    # record is the LangSmith SDK issue we already declared out of scope.
    assert "CVE-2026-45134" in aw.load_ignore(aw.IGNORE_PATH)


def test_community_advisories_are_not_double_listed_in_the_ignore_file():
    ignored = aw.load_ignore(aw.IGNORE_PATH)
    for cve in ("CVE-2025-2828", "CVE-2025-6984", "CVE-2026-72848"):
        assert cve not in ignored


# --- alias-aware delta state (0.1.6) ----------------------------------------

def test_new_pysec_record_for_an_already_alerted_ghsa_is_not_new():
    """Regression: the 2026-10-19 watch comment was 100% duplicates.

    OSV published PYSEC records for ten Langflow GHSAs alerted the week before.
    The delta compared only the primary id, so every PYSEC re-alerted even
    though its aliases named a GHSA already in the state file.
    """
    known = {"GHSA-4f6c-2vvp-gw82"}
    uncovered = [{"id": "PYSEC-2026-4229",
                  "aliases": ["CVE-2026-105741", "GHSA-4f6c-2vvp-gw82"]}]
    assert aw.new_advisories(uncovered, known) == []


def test_alias_overlap_is_case_insensitive():
    uncovered = [{"id": "PYSEC-1", "aliases": ["ghsa-abc"]}]
    assert aw.new_advisories(uncovered, {"GHSA-ABC"}) == []


def test_state_ids_include_aliases_so_a_later_ghsa_is_not_new():
    # The reverse order: a PYSEC alerts first (its aliases name the GHSA), then
    # the GHSA record appears. GHSA records rarely alias their PYSEC twin, so the
    # state must remember every identifier, not just the primary id.
    first_run = [{"id": "PYSEC-2026-1", "aliases": ["CVE-2026-1", "GHSA-aaaa"]}]
    known = set(aw.advisory_ids(first_run))
    assert {"PYSEC-2026-1", "CVE-2026-1", "GHSA-aaaa"} <= known
    second_run = [{"id": "GHSA-aaaa", "aliases": ["CVE-2026-1"]}]
    assert aw.new_advisories(second_run, known) == []


def test_genuinely_new_advisory_still_alerts_with_aliases_present():
    uncovered = [{"id": "GHSA-new", "aliases": ["CVE-2099-5"]}]
    assert [u["id"] for u in aw.new_advisories(uncovered, {"GHSA-old"})] == ["GHSA-new"]


def test_advisory_ids_tolerates_records_without_aliases():
    # KEV entries carry no aliases key at all.
    assert aw.advisory_ids([{"id": "CVE-2099-1"}]) == ["CVE-2099-1"]


# --- multi-package advisories in the report (0.1.6) -------------------------

def _multi_pkg_vuln():
    return {
        "id": "GHSA-6hmw-9432-67qq",
        "aliases": ["CVE-2026-115883"],
        "summary": "Namespace labels containing . reach other namespaces",
        "affected": [
            {"package": {"name": "langgraph-checkpoint-postgres"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]},
            {"package": {"name": "langgraph-checkpoint-sqlite"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.2"}]}]},
        ],
    }


def test_uncovered_advisory_lists_every_affected_package():
    # Regression: GHSA-6hmw was reported as sqlite-only although Postgres is
    # affected too (with a different fix version), because the record was
    # attributed to whichever watched package returned it first.
    osv = {"langgraph-checkpoint-sqlite": [_multi_pkg_vuln()],
           "langgraph-checkpoint-postgres": [_multi_pkg_vuln()]}
    [r] = aw.uncovered_advisories(osv, COVERED)
    assert r["packages"] == ["langgraph-checkpoint-postgres", "langgraph-checkpoint-sqlite"]


def test_packages_falls_back_to_the_queried_package():
    osv = {"langflow": [{"id": "GHSA-x"}]}  # no "affected" block at all
    [r] = aw.uncovered_advisories(osv, COVERED)
    assert r["packages"] == ["langflow"]


def test_render_issue_names_every_affected_package():
    osv = {"langgraph-checkpoint-sqlite": [_multi_pkg_vuln()]}
    body = aw.render_issue(aw.uncovered_advisories(osv, COVERED))
    assert "langgraph-checkpoint-postgres" in body
    assert "langgraph-checkpoint-sqlite" in body


# --- langgraph-sdk coverage (0.1.6) -----------------------------------------

def test_packages_include_langgraph_sdk():
    assert "langgraph-sdk" in aw.PACKAGES


def test_every_known_langgraph_sdk_advisory_is_covered():
    """Every advisory OSV listed for langgraph-sdk on 2026-11-18 must be covered,
    so adding the package to the watch list cannot open a spurious issue."""
    from langdoctor.advisories import load_db

    covered = aw.covered_identifiers(load_db())
    assert {
        "GHSA-3FX2-CQW9-XR3C",   # CVE-2026-118667 -> LD130 / LD131
        "GHSA-FVWW-7H3R-VFHP",   # CVE-2026-104873 -> LD132
        "PYSEC-2026-4240",       # its PYSEC twin
        "GHSA-W39P-VH2G-G8G5",   # CVE-2026-48776 -> LD112 / LD133
        "PYSEC-2026-2575",       # its langgraph-sdk PYSEC record
        "GHSA-6HMW-9432-67QQ",   # CVE-2026-115883 -> LD128 / LD129
    } <= covered


def test_malformed_affected_entries_do_not_crash_the_package_listing():
    # Review finding: a junk `affected` row must not abort the whole OSV report.
    vuln = {"id": "GHSA-junk", "affected": [None, "x", {"package": "langflow"},
                                            {"package": {"name": "langflow"}}]}
    [r] = aw.uncovered_advisories({"langflow": [vuln]}, COVERED)
    assert r["packages"] == ["langflow"]


# --- NVD baseline drift as a third source ------------------------------------

def _drift_entry(cve="CVE-2099-8", version="1.14.0"):
    return {"id": cve, "advisory": "LD150", "package": "langflow", "baseline": "1.13.0",
            "bound": "fixed", "version": version, "source": "cpe", "cvss": 9.8,
            "published": "2026-11-20", "summary": "IBM Langflow OSS ... RCE"}


def test_render_issue_orders_kev_then_drift_then_osv():
    body = aw.render_issue(
        [{"package": "langflow", "id": "GHSA-x", "aliases": [], "summary": "s", "fixed": []}],
        aw.uncovered_kev([_kev("CVE-2099-9")], COVERED),
        [_drift_entry()],
    )
    assert body.index("CISA KEV") < body.index("Baseline drift") < body.index("OSV")
    assert "CVE-2099-8" in body


def test_render_issue_with_only_drift():
    body = aw.render_issue([], None, [_drift_entry()])
    assert "Baseline drift" in body
    assert "CISA KEV" not in body
    assert "advisories.json" in body


def test_drift_state_is_kept_apart_from_osv_and_kev(tmp_path):
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"GHSA-osv"}, {"CVE-kev"}, {"CVE-drift"})
    assert aw.load_state(p) == {"GHSA-OSV"}
    assert aw.load_kev_state(p) == {"CVE-KEV"}
    assert aw.load_drift_state(p) == {"CVE-DRIFT"}


def test_saving_without_drift_ids_preserves_the_drift_baseline(tmp_path):
    # An NVD outage (or rate limit) must not wipe the baseline and re-alert.
    p = tmp_path / ".watch-state.json"
    aw.save_state(p, {"GHSA-a"}, {"CVE-kev"}, {"CVE-drift"})
    aw.save_state(p, {"GHSA-b"}, {"CVE-kev"})          # NVD unavailable this run
    assert aw.load_drift_state(p) == {"CVE-DRIFT"}


def test_drift_delta_alerts_once():
    drift = [_drift_entry("CVE-2099-1"), _drift_entry("CVE-2099-2")]
    known = set(aw.advisory_ids(drift[:1]))
    assert [d["id"] for d in aw.new_advisories(drift, known)] == ["CVE-2099-2"]


def test_load_drift_state_missing_file_is_empty(tmp_path):
    assert aw.load_drift_state(tmp_path / "none.json") == set()


# --- fetch_nvd and source isolation (review hardening) -----------------------

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _page(records, total):
    return _Resp(json.dumps({"vulnerabilities": records, "totalResults": total}).encode())


def _fake_urlopen(responses, seen=None):
    queue = list(responses)

    def urlopen(req, timeout=None):
        if seen is not None:
            seen.append(req)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
    return urlopen


def _http(code):
    return urllib.error.HTTPError("https://nvd", code, "err", {}, None)


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(aw.time, "sleep", lambda s: None)


def test_fetch_nvd_follows_pages_until_total(monkeypatch, no_sleep):
    seen = []
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen(
        [_page([{"cve": {"id": "A"}}, {"cve": {"id": "B"}}], 3), _page([{"cve": {"id": "C"}}], 3)],
        seen))
    assert [r["cve"]["id"] for r in aw.fetch_nvd("langflow")] == ["A", "B", "C"]
    assert "startIndex=2" in seen[1].full_url


def test_fetch_nvd_treats_a_short_empty_page_as_failure(monkeypatch, no_sleep):
    # Review finding: returning the partial list would empty the drift state
    # and re-alert everything next week.
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen(
        [_page([{"cve": {"id": "A"}}], 5), _page([], 5)]))
    assert aw.fetch_nvd("langflow") is None


def test_fetch_nvd_retries_a_transient_error(monkeypatch, no_sleep):
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen(
        [_http(503), _page([{"cve": {"id": "A"}}], 1)]))
    assert [r["cve"]["id"] for r in aw.fetch_nvd("langflow")] == ["A"]


def test_fetch_nvd_gives_up_as_none_without_raising(monkeypatch, no_sleep):
    monkeypatch.setattr(aw.urllib.request, "urlopen",
                        _fake_urlopen([_http(503)] * 10))
    assert aw.fetch_nvd("langflow") is None


def test_fetch_nvd_sends_the_optional_api_key(monkeypatch, no_sleep):
    seen = []
    monkeypatch.setenv("NVD_API_KEY", "k-123")
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen([_page([], 0)], seen))
    assert aw.fetch_nvd("langflow") == []
    assert seen[0].get_header("Apikey") == "k-123"


def _isolated_main(monkeypatch, tmp_path, drift_raises=False):
    state = tmp_path / ".watch-state.json"
    aw.save_state(state, {"GHSA-old"}, set(), {"CVE-kept"})
    monkeypatch.setattr(aw, "STATE_PATH", state)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    monkeypatch.setattr(aw, "fetch_kev", lambda: [_kev("CVE-2099-7777")])
    monkeypatch.setattr(aw, "fetch_osv", lambda p: [])
    monkeypatch.setattr(aw, "fetch_nvd", lambda k: [])
    if drift_raises:
        def boom(*a, **k):
            raise ValueError("unexpected NVD shape")
        monkeypatch.setattr(aw.bd, "baseline_drift", boom)
    assert aw.main() == 0
    return state


def test_a_crashing_source_does_not_lose_the_others(monkeypatch, tmp_path):
    # Review finding: an exception in the drift path used to abort main()
    # before the KEV/OSV report and state were written.
    state = _isolated_main(monkeypatch, tmp_path, drift_raises=True)
    assert "CVE-2099-7777" in (tmp_path / "advisory-report.md").read_text(encoding="utf-8")
    assert aw.load_kev_state(state) == {"CVE-2099-7777"}
    assert aw.load_state(state) == set()             # OSV ran: nothing uncovered
    assert aw.load_drift_state(state) == {"CVE-KEPT"}  # drift failed: baseline kept
    assert (tmp_path / "out").read_text(encoding="utf-8") == "new_count=1\n"


def test_main_writes_an_empty_report_when_nothing_is_new(monkeypatch, tmp_path):
    monkeypatch.setattr(aw, "uncovered_kev", lambda v, c: [])
    _isolated_main(monkeypatch, tmp_path)
    assert (tmp_path / "advisory-report.md").read_text(encoding="utf-8") == ""
    assert (tmp_path / "out").read_text(encoding="utf-8") == "new_count=0\n"


def test_render_issue_neutralises_mentions_in_osv_and_kev_text():
    body = aw.render_issue(
        [{"package": "langflow", "id": "GHSA-x", "aliases": [], "summary": "by @alice",
          "fixed": []}],
        aw.uncovered_kev([_kev("CVE-2099-9", short="ping @bob")], COVERED),
    )
    assert "@alice" not in body and "@bob" not in body


# --- second review pass -------------------------------------------------------

@pytest.mark.parametrize("payload", [{}, {"message": "rate limited"},
                                     {"totalResults": "5", "vulnerabilities": []},
                                     {"totalResults": 3}])
def test_fetch_nvd_rejects_a_malformed_reply(monkeypatch, no_sleep, payload):
    # Review finding: a 200 with no results schema used to read as "0 CVEs",
    # emptying the drift state and re-alerting everything next week.
    monkeypatch.setattr(aw.urllib.request, "urlopen",
                        _fake_urlopen([_Resp(json.dumps(payload).encode())] * 3))
    assert aw.fetch_nvd("langflow") is None


def test_fetch_nvd_retries_a_dropped_connection(monkeypatch, no_sleep):
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen(
        [ConnectionResetError("reset"), _page([{"cve": {"id": "A"}}], 1)]))
    assert [r["cve"]["id"] for r in aw.fetch_nvd("langflow")] == ["A"]


def test_fetch_nvd_gives_up_once_its_time_budget_is_spent(monkeypatch, no_sleep):
    clock = iter([0.0, aw.NVD_DEADLINE_S + 1] + [aw.NVD_DEADLINE_S + 2] * 20)
    monkeypatch.setattr(aw.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(aw.urllib.request, "urlopen", _fake_urlopen(
        [_page([{"cve": {"id": "A"}}], 3)] * 5))
    assert aw.fetch_nvd("langflow") is None


def test_zero_nvd_records_keeps_the_drift_baseline(monkeypatch, tmp_path):
    # ~240 Langflow CVEs exist; an empty answer is an outage, not good news.
    state = _isolated_main(monkeypatch, tmp_path)
    assert aw.load_drift_state(state) == {"CVE-KEPT"}


def test_a_failing_drift_render_still_writes_the_rest(monkeypatch, tmp_path):
    def boom(entries):
        raise KeyError("bound")
    monkeypatch.setattr(aw.bd, "render_drift", boom)
    monkeypatch.setattr(aw.bd, "baseline_drift", lambda records, adv, covered: [
        {"id": "CVE-2099-5", "advisory": "LD150", "package": "langflow",
         "baseline": "1.13.0"}])
    monkeypatch.setattr(aw, "fetch_nvd", lambda k: [{"cve": {"id": "CVE-2099-5"}}])
    state = tmp_path / ".watch-state.json"
    monkeypatch.setattr(aw, "STATE_PATH", state)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(aw, "fetch_kev", lambda: [_kev("CVE-2099-7777")])
    monkeypatch.setattr(aw, "fetch_osv", lambda p: [])
    assert aw.main() == 0
    report = (tmp_path / "advisory-report.md").read_text(encoding="utf-8")
    assert "CVE-2099-7777" in report       # KEV section survived
    assert "CVE-2099-5" in report          # drift CVE still named, unrendered
    assert aw.load_drift_state(state) == {"CVE-2099-5"}


def test_kev_product_mentions_are_neutralised():
    body = aw.render_issue([], aw.uncovered_kev(
        [_kev("CVE-2099-9", vendor="Langflow @mallory")], COVERED))
    assert "@mallory" not in body


def test_deprecated_ld112_still_covers_the_misattributed_pysec_record():
    # PYSEC-2026-2194 files the SDK CVE under `langgraph`; deprecating LD112
    # must not turn it into a weekly "uncovered" alert.
    from langdoctor.advisories import load_db

    covered = aw.covered_identifiers(load_db())
    osv = {"langgraph": [{"id": "PYSEC-2026-2194",
                          "aliases": ["CVE-2026-48776", "GHSA-w39p-vh2g-g8g5"]}]}
    assert aw.uncovered_advisories(osv, covered) == []
