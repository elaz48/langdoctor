"""Aggregate-baseline drift detection against NVD (scripts/baseline_drift.py).

LD150 drifted twice — 1.10.1 (0.1.4) and 1.11.0 (0.1.6) — because IBM PSIRT
publishes Langflow CVEs that OSV never indexes. These tests pin the pure logic
the watcher uses to notice that before a release ships stale.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import baseline_drift as bd  # noqa: E402

from langdoctor.advisories import VersionRange, load_db  # noqa: E402

# --- NVD record builders (shapes copied from real NVD CVE API 2.0 records) ---


def _cpe(product="langflow", version="*", vendor="langflow", vulnerable=True, **bounds):
    return {
        "vulnerable": vulnerable,
        "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        **bounds,
    }


def _nvd(cve_id, desc="Langflow is affected.", cpes=(), status="Analyzed",
         score=9.8, published="2026-10-29T15:16:00.000"):
    cve = {
        "id": cve_id,
        "vulnStatus": status,
        "published": published,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"type": "Secondary",
                                       "cvssData": {"baseScore": score}}]},
    }
    if cpes:
        cve["configurations"] = [{"nodes": [{"cpeMatch": list(cpes)}]}]
    return {"cve": cve}


IBM_THROUGH_1_12_8 = _nvd(
    "CVE-2026-110186",
    "IBM Langflow OSS 1.0.0 through 1.12.8 could allow a remote attacker to "
    "execute arbitrary code due to improper control of code generation.",
    cpes=[
        _cpe(versionStartIncluding="1.0.0", versionEndExcluding="1.13.0"),
        _cpe(vendor="apple", product="macos", version="-", vulnerable=False),
    ],
)


def _aggregate(baseline, package="langflow", id="LD150"):
    return SimpleNamespace(
        id=id, package=package, aggregate=True, fixed_in=baseline,
        ranges=(VersionRange(introduced="0", fixed=baseline),),
    )


# --- version bounds: CPE ---------------------------------------------------

def test_cpe_end_excluding_is_the_fix_version():
    assert bd.version_bounds(IBM_THROUGH_1_12_8, "langflow") == [
        bd.Bound("fixed", "1.13.0", "cpe")
    ]


def test_cpe_end_including_is_the_last_affected_version():
    rec = _nvd("CVE-1", cpes=[_cpe(versionEndIncluding="1.12.8")])
    assert bd.version_bounds(rec, "langflow") == [bd.Bound("through", "1.12.8", "cpe")]


def test_cpe_with_an_exact_version_marks_that_version_affected():
    rec = _nvd("CVE-1", cpes=[_cpe(version="1.9.3")])
    assert bd.version_bounds(rec, "langflow") == [bd.Bound("affected", "1.9.3", "cpe")]


def test_cpe_wildcard_without_an_end_is_unfixed():
    rec = _nvd("CVE-1", cpes=[_cpe(versionStartIncluding="1.0.0")])
    assert bd.version_bounds(rec, "langflow") == [bd.Bound("unfixed", "*", "cpe")]


def test_cpe_ignores_platform_and_other_products():
    rec = _nvd("CVE-1", cpes=[
        _cpe(vendor="linux", product="linux_kernel", version="-", vulnerable=False),
        _cpe(vendor="flowiseai", product="flowise", versionEndExcluding="9.9.9"),
    ])
    assert bd.version_bounds(rec, "langflow") == []


# --- version bounds: description fallback (CPE not assigned yet) -----------

@pytest.mark.parametrize("desc, expected", [
    # every phrasing seen on CPE-less Langflow CVEs on NVD, 2026-11-18
    ("Langflow 1.0.16 before 1.12.0 and 0.0.94 before 1.12.0 contain an unsafe eval()",
     [bd.Bound("fixed", "1.12.0", "description")]),
    ("langflow-ai langflow v1.9.3 is affected by: Code Injection.",
     [bd.Bound("affected", "1.9.3", "description")]),
    ("Before Langflow 1.10.3, the MCP stdio transport launched whatever command",
     [bd.Bound("fixed", "1.10.3", "description")]),
    ("From 1.0.0 until 1.10.1, Langflow did not verify flow ownership",
     [bd.Bound("fixed", "1.10.1", "description")]),
    ("Prior to 1.9.0, any authenticated Langflow user can achieve RCE",
     [bd.Bound("fixed", "1.9.0", "description")]),
    ("IBM Langflow OSS 1.0.0 through 1.11.1 is vulnerable to SSRF.",
     [bd.Bound("through", "1.11.1", "description")]),
])
def test_description_phrasings(desc, expected):
    assert bd.version_bounds(_nvd("CVE-1", desc), "langflow") == expected


def test_description_without_a_version_yields_no_bound():
    assert bd.version_bounds(_nvd("CVE-1", "Langflow mishandles input."), "langflow") == []


def test_cpe_wins_over_the_description():
    # NVD's analysed CPE is authoritative; the CNA prose is only a fallback.
    rec = _nvd("CVE-1", "IBM Langflow OSS 1.0.0 through 1.11.1 is vulnerable.",
               cpes=[_cpe(versionEndExcluding="1.11.2")])
    assert bd.version_bounds(rec, "langflow") == [bd.Bound("fixed", "1.11.2", "cpe")]


# --- drift decision --------------------------------------------------------

@pytest.mark.parametrize("bound, drifts", [
    (bd.Bound("fixed", "1.13.0", "cpe"), False),     # fixed AT the baseline: covered
    (bd.Bound("fixed", "1.13.1", "cpe"), True),      # 1.13.0 itself is affected
    (bd.Bound("through", "1.13.0", "cpe"), True),
    (bd.Bound("through", "1.12.8", "cpe"), False),
    (bd.Bound("affected", "1.13.0", "cpe"), True),
    (bd.Bound("affected", "1.9.3", "cpe"), False),
    (bd.Bound("unfixed", "*", "cpe"), True),         # no fix at all
    (bd.Bound("fixed", "not-a-version", "cpe"), False),
])
def test_drifting_bound(bound, drifts):
    assert (bd.drifting_bound([bound], "1.13.0") is not None) is drifts


def test_drifting_bound_reports_the_highest_offending_version():
    bounds = [bd.Bound("fixed", "1.13.1", "description"),
              bd.Bound("fixed", "1.14.0", "description")]
    assert bd.drifting_bound(bounds, "1.13.0").version == "1.14.0"


# --- end to end over NVD records -------------------------------------------

def test_replay_0_1_6_drift_against_the_old_baseline():
    """CVE-2026-110186 (fixed 1.13.0) went unnoticed while LD150 sat at 1.11.0."""
    [entry] = bd.baseline_drift([IBM_THROUGH_1_12_8], _aggregate("1.11.0"), set())
    assert entry["id"] == "CVE-2026-110186"
    assert entry["advisory"] == "LD150"
    assert entry["baseline"] == "1.11.0"
    assert (entry["bound"], entry["version"], entry["source"]) == ("fixed", "1.13.0", "cpe")
    assert entry["cvss"] == 9.8
    assert entry["published"] == "2026-10-29"
    assert "through 1.12.8" in entry["summary"]


def test_current_ld150_baseline_has_no_drift_for_that_cve():
    ld150 = {a.id: a for a in load_db().advisories}["LD150"]
    assert bd.baseline_drift([IBM_THROUGH_1_12_8], ld150, set()) == []


def test_covered_rejected_and_foreign_records_are_skipped():
    agg = _aggregate("1.13.0")
    records = [
        _nvd("CVE-2099-1", "Before Langflow 1.14.0, boom."),               # drift
        _nvd("CVE-2099-2", "Before Langflow 1.14.0, boom."),               # covered
        _nvd("CVE-2099-3", "Before Langflow 1.14.0.", status="Rejected"),  # rejected
        _nvd("CVE-2099-4", "Flowise before 3.1.5 mentions langflow.",       # other product
             cpes=[_cpe(vendor="flowiseai", product="flowise",
                        versionEndExcluding="3.1.5")]),
    ]
    got = bd.baseline_drift(records, agg, {"cve-2099-2"})
    assert [e["id"] for e in got] == ["CVE-2099-1"]


def test_malformed_nvd_records_do_not_crash():
    agg = _aggregate("1.13.0")
    junk = [None, {}, {"cve": None}, {"cve": {"id": "CVE-1"}},
            {"cve": {"id": "CVE-2", "configurations": [None, {"nodes": [None]}]}}]
    assert bd.baseline_drift(junk, agg, set()) == []


def test_drift_entries_are_sorted_highest_version_first():
    agg = _aggregate("1.13.0")
    records = [_nvd("CVE-A", "Before Langflow 1.13.2, x."),
               _nvd("CVE-B", "Before Langflow 1.14.0, x.")]
    assert [e["id"] for e in bd.baseline_drift(records, agg, set())] == ["CVE-B", "CVE-A"]


# --- targets ---------------------------------------------------------------

def test_real_db_watches_ld150_on_nvd():
    watched, unmapped = bd.baseline_targets(load_db())
    assert [(adv.id, keyword) for adv, keyword in watched] == [("LD150", "langflow")]
    assert unmapped == []


def test_an_aggregate_without_an_nvd_keyword_is_reported_not_skipped_silently():
    db = SimpleNamespace(advisories=[_aggregate("1.0.0", package="newpkg", id="LD151"),
                                     SimpleNamespace(id="LD101", aggregate=False)])
    watched, unmapped = bd.baseline_targets(db)
    assert watched == []
    assert [a.id for a in unmapped] == ["LD151"]


def test_baseline_is_the_highest_fixed_bound():
    agg = SimpleNamespace(fixed_in=None, ranges=(VersionRange("0", "1.12.9"),
                                                 VersionRange("1.13.0.dev0", "1.13.0")))
    assert bd.baseline_of(agg) == "1.13.0"


# --- report ----------------------------------------------------------------

def test_render_names_advisory_baseline_cves_and_suggested_bump():
    agg = _aggregate("1.13.0")
    drift = bd.baseline_drift(
        [_nvd("CVE-A", "Before Langflow 1.13.2, x."),
         _nvd("CVE-B", "IBM Langflow OSS 1.0.0 through 1.14.1 is vulnerable.")],
        agg, set())
    body = "\n".join(bd.render_drift(drift))
    assert "LD150" in body and "1.13.0" in body
    assert "CVE-A" in body and "CVE-B" in body
    assert "through 1.14.1" in body
    assert "1.13.2" in body  # highest stated fix -> suggested new baseline


def test_render_of_no_drift_is_empty():
    assert bd.render_drift([]) == []


def test_same_fix_version_sorts_most_severe_first():
    agg = _aggregate("1.13.0")
    records = [_nvd("CVE-2026-9", "Before Langflow 1.14.0, x.", score=4.3),
               _nvd("CVE-2026-1", "Before Langflow 1.14.0, x.", score=9.8)]
    assert [e["id"] for e in bd.baseline_drift(records, agg, set())] == ["CVE-2026-1",
                                                                        "CVE-2026-9"]


def test_render_caps_a_long_listing_to_stay_under_githubs_body_limit():
    # A long gap between runs once produced 145 drift CVEs; GitHub rejects issue
    # bodies over 65,536 characters, which would lose the whole report.
    agg = _aggregate("1.13.0")
    records = [_nvd(f"CVE-2099-{i:04d}", "IBM Langflow OSS 1.0.0 through 1.13.5 " + "x" * 400)
               for i in range(150)]
    lines = bd.render_drift(bd.baseline_drift(records, agg, set()))
    listed = [line for line in lines if line.startswith("- `CVE-")]
    assert len(listed) == bd.MAX_LISTED
    assert any(f"{150 - bd.MAX_LISTED} more" in line for line in lines)
    assert len("\n".join(lines)) < 30_000


# --- review hardening -------------------------------------------------------

def test_versions_of_other_products_in_the_prose_are_ignored():
    # Review finding: "Python before 3.12" must not read as a Langflow fix.
    desc = ("Langflow before 1.12.0 contains an unsafe eval(). Exploitation "
            "requires Python before 3.12 and litellm prior to 1.83.0.")
    assert bd.version_bounds(_nvd("CVE-1", desc), "langflow") == [
        bd.Bound("fixed", "1.12.0", "description")
    ]


@pytest.mark.parametrize("desc, expected", [
    ("Langflow 1.14.0 and earlier allows RCE.", bd.Bound("through", "1.14.0", "description")),
    ("Langflow <= 1.14.0 allows RCE.", bd.Bound("through", "1.14.0", "description")),
    ("Langflow < 1.14.0 allows RCE.", bd.Bound("fixed", "1.14.0", "description")),
    ("Langflow before version 1.14.0 allows RCE.", bd.Bound("fixed", "1.14.0", "description")),
    ("Langflow from 1.0.0 to 1.14.0 allows RCE.", bd.Bound("through", "1.14.0", "description")),
    ("All versions of Langflow allow RCE.", bd.Bound("unfixed", "*", "description")),
])
def test_more_description_phrasings(desc, expected):
    assert expected in bd.version_bounds(_nvd("CVE-1", desc), "langflow")


def test_prerelease_suffixes_are_kept():
    # "through 1.13.0-rc.1" is BELOW 1.13.0; truncating it to 1.13.0 would drift.
    rec = _nvd("CVE-1", "IBM Langflow OSS 1.0.0 through 1.13.0-rc.1 is vulnerable.")
    assert bd.baseline_drift([rec], _aggregate("1.13.0"), set()) == []


def test_unparseable_cpe_less_record_still_alerts():
    # Review finding: a watcher that drops what it cannot parse defeats its
    # purpose. No CPE yet and no recognisable version -> report for a human.
    [entry] = bd.baseline_drift([_nvd("CVE-1", "Langflow mishandles input.")],
                                _aggregate("1.13.0"), set())
    assert entry["bound"] == "unparsed"


def test_unparseable_record_for_another_product_is_not_ours():
    assert bd.baseline_drift([_nvd("CVE-1", "Flowise mishandles input.")],
                             _aggregate("1.13.0"), set()) == []


def test_list_shaped_metrics_do_not_crash():
    rec = _nvd("CVE-1", "Before Langflow 1.14.0, x.")
    rec["cve"]["metrics"] = [{"cvssData": {"baseScore": 9.8}}]  # list, not dict
    [entry] = bd.baseline_drift([rec], _aggregate("1.13.0"), set())
    assert entry["cvss"] is None


def test_suggestion_says_the_baseline_must_clear_a_through_bound():
    drift = bd.baseline_drift(
        [_nvd("CVE-B", "IBM Langflow OSS 1.0.0 through 1.14.1 is vulnerable.")],
        _aggregate("1.13.0"), set())
    assert "above 1.14.1" in "\n".join(bd.render_drift(drift))


def test_mentions_in_nvd_text_are_neutralised():
    # NVD prose lands in a GitHub issue; "@someone" there would ping them.
    drift = bd.baseline_drift([_nvd("CVE-1", "Before Langflow 1.14.0, see @octocat.")],
                              _aggregate("1.13.0"), set())
    body = "\n".join(bd.render_drift(drift))
    assert "@octocat" not in body
    assert "octocat" in body


# --- second review pass -------------------------------------------------------

@pytest.mark.parametrize("desc", [
    "An issue in FooLib is fixed in 3.0.0. Langflow is mentioned.",
    "Langflow is a tool. Prior to version 1.9.0, X. The dependency foo was patched in 2.5.0.",
])
def test_patched_in_for_another_component_is_not_a_langflow_fix(desc):
    versions = {b.version for b in bd.version_bounds(_nvd("CVE-1", desc), "langflow")}
    assert not versions & {"3.0.0", "2.5.0"}


@pytest.mark.parametrize("desc", [
    "Langflow is a tool for building agents. A path traversal exists in the upload "
    "API. This issue has been patched in version 1.14.0.",
    "Langflow is a tool for building agents. A path traversal exists in the upload "
    "API. Version 1.14.0 contains a patch for the issue.",
])
def test_cna_patched_boilerplate_still_counts(desc):
    assert bd.Bound("fixed", "1.14.0", "description") in bd.version_bounds(
        _nvd("CVE-1", desc), "langflow")


def test_patched_boilerplate_needs_the_product_somewhere():
    desc = "A tool for agents. This issue has been patched in version 9.0.0."
    assert bd.version_bounds(_nvd("CVE-1", desc), "langflow") == []


@pytest.mark.parametrize("desc", [
    "IBM Langflow OSS 1.0.0 through 1.13.0-dev is vulnerable.",
    "IBM Langflow OSS 1.0.0 through 1.13.0-alpha is vulnerable.",
])
def test_digitless_prerelease_suffixes_are_kept(desc):
    assert bd.baseline_drift([_nvd("CVE-1", desc)], _aggregate("1.13.0"), set()) == []


def test_a_hyphenated_word_after_a_version_is_not_a_prerelease():
    rec = _nvd("CVE-1", "Langflow before 1.14.0-based deployments is affected.")
    assert bd.Bound("fixed", "1.14.0", "description") in bd.version_bounds(rec, "langflow")


def test_no_mentions_keeps_emails_and_neutralises_issue_refs():
    out = bd.no_mentions("mail sec@langflow.org, ping @alice, see #123")
    assert "sec@langflow.org" in out
    assert "@alice" not in out and "alice" in out
    assert "#123" not in out and "123" in out
