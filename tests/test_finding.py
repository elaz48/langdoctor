from langdoctor.finding import Finding


def _kev_finding():
    return Finding(
        id="LD106",
        severity="critical",
        title="Unauthenticated RCE",
        cve="CVE-2025-3248",
        aliases=("GHSA-rvqx-wpfh-mfx7", "PYSEC-2025-36"),
    )


def test_matches_by_id_cve_and_alias():
    f = _kev_finding()
    assert f.matches_id("LD106")
    assert f.matches_id("ld106")
    assert f.matches_id("CVE-2025-3248")
    assert f.matches_id("GHSA-rvqx-wpfh-mfx7")
    assert f.matches_id("pysec-2025-36")


def test_does_not_match_unrelated_token():
    f = _kev_finding()
    assert not f.matches_id("LD999")
    assert not f.matches_id("")


def test_severity_rank_ordering():
    assert Finding("x", "critical", "t").severity_rank > Finding("y", "low", "t").severity_rank
    assert Finding("z", "unknown", "t").severity_rank == 0


def test_finding_is_immutable():
    import dataclasses

    f = _kev_finding()
    try:
        f.severity = "low"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Finding should be frozen/immutable")
