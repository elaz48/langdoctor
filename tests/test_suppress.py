from langdoctor.engine import run_checks, run_scan
from langdoctor.scanner import scan
from langdoctor.suppress import line_ignore_tokens


def _ids(findings):
    return {f.id for f in findings}


def test_line_ignore_tokens_parsing():
    assert line_ignore_tokens("x = 1") is None
    assert line_ignore_tokens("x = 1  # langdoctor: ignore") == frozenset()
    assert line_ignore_tokens("x  # langdoctor: ignore=LD203") == frozenset({"ld203"})
    assert line_ignore_tokens("x  # langdoctor: ignore=LD203, LD302") == frozenset(
        {"ld203", "ld302"}
    )


def test_inline_ignore_in_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langgraph==1.0.5  # langdoctor: ignore=LD102\n", encoding="utf-8"
    )
    findings = run_checks(scan(tmp_path))
    assert "LD102" not in _ids(findings)


def test_inline_ignore_by_cve(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langflow==1.2.0  # langdoctor: ignore=CVE-2025-3248\n", encoding="utf-8"
    )
    findings = run_checks(scan(tmp_path))
    assert "LD106" not in _ids(findings)  # suppressed by its CVE
    assert "LD111" in _ids(findings)      # a different langflow CVE still reported


def test_bare_inline_ignore_suppresses_all_on_line(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langflow==1.2.0  # langdoctor: ignore\n", encoding="utf-8"
    )
    findings = run_checks(scan(tmp_path))
    got = _ids(findings)
    assert "LD106" not in got and "LD111" not in got


def test_inline_ignore_in_source_line(tmp_path):
    key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    (tmp_path / "cfg.py").write_text(
        f'API_KEY = "{key}"  # langdoctor: ignore=LD401\n', encoding="utf-8"
    )
    assert run_checks(scan(tmp_path)) == []


def test_wrong_id_does_not_suppress(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langgraph==1.0.5  # langdoctor: ignore=LD999\n", encoding="utf-8"
    )
    findings = run_checks(scan(tmp_path))
    assert "LD102" in _ids(findings)  # LD999 does not match LD102


def test_alias_suppression_is_case_insensitive(tmp_path):
    # lower-cased GHSA alias + mixed-case CVE must both suppress
    (tmp_path / "requirements.txt").write_text(
        "langflow==1.2.0  # langdoctor: ignore=ghsa-rvqx-wpfh-mfx7\n", encoding="utf-8"
    )
    assert "LD106" not in _ids(run_checks(scan(tmp_path)))


def test_run_scan_reports_suppressed_count(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "langflow==1.2.0  # langdoctor: ignore=LD106\n", encoding="utf-8"
    )
    result = run_scan(scan(tmp_path))
    assert result.suppressed == 1
    assert "LD106" not in {f.id for f in result.findings}
