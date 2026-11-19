from pathlib import Path

from langdoctor.engine import exit_code_for, run_checks
from langdoctor.scanner import scan

FIX = Path(__file__).parent / "fixtures"


def _ids(findings):
    return {f.id for f in findings}


def test_kev_findings_sort_first():
    findings = run_checks(scan(FIX / "vulnerable_project"))
    assert findings[0].exploited_in_the_wild is True
    # highest-severity KEV (LD106, critical) should lead over the high KEV (LD111)
    assert findings[0].id == "LD106"


def test_ignore_by_ld_id():
    findings = run_checks(scan(FIX / "vulnerable_project"), ignore=["LD101"])
    assert "LD101" not in _ids(findings)


def test_ignore_by_cve_and_alias():
    base = run_checks(scan(FIX / "vulnerable_project"))
    assert "LD106" in _ids(base)

    by_cve = run_checks(scan(FIX / "vulnerable_project"), ignore=["CVE-2025-3248"])
    assert "LD106" not in _ids(by_cve)

    by_alias = run_checks(scan(FIX / "vulnerable_project"), ignore=["GHSA-rvqx-wpfh-mfx7"])
    assert "LD106" not in _ids(by_alias)


def test_exit_code_thresholds():
    findings = run_checks(scan(FIX / "vulnerable_project"))
    assert exit_code_for(findings, fail_on="high") == 1
    assert exit_code_for(findings, fail_on="critical") == 1
    assert exit_code_for(findings, fail_on="never") == 0


def test_clean_project_exits_zero():
    findings = run_checks(scan(FIX / "clean_project"))
    assert findings == []
    assert exit_code_for(findings, fail_on="high") == 0


def test_heuristic_only_findings_need_strict(tmp_path):
    # A lone ChatOpenAI() with no timeout -> only LD302 (heuristic, low). No deps,
    # so no LD501/version findings muddy the exit-code behaviour.
    (tmp_path / "agent.py").write_text(
        "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI(model='gpt-4o')\n",
        encoding="utf-8",
    )
    findings = run_checks(scan(tmp_path))
    assert findings and all(f.heuristic for f in findings)
    assert {f.id for f in findings} == {"LD302"}
    assert exit_code_for(findings, fail_on="low", strict=False) == 0
    assert exit_code_for(findings, fail_on="low", strict=True) == 1


# --- a check that crashes must not pass for a clean result ---------------------

def _add_crashing_check(monkeypatch):
    from langdoctor import engine
    from langdoctor.checks import RegisteredCheck, all_checks

    def boom(project):
        raise RuntimeError("kaboom \x1b[2J")

    checks = [*all_checks(), RegisteredCheck("LD999", "config", "high", "crashes", False, boom)]
    monkeypatch.setattr(engine, "all_checks", lambda: checks)


def test_a_crashing_check_is_recorded_and_the_others_still_run(tmp_path, monkeypatch):
    from langdoctor.engine import run_scan
    from langdoctor.scanner import scan

    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    _add_crashing_check(monkeypatch)
    result = run_scan(scan(tmp_path))
    assert "LD106" in {f.id for f in result.findings}
    # named, typed, and stripped of control characters from the message
    assert result.errors == ["LD999: RuntimeError: kaboom [2J"]


def test_an_incomplete_scan_exits_2_even_when_nothing_else_was_found(tmp_path, monkeypatch, capsys):
    import json

    from langdoctor import cli

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert cli.main([str(tmp_path)]) == 0
    capsys.readouterr()

    _add_crashing_check(monkeypatch)
    assert cli.main([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert "LD999: RuntimeError" in captured.err and "incomplete" in captured.err
    assert "All clear" not in captured.out  # a scan that lost a check is not all clear

    assert cli.main([str(tmp_path), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["errors"] == ["LD999: RuntimeError: kaboom [2J"]
    # even a run that is told never to fail must not report an incomplete scan as fine
    assert cli.main([str(tmp_path), "--fail-on", "never"]) == 2


def test_a_crash_in_the_version_check_is_a_scan_error_too(tmp_path, monkeypatch, capsys):
    from langdoctor import cli, engine

    def boom(project):
        raise ValueError("bad advisory data")

    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    monkeypatch.setattr(engine, "check_versions", boom)
    assert cli.main([str(tmp_path)]) == 2
    assert "known-vulnerability check: ValueError: bad advisory data" in capsys.readouterr().err


def test_a_complete_scan_reports_no_errors(tmp_path, capsys):
    import json

    from langdoctor import cli

    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    assert cli.main([str(tmp_path), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["errors"] == []


def test_an_incomplete_scan_writes_no_sarif(tmp_path, monkeypatch, capsys):
    # GitHub closes every alert a new SARIF upload no longer contains. A file
    # produced while a check was down would close real alerts as "fixed".
    from langdoctor import cli

    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    assert cli.main([str(tmp_path), "--format", "sarif"]) == 1
    assert '"results"' in capsys.readouterr().out

    _add_crashing_check(monkeypatch)
    assert cli.main([str(tmp_path), "--format", "sarif"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no SARIF was written" in captured.err


def test_a_check_that_calls_sys_exit_cannot_end_the_run_as_a_success(tmp_path, monkeypatch, capsys):
    from langdoctor import cli, engine
    from langdoctor.checks import RegisteredCheck, all_checks

    def quits(project):
        raise SystemExit(0)

    checks = [*all_checks(), RegisteredCheck("LD998", "config", "high", "quits", False, quits)]
    monkeypatch.setattr(engine, "all_checks", lambda: checks)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert cli.main([str(tmp_path)]) == 2
    assert "LD998: SystemExit" in capsys.readouterr().err


def test_a_failure_while_rendering_is_a_scan_error_not_a_finding(tmp_path, monkeypatch, capsys):
    from langdoctor import cli

    def broken_render(*args, **kwargs):
        raise RuntimeError("renderer broke")

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "render", broken_render)
    assert cli.main([str(tmp_path)]) == 2  # not 1, which would read as "findings"
    assert "scan error: renderer broke" in capsys.readouterr().err
