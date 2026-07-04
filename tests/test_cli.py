from pathlib import Path

from langdoctor.cli import main

FIX = Path(__file__).parent / "fixtures"


def test_cli_vulnerable_returns_1(capsys):
    rc = main([str(FIX / "vulnerable_project")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "LD106" in out


def test_cli_clean_returns_0(capsys):
    rc = main([str(FIX / "clean_project")])
    assert rc == 0
    assert "All clear" in capsys.readouterr().out


def test_cli_fail_on_never_returns_0():
    assert main([str(FIX / "vulnerable_project"), "--fail-on", "never"]) == 0


def test_cli_ignore_flag(capsys):
    rc = main([str(FIX / "vulnerable_project"), "--ignore", "LD106,CVE-2026-5027"])
    out = capsys.readouterr().out
    assert "LD106" not in out
    assert "LD111" not in out  # suppressed via its CVE alias
    assert rc == 1  # other findings remain


def test_cli_version(capsys):
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "langdoctor" in out
    assert "advisories as of 2026-07-04" in out


def test_cli_list_checks(capsys):
    rc = main(["list-checks"])
    assert rc == 0
    assert "LD106" in capsys.readouterr().out


def test_cli_scan_error_returns_2(capsys):
    rc = main([str(FIX / "nope_does_not_exist")])
    assert rc == 2
    assert "scan error" in capsys.readouterr().err
