import json
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
    assert "advisories as of 2026-08-11" in out


def test_cli_list_checks(capsys):
    rc = main(["list-checks"])
    assert rc == 0
    assert "LD106" in capsys.readouterr().out


def test_cli_scan_error_returns_2(capsys):
    rc = main([str(FIX / "nope_does_not_exist")])
    assert rc == 2
    assert "scan error" in capsys.readouterr().err


def test_cli_json_format(capsys):
    rc = main([str(FIX / "vulnerable_project"), "--format", "json"])
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "langdoctor"
    assert any(f["id"] == "LD106" for f in doc["findings"])


def test_cli_sarif_format(capsys):
    rc = main([str(FIX / "vulnerable_project"), "--format", "sarif"])
    assert rc == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"


def test_cli_markdown_format(capsys):
    rc = main([str(FIX / "vulnerable_project"), "--format", "markdown"])
    assert rc == 1
    assert "| Severity | ID |" in capsys.readouterr().out


def test_cli_config_fail_on_never(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.langdoctor]\nfail-on = "never"\n', encoding="utf-8"
    )
    rc = main([str(tmp_path), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["total"] > 0  # findings exist
    assert rc == 0                        # ...but config says never fail


def test_cli_config_ignore(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("langflow==1.2.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.langdoctor]\nignore = ["LD106", "LD111", "LD403"]\n', encoding="utf-8"
    )
    main([str(tmp_path), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    ids = {f["id"] for f in doc["findings"]}
    assert not ({"LD106", "LD111", "LD403"} & ids)
