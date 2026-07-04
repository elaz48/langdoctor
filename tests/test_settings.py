from langdoctor.settings import load_settings


def test_defaults_when_no_pyproject(tmp_path):
    s = load_settings(tmp_path)
    assert s.fail_on is None
    assert s.ignore == []
    assert s.exclude == []


def test_reads_tool_langdoctor_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.langdoctor]\n"
        'fail-on = "critical"\n'
        'ignore = ["LD203", "LD302"]\n'
        'exclude = ["examples", "vendor"]\n',
        encoding="utf-8",
    )
    s = load_settings(tmp_path)
    assert s.fail_on == "critical"
    assert s.ignore == ["LD203", "LD302"]
    assert s.exclude == ["examples", "vendor"]


def test_missing_table_is_empty(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    s = load_settings(tmp_path)
    assert s.fail_on is None and s.ignore == []
