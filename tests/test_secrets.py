from langdoctor.checks.secrets import env_not_gitignored, hardcoded_secrets
from langdoctor.engine import run_checks
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def test_ld401_detects_anthropic_key(tmp_path):
    key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    project = _write(tmp_path, {"cfg.py": f'API_KEY = "{key}"\n'})
    findings = hardcoded_secrets(project)
    assert [f.id for f in findings] == ["LD401"]
    assert "Anthropic" in findings[0].title
    assert findings[0].severity == "critical"


def test_ld401_detects_aws_key(tmp_path):
    project = _write(tmp_path, {"cfg.py": 'AWS = "AKIAIOSFODNN7EXAMPLE"\n'})
    assert [f.id for f in hardcoded_secrets(project)] == ["LD401"]


def test_ld401_respects_inline_ignore(tmp_path):
    # Inline suppression is applied centrally by the engine, not the check itself.
    key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"
    project = _write(tmp_path, {"cfg.py": f'API_KEY = "{key}"  # langdoctor: ignore=LD401\n'})
    assert [f.id for f in hardcoded_secrets(project)] == ["LD401"]  # raw check still emits
    assert run_checks(scan(tmp_path)) == []  # engine suppresses it


def test_ld401_clean_no_secrets(tmp_path):
    project = _write(tmp_path, {"cfg.py": 'API_KEY = os.environ["API_KEY"]\n'})
    assert hardcoded_secrets(project) == []


def test_ld402_env_not_ignored(tmp_path):
    project = _write(tmp_path, {".env": "SECRET=1\n", ".gitignore": "__pycache__/\n"})
    findings = env_not_gitignored(project)
    assert [f.id for f in findings] == ["LD402"]
    assert findings[0].severity == "high"


def test_ld402_clean_when_ignored(tmp_path):
    project = _write(tmp_path, {".env": "SECRET=1\n", ".gitignore": ".env\n"})
    assert env_not_gitignored(project) == []


def test_ld402_clean_when_wildcard_ignored(tmp_path):
    project = _write(tmp_path, {".env": "SECRET=1\n", ".gitignore": "*.env\n"})
    assert env_not_gitignored(project) == []


def test_ld402_no_env_no_finding(tmp_path):
    project = _write(tmp_path, {".gitignore": "__pycache__/\n"})
    assert env_not_gitignored(project) == []
