from langdoctor.checks.hygiene import unpinned_dependencies, unpinned_github_actions
from langdoctor.scanner import scan


def _write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan(tmp_path)


def test_ld501_unpinned_without_lockfile(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langgraph>=1.0\nrich\n"})
    findings = unpinned_dependencies(project)
    assert [f.id for f in findings] == ["LD501"]
    assert findings[0].severity == "medium"


def test_ld501_clean_when_all_pinned(tmp_path):
    project = _write(tmp_path, {"requirements.txt": "langgraph==1.2.7\nrich==13.9.0\n"})
    assert unpinned_dependencies(project) == []


def test_ld501_clean_with_lockfile(tmp_path):
    project = _write(tmp_path, {
        "requirements.txt": "langgraph>=1.0\n",
        "uv.lock": '[[package]]\nname = "langgraph"\nversion = "1.2.7"\n',
    })
    assert unpinned_dependencies(project) == []


def test_ld502_unpinned_action(tmp_path):
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": (
            "jobs:\n  x:\n    steps:\n      - uses: tj-actions/changed-files@v44\n"
        ),
    })
    findings = unpinned_github_actions(project)
    assert [f.id for f in findings] == ["LD502"]
    assert "tj-actions" in findings[0].detail


def test_ld502_clean_when_sha_pinned(tmp_path):
    sha = "a" * 40
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": f"steps:\n  - uses: tj-actions/changed-files@{sha}\n",
    })
    assert unpinned_github_actions(project) == []


def test_ld502_ignores_first_party_actions(tmp_path):
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": "steps:\n  - uses: actions/checkout@v4\n",
    })
    assert unpinned_github_actions(project) == []


def test_ld502_ignores_actions_that_are_only_mentioned_in_comments(tmp_path):
    # A commented-out step and prose that quotes a `uses:` line run nothing.
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      # - uses: some-org/disabled-action@v1\n"
            "      # the way `uses: some-org/quoted-action@v2` would\n"
            "      - run: echo uses: some-org/echoed-action@v3\n"
        ),
    })
    assert unpinned_github_actions(project) == []


def test_ld502_flags_every_form_of_a_real_uses_key(tmp_path):
    project = _write(tmp_path, {
        ".github/workflows/ci.yml": (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: some-org/first@v1\n"
            "      - name: second\n"
            "        uses: 'some-org/second@main'  # a trailing comment\n"
            "      -   uses: \"some-org/third@v3\"\n"
            "  reusable:\n"
            "    uses: some-org/workflows/.github/workflows/build.yml@v4\n"
        ),
    })
    findings = unpinned_github_actions(project)
    assert [f.line for f in findings] == [4, 6, 7, 9]


def test_ld501_judges_each_manifest_directory_by_its_own_lockfile(tmp_path):
    project = _write(tmp_path, {
        "locked/pyproject.toml": '[project]\ndependencies = ["langgraph>=1.0"]\n',
        "locked/uv.lock": '[[package]]\nname = "langgraph"\nversion = "1.2.7"\n',
        "loose/requirements.txt": "langgraph>=1.0\nrich\n",
    })
    findings = unpinned_dependencies(project)
    assert [(f.id, f.file) for f in findings] == [("LD501", "loose/requirements.txt")]
    assert "loose/" in findings[0].detail


def test_ld501_root_lockfile_covers_workspace_members(tmp_path):
    project = _write(tmp_path, {
        "uv.lock": '[[package]]\nname = "langgraph"\nversion = "1.2.7"\n',
        "packages/agent/pyproject.toml": '[project]\ndependencies = ["langgraph>=1.0"]\n',
    })
    assert unpinned_dependencies(project) == []


def test_ld501_is_about_python_dependencies_not_container_images(tmp_path):
    project = _write(tmp_path, {"Dockerfile": "FROM langflowai/langflow:latest\n"})
    assert unpinned_dependencies(project) == []
