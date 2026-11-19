"""The repo's own docs and config must agree with the code they describe.

These guard against drift that no unit test of the package would notice: the
README once told users to run `elaz48/langdoctor@v1` while only 0.1.x tags
existed, so the documented GitHub Action could not be resolved at all.
"""

import re
from pathlib import Path

import pytest

from langdoctor import __version__

ROOT = Path(__file__).parent.parent
MAJOR_TAG = "v" + __version__.split(".")[0]
ACTION_REF = re.compile(r"elaz48/langdoctor@([A-Za-z0-9._-]+)")


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "rel", ["README.md", "site/index.html", "src/langdoctor/output/console.py"]
)
def test_documented_action_ref_is_the_current_major_tag(rel):
    refs = ACTION_REF.findall(_read(rel))
    assert refs, f"{rel} no longer shows the GitHub Action usage"
    # A full commit SHA is the hardened form and is always acceptable.
    tags = {ref for ref in refs if not re.fullmatch(r"[0-9a-f]{40}", ref)}
    assert tags == {MAJOR_TAG}


def test_readme_precommit_rev_is_the_current_release():
    revs = re.findall(r"^\s*rev:\s*(\S+)", _read("README.md"), flags=re.MULTILINE)
    assert revs == [f"v{__version__}"]


def test_release_workflow_ignores_the_moving_major_tag():
    # `v0` is a tag too. Under a `v*` trigger, pushing it by hand would start a
    # release run that can only fail the version guard.
    workflow = _read(".github/workflows/release.yml")
    assert 'tags: ["v[0-9]+.[0-9]+.[0-9]+"]' in workflow
    assert 'tags: ["v*"]' not in workflow


def test_action_does_not_interpolate_inputs_into_shell():
    # `${{ inputs.x }}` inside `run:` is pasted into the script before the shell
    # parses it. Inputs must arrive through `env:` instead.
    in_run_block = False
    for line in _read("action.yml").splitlines():
        stripped = line.strip()
        if stripped.startswith("run:"):
            in_run_block = True
        elif stripped.startswith(("- name:", "env:", "shell:", "outputs:")):
            in_run_block = False
        if in_run_block:
            assert "${{" not in line, f"expression inside a run block: {stripped}"


def _release_jobs() -> dict[str, str]:
    """Split release.yml into {job id: the job's text}."""
    text = _read(".github/workflows/release.yml")
    body = text.split("\njobs:\n", 1)[1]
    jobs: dict[str, str] = {}
    current = None
    for line in body.splitlines():
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if header:
            current = header.group(1)
            jobs[current] = ""
        elif current:
            jobs[current] += line + "\n"
    return jobs


def test_release_workflow_pins_every_action_to_a_commit_sha():
    # The workflow that can publish to PyPI must not run a tag that can move.
    refs = re.findall(
        r"^\s*(?:-\s+)?uses:\s*(\S+)", _read(".github/workflows/release.yml"), flags=re.MULTILINE
    )
    assert refs
    unpinned = [ref for ref in refs if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref)]
    assert unpinned == []


def test_pypi_token_job_only_publishes():
    # PyPI's Trusted Publisher is bound to release.yml + environment `pypi`.
    # The one job that can mint that token must run nothing but the download of
    # the already-built files and the publish action: no build tools, no shell,
    # no write access to the repository.
    jobs = _release_jobs()
    holders = [name for name, body in jobs.items() if "id-token: write" in body]
    assert holders == ["publish"]
    publish = jobs["publish"]
    assert "environment: pypi" in publish
    assert "contents: write" not in publish
    assert "run:" not in publish
    assert len(re.findall(r"^\s*(?:-\s+)?uses:", publish, flags=re.MULTILINE)) == 2


def test_release_is_refused_for_a_commit_that_is_not_on_main():
    jobs = _release_jobs()
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in jobs["build"]
    assert "needs: build" in jobs["publish"]
