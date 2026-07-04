"""Project discovery: find dependency sources and Python files, parse deps.

Prefers exact versions (lockfiles, `==` pins). Uses pathlib throughout and
reads files as UTF-8 with replacement so a stray byte never aborts a scan.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None       # exact resolved version, when known
    specifier: str | None     # raw version specifier, when only a range is known
    source: str               # relative path of the file it came from
    line: int | None = None


@dataclass
class Project:
    root: Path
    dependencies: list[Dependency] = field(default_factory=list)
    python_files: list[Path] = field(default_factory=list)
    present_files: set[str] = field(default_factory=set)
    pyproject: dict | None = None


DEFAULT_EXCLUDES = {
    ".git", ".venv", "venv", "env", ".env", "node_modules", "build", "dist",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".tox", "site-packages",
}


def scan(root, excludes: set[str] | None = None) -> Project:
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {root}")
    excludes = set(excludes or ()) | DEFAULT_EXCLUDES
    project = Project(root=root)
    _discover_files(root, excludes, project)
    _collect_dependencies(root, project)
    return project


def _discover_files(root: Path, excludes: set[str], project: Project) -> None:
    if root.is_file():
        return
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in excludes for part in rel_parts):
            continue
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            project.present_files.add(rel)
            if path.suffix == ".py":
                project.python_files.append(path)


def _collect_dependencies(root: Path, project: Project) -> None:
    deps: list[Dependency] = []

    req = root / "requirements.txt"
    if req.is_file():
        deps.extend(parse_requirements(req, "requirements.txt"))

    pp = root / "pyproject.toml"
    if pp.is_file():
        data = _read_toml(pp)
        project.pyproject = data
        deps.extend(parse_pyproject_deps(data, "pyproject.toml"))

    uv = root / "uv.lock"
    if uv.is_file():
        deps.extend(parse_lock(_read_toml(uv), "uv.lock"))

    poetry = root / "poetry.lock"
    if poetry.is_file():
        deps.extend(parse_lock(_read_toml(poetry), "poetry.lock"))

    project.dependencies = deps


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def parse_requirements(path: Path, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()  # drop environment markers
        dep = _dep_from_requirement(line, source, i)
        if dep:
            deps.append(dep)
    return deps


def _dep_from_requirement(spec_str: str, source: str, line: int | None) -> Dependency | None:
    try:
        req = Requirement(spec_str)
    except InvalidRequirement:
        return None
    if req.url:  # direct URL / VCS reference: name known, version not
        return Dependency(req.name, None, None, source, line)
    exact = _exact_from_specifier(req.specifier)
    if exact:
        return Dependency(req.name, exact, None, source, line)
    spec = str(req.specifier) or None
    return Dependency(req.name, None, spec, source, line)


def _exact_from_specifier(specifier) -> str | None:
    pins = [s for s in specifier if s.operator in ("==", "===")]
    if len(pins) == 1:
        return pins[0].version.replace(".*", "").replace("*", "0")
    return None


def parse_pyproject_deps(data: dict, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    project = data.get("project", {}) or {}

    for item in project.get("dependencies", []) or []:
        dep = _dep_from_requirement(item, source, None)
        if dep:
            deps.append(dep)
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for item in group or []:
            dep = _dep_from_requirement(item, source, None)
            if dep:
                deps.append(dep)

    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    for name, constraint in (poetry.get("dependencies", {}) or {}).items():
        if name.lower() == "python":
            continue
        dep = _dep_from_poetry(name, constraint, source)
        if dep:
            deps.append(dep)
    return deps


def _dep_from_poetry(name: str, constraint, source: str) -> Dependency | None:
    if isinstance(constraint, dict):
        constraint = constraint.get("version")
    if not isinstance(constraint, str) or not constraint.strip():
        return Dependency(name, None, None, source, None)
    return Dependency(name, None, _poetry_to_specifier(constraint.strip()), source, None)


def _poetry_to_specifier(constraint: str) -> str | None:
    """Convert the common caret/tilde forms to PEP 440 specifiers; best effort."""
    if constraint == "*":
        return None
    if constraint.startswith("^"):
        base = constraint[1:]
        parts = base.split(".")
        try:
            major = int(parts[0])
        except (ValueError, IndexError):
            return None
        if major > 0:
            upper = f"{major + 1}.0.0"
        elif len(parts) >= 2:
            try:
                upper = f"0.{int(parts[1]) + 1}.0"
            except ValueError:
                upper = "1.0.0"
        else:
            upper = "1.0.0"
        return f">={base},<{upper}"
    if constraint.startswith("~"):
        return f"~={constraint[1:]}"
    return constraint


def parse_lock(data: dict, source: str) -> list[Dependency]:
    """uv.lock and poetry.lock both use [[package]] tables with name + version."""
    deps: list[Dependency] = []
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append(Dependency(name, str(version), None, source, None))
    return deps
