"""Project discovery: find dependency sources and Python files, parse deps.

Dependency sources are read wherever they sit in the tree — a monorepo keeps a
manifest per service — and a known container image counts as an install of its
package. Prefers exact versions (lockfiles, `==` pins). Uses pathlib throughout
and reads files as UTF-8 with replacement so a stray byte never aborts a scan.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from . import containers
from .advisories import load_db

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
    image: str | None = None  # the container image it was read from, if any


@dataclass
class Project:
    root: Path
    dependencies: list[Dependency] = field(default_factory=list)
    python_files: list[Path] = field(default_factory=list)
    present_files: set[str] = field(default_factory=set)
    pyproject: dict | None = None


# Directory names whose *contents* we skip. Matched against parent directories
# only (never the filename) so a top-level `.env` FILE is still discovered.
DEFAULT_EXCLUDES = {
    ".git", ".venv", "venv", "virtualenv", "node_modules", "build", "dist",
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
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune in place (the os.walk contract): a directory removed here is
        # never descended into, so a large node_modules/.venv costs nothing.
        # Only directory names are matched, so a FILE named like an excluded
        # dir (e.g. a top-level `.env`) is still discovered. Sorting makes the
        # scan order, and so the order of equally ranked findings, the same on
        # every filesystem.
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not path.is_file():  # broken symlink, socket, fifo
                continue
            # A link out of the project would put some other file's contents
            # into the report; a link to a file inside it is read as usual.
            if path.is_symlink() and _inside_project(root, path) is None:
                continue
            project.present_files.add(path.relative_to(root).as_posix())
            if path.suffix == ".py":
                project.python_files.append(path)


# Lockfiles that are TOML with [[package]] name/version tables.
_PACKAGE_TABLE_LOCKS = {"uv.lock", "poetry.lock", "pdm.lock"}
_PIPFILE_LOCK = "Pipfile.lock"
_REQUIREMENTS_DIR = "requirements"
# -r other.txt / --requirement other.txt / --requirement=other.txt
_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(\S+)")


def is_lockfile(name: str) -> bool:
    return name in _PACKAGE_TABLE_LOCKS or name == _PIPFILE_LOCK or _is_pylock(name)


def _is_pylock(name: str) -> bool:
    """PEP 751: pylock.toml or pylock.<name>.toml."""
    return name.startswith("pylock.") and name.endswith(".toml")


def is_requirements_file(rel: str) -> bool:
    """requirements.txt, requirements-dev.txt, dev-requirements.txt, requirements/*.txt."""
    parts = rel.split("/")
    name = parts[-1].lower()
    if not name.endswith(".txt"):
        return False
    stem = name[: -len(".txt")]
    if stem.startswith("requirements") or stem.endswith("requirements"):
        return True
    return len(parts) > 1 and parts[-2].lower() == _REQUIREMENTS_DIR


def _collect_dependencies(root: Path, project: Project) -> None:
    """Read every dependency source in the tree, in path order."""
    image_packages = {
        _image_key(image): package for image, package in load_db().container_images.items()
    }
    deps: list[Dependency] = []
    parsed_requirements: set[str] = set()
    for rel in sorted(project.present_files):
        name = rel.rsplit("/", 1)[-1]
        path = root / rel
        if name == "pyproject.toml":
            data = read_toml(path)
            if rel == "pyproject.toml":  # only the root one is the project's own config
                project.pyproject = data
            deps.extend(parse_pyproject_deps(data, rel))
        elif name in _PACKAGE_TABLE_LOCKS:
            deps.extend(parse_lock(read_toml(path), rel))
        elif name == _PIPFILE_LOCK:
            deps.extend(parse_pipfile_lock(path, rel))
        elif _is_pylock(name):
            deps.extend(parse_lock(read_toml(path), rel, table="packages"))
        elif is_requirements_file(rel):
            deps.extend(_requirements_with_includes(root, rel, parsed_requirements))
        elif containers.is_dockerfile(name):
            refs = containers.dockerfile_images(_read_text(path))
            deps.extend(_image_dependencies(refs, rel, image_packages))
        elif name.endswith((".yml", ".yaml")):
            refs = containers.yaml_images(_read_text(path))
            deps.extend(_image_dependencies(refs, rel, image_packages))
    project.dependencies = deps


def _image_dependencies(refs, source: str, image_packages: dict[str, str]) -> list[Dependency]:
    """A known image is an install of its package, at the version its tag names."""
    deps: list[Dependency] = []
    for ref in refs:
        package = image_packages.get(_image_key(ref.repository))
        if package:
            version = containers.tag_version(ref.tag)
            deps.append(Dependency(package, version, None, source, ref.line, image=ref.repository))
    return deps


def _image_key(repository: str) -> str:
    """`org/name`, whatever registry or proxy path comes before it.

    A pull-through mirror (`mirror.corp/docker-remote/langflowai/langflow`)
    serves the same image under the same tags, so it is matched like the
    original.
    """
    return "/".join(repository.split("/")[-2:])


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_toml(path: Path) -> dict:
    """Parse a TOML file, returning {} on error (never raises).

    RecursionError: a document nested thousands of levels deep is not a
    manifest, and must not take the scan down.
    """
    try:
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError, RecursionError):
        return {}


def parse_requirements(path: Path, source: str) -> list[Dependency]:
    """The dependencies one requirements file declares itself (no includes)."""
    return _read_requirements(path, source)[0]


def _read_requirements(path: Path, source: str) -> tuple[list[Dependency], list[str]]:
    """(dependencies, the paths of its `-r` includes exactly as written)."""
    deps: list[Dependency] = []
    includes: list[str] = []
    for i, raw in enumerate(_read_text(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            include = _INCLUDE_RE.match(line)
            if include:
                includes.append(include.group(1))
            continue
        line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()  # drop environment markers
        dep = _dep_from_requirement(line, source, i)
        if dep:
            deps.append(dep)
    return deps, includes


def _requirements_with_includes(root: Path, rel: str, parsed: set[str]) -> list[Dependency]:
    """One requirements file plus everything it `-r` includes.

    `parsed` collects the files already read across the whole scan, so a file
    that is both found by name and included is read once and a cycle ends.
    """
    deps: list[Dependency] = []
    pending = [rel]  # a stack, not recursion: an include chain can be any length
    while pending:
        current = pending.pop()
        if current in parsed:
            continue
        parsed.add(current)
        path = root / current
        found, includes = _read_requirements(path, current)
        deps.extend(found)
        targets = [_inside_project(root, path.parent / target) for target in includes]
        pending.extend(target for target in reversed(targets) if target)
    return deps


def _inside_project(root: Path, candidate: Path) -> str | None:
    """The root-relative path if `candidate` is a file inside the project.

    An include can name any path (`-r ../../etc/passwd`); the scan never
    follows one out of the directory it was asked to scan.
    """
    try:
        resolved = candidate.resolve()
        if resolved.is_file() and resolved.is_relative_to(root):
            return resolved.relative_to(root).as_posix()
    except (OSError, ValueError, RuntimeError):
        # ValueError: a NUL byte in the path. RuntimeError: a symlink loop
        # (Python < 3.13). Either way it is not a file inside the project.
        pass
    return None


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
    """PEP 621 dependencies and extras, plus Poetry's own table.

    A pyproject.toml from an untrusted repository can hold any type anywhere,
    so each level is checked: a malformed part is skipped, the rest is read.
    """
    deps: list[Dependency] = []
    project = _table(data, "project")
    groups = [project.get("dependencies"), *_table(project, "optional-dependencies").values()]
    for group in groups:
        for item in group if isinstance(group, list) else []:
            dep = _dep_from_requirement(item, source, None) if isinstance(item, str) else None
            if dep:
                deps.append(dep)

    poetry = _table(_table(data, "tool"), "poetry")
    for name, constraint in _table(poetry, "dependencies").items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        dep = _dep_from_poetry(name, constraint, source)
        if dep:
            deps.append(dep)
    return deps


def _table(parent, key: str) -> dict:
    """parent[key] when both are tables, else {}."""
    value = parent.get(key) if isinstance(parent, dict) else None
    return value if isinstance(value, dict) else {}


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


def parse_lock(data: dict, source: str, table: str = "package") -> list[Dependency]:
    """uv.lock, poetry.lock and pdm.lock use [[package]] tables with name +
    version; PEP 751's pylock.toml calls the table [[packages]]."""
    deps: list[Dependency] = []
    packages = data.get(table) if isinstance(data, dict) else None
    for pkg in packages if isinstance(packages, list) else []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append(Dependency(str(name), str(version), None, source, None))
    return deps


def parse_pipfile_lock(path: Path, source: str) -> list[Dependency]:
    """Pipfile.lock is JSON: {"default": {name: {"version": "==1.2.3"}}, "develop": {...}}."""
    try:
        data = json.loads(_read_text(path))
    except (ValueError, RecursionError):  # not JSON, or nested absurdly deep
        return []
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        packages = data.get(section) if isinstance(data, dict) else None
        for name, entry in (packages if isinstance(packages, dict) else {}).items():
            version = entry.get("version") if isinstance(entry, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                deps.append(Dependency(str(name), version[2:].strip(), None, source, None))
    return deps
