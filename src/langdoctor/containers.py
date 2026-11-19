"""Container images as a dependency source.

Langflow is mostly deployed from its official image, so a Dockerfile's
`FROM langflowai/langflow:1.2.0` or a compose `image:` line says as much about
the installed version as a requirements pin does. This module only reads image
references out of Dockerfiles and YAML. Which image means which package is
data: `container_images` in advisories.json.

Both formats are read line by line, the way LD502 reads workflows, so no YAML
or Dockerfile parser joins the dependency set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class ImageRef:
    repository: str  # lower-case, Docker Hub's registry prefix removed
    tag: str | None
    line: int


_DOCKER_HUB_PREFIXES = (
    "docker.io/", "index.docker.io/", "registry-1.docker.io/", "registry.hub.docker.com/",
)
# FROM [--platform=...] image[:tag][@digest] [AS name]
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.IGNORECASE)
_ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$", re.IGNORECASE)
# An `image:` KEY with a scalar value, optionally quoted, optionally followed by
# a comment. A templated value (`{{ .Values.image }}`) does not match.
_IMAGE_RE = re.compile(r"""^\s*(?:-\s+)?image:\s*(["']?)([^\s"'#]+)\1\s*(?:#.*)?$""")
# $VAR, ${VAR}, ${VAR:-default}, ${VAR-default}. The default is length-bounded:
# an unbounded `[^}]*` rescans to the end of the line for every unclosed `${A-`,
# which is quadratic on a crafted line.
_VARIABLE_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}\s]{0,200}))?\}|([A-Za-z_][A-Za-z0-9_]*))"
)
_FULL_RELEASE_SEGMENTS = 3  # X.Y.Z
# No image reference is anywhere near this long; a longer line is not one, and
# skipping it keeps every pattern here cheap on hostile input.
_MAX_LINE_LENGTH = 4096


def is_dockerfile(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in ("dockerfile", "containerfile")
        or lowered.startswith(("dockerfile.", "containerfile."))
        or lowered.endswith((".dockerfile", ".containerfile"))
    )


def dockerfile_images(text: str) -> list[ImageRef]:
    """Every FROM line's image, with global `ARG NAME=default` values filled in.

    Only an ARG declared before the first FROM is visible to FROM lines; Docker
    scopes one declared inside a stage to that stage.
    """
    variables: dict[str, str] = {}
    refs: list[ImageRef] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > _MAX_LINE_LENGTH:
            continue
        arg = _ARG_RE.match(line)
        if arg:
            if not refs and arg.group(2) is not None:
                variables = {**variables, arg.group(1): arg.group(2).strip().strip("\"'")}
            continue
        match = _FROM_RE.match(line)
        if match:
            repository, tag = parse_image(_substitute(match.group(1), variables))
            refs.append(ImageRef(repository, tag, lineno))
    return refs


def yaml_images(text: str) -> list[ImageRef]:
    """Every `image: name[:tag]` line: compose services, Kubernetes containers."""
    if "image:" not in text:
        return []
    refs: list[ImageRef] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > _MAX_LINE_LENGTH:
            continue
        match = _IMAGE_RE.match(line)
        if match:
            repository, tag = parse_image(_substitute(match.group(2), {}))
            refs.append(ImageRef(repository, tag, lineno))
    return refs


def parse_image(reference: str) -> tuple[str, str | None]:
    """Split `[registry[:port]/]path[:tag][@digest]` into (repository, tag)."""
    name = reference.strip().split("@", 1)[0]
    tag = None
    # A colon before the last "/" is a registry port, not a tag.
    colon = name.find(":", name.rfind("/") + 1)
    if colon != -1:
        name, tag = name[:colon], name[colon + 1:] or None
    name = name.lower()
    for prefix in _DOCKER_HUB_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name, tag


def tag_version(tag: str | None) -> str | None:
    """The package version a release tag names, or None.

    `1.13.3`, `v1.13.3` and `1.13.3-amd64` all name 1.13.3. A tag that does not
    START with a full X.Y.Z version is not read as one: `latest` floats, and a
    prefixed tag such as `base-0.11.6` (the langflow-base build) belongs to a
    different version line, where the advisory ranges do not apply.
    """
    if not tag:
        return None
    head = tag.split("-", 1)[0]
    if head[:1] in ("v", "V"):
        head = head[1:]
    try:
        version = Version(head)
    except InvalidVersion:
        return None
    if len(version.release) < _FULL_RELEASE_SEGMENTS:
        return None
    return head


def _substitute(text: str, variables: dict[str, str]) -> str:
    """Expand $VAR, ${VAR} and ${VAR:-default}. A variable with no known value
    and no default is left exactly as written, so it never looks like a tag."""

    def replace(match: re.Match) -> str:
        value = variables.get(match.group(1) or match.group(3))
        if value:
            return value
        default = match.group(2)
        return default if default is not None else match.group(0)

    return _VARIABLE_RE.sub(replace, text)
