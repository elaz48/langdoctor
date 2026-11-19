from langdoctor.containers import (
    ImageRef,
    dockerfile_images,
    is_dockerfile,
    parse_image,
    tag_version,
    yaml_images,
)


def test_parse_image_splits_repository_and_tag():
    digest = "sha256:" + "a" * 64
    assert parse_image("langflowai/langflow:1.2.0") == ("langflowai/langflow", "1.2.0")
    assert parse_image("langflowai/langflow") == ("langflowai/langflow", None)
    assert parse_image(f"langflowai/langflow@{digest}") == ("langflowai/langflow", None)
    assert parse_image(f"langflowai/langflow:1.2.0@{digest}") == ("langflowai/langflow", "1.2.0")


def test_parse_image_normalizes_docker_hub_spellings():
    for reference in (
        "docker.io/langflowai/langflow:1.2.0",
        "index.docker.io/langflowai/langflow:1.2.0",
        "LangflowAI/Langflow:1.2.0",
    ):
        assert parse_image(reference) == ("langflowai/langflow", "1.2.0")


def test_parse_image_keeps_other_registries_and_their_ports():
    assert parse_image("ghcr.io/langflow-ai/langflow:1.2.0") == (
        "ghcr.io/langflow-ai/langflow", "1.2.0",
    )
    assert parse_image("registry.local:5000/team/langflow:1.2.0") == (
        "registry.local:5000/team/langflow", "1.2.0",
    )
    # the colon belongs to the port, not to a tag
    assert parse_image("registry.local:5000/team/langflow") == (
        "registry.local:5000/team/langflow", None,
    )


def test_tag_version_reads_release_tags():
    assert tag_version("1.2.0") == "1.2.0"
    assert tag_version("v1.2.0") == "1.2.0"
    assert tag_version("1.13.3-amd64") == "1.13.3"
    assert tag_version("1.13.3rc0-arm64") == "1.13.3rc0"
    assert tag_version("1.14.0.dev32") == "1.14.0.dev32"


def test_tag_version_refuses_tags_that_do_not_name_a_release():
    # base-* tags carry the langflow-base version, which is a different version
    # line: reading them as a langflow version would misjudge every advisory.
    for tag in (
        None, "", "latest", "nightly", "base-latest", "base-1.13.3", "base-0.11.6-amd64",
        "1.13", "1", "${LANGFLOW_VERSION}",
    ):
        assert tag_version(tag) is None, tag


def test_dockerfile_from_lines():
    text = (
        "# syntax=docker/dockerfile:1\n"
        "ARG LANGFLOW_VERSION=1.2.0\n"
        "FROM --platform=linux/amd64 python:3.12-slim AS builder\n"
        "# FROM langflowai/langflow:0.0.1\n"
        "FROM langflowai/langflow:${LANGFLOW_VERSION}\n"
        "from langflowai/langflow-backend:$LANGFLOW_VERSION as api\n"
        "FROM builder\n"
        "COPY --from=langflowai/langflow:9.9.9 /app /app\n"
        "RUN echo FROM langflowai/langflow:8.8.8\n"
    )
    assert [(r.repository, r.tag, r.line) for r in dockerfile_images(text)] == [
        ("python", "3.12-slim", 3),
        ("langflowai/langflow", "1.2.0", 5),
        ("langflowai/langflow-backend", "1.2.0", 6),
        ("builder", None, 7),
    ]


def test_dockerfile_variable_defaults():
    text = (
        'ARG TAG="1.9.0"\n'
        "ARG EMPTY\n"
        "FROM langflowai/langflow:${TAG}\n"
        "FROM langflowai/langflow:${OTHER:-1.3.0}\n"
        "FROM langflowai/langflow:${EMPTY}\n"
    )
    assert [r.tag for r in dockerfile_images(text)] == ["1.9.0", "1.3.0", "${EMPTY}"]


def test_yaml_image_lines():
    text = (
        "services:\n"
        "  langflow:\n"
        "    image: langflowai/langflow:1.2.0\n"
        "  db:\n"
        '    image: "postgres:16"\n'
        "  # image: langflowai/langflow:0.0.1\n"
        "  api:\n"
        "    image: ghcr.io/langflow-ai/langflow-backend:${LANGFLOW_VERSION:-1.9.0}  # pinned\n"
        "---\n"
        "containers:\n"
        "  - image: 'langflowai/langflow-ep:1.13.3'\n"
        "    name: ep\n"
        "  - name: x\n"
        "    image: langflowai/langflow\n"
        "  - image: {{ .Values.image }}\n"
        "image:\n"
        "  repository: langflowai/langflow\n"
    )
    assert [(r.repository, r.tag, r.line) for r in yaml_images(text)] == [
        ("langflowai/langflow", "1.2.0", 3),
        ("postgres", "16", 5),
        ("ghcr.io/langflow-ai/langflow-backend", "1.9.0", 8),
        ("langflowai/langflow-ep", "1.13.3", 11),
        ("langflowai/langflow", None, 14),
    ]


def test_is_dockerfile():
    for name in ("Dockerfile", "dockerfile", "Dockerfile.prod", "api.Dockerfile", "Containerfile"):
        assert is_dockerfile(name), name
    for name in ("docker-compose.yml", "README.md", "Dockerfiles.txt", "requirements.txt"):
        assert not is_dockerfile(name), name


def test_an_overlong_line_is_skipped_not_searched():
    # `${A-${A-${A-...` without a closing brace made the variable pattern
    # quadratic: a 150 KB compose file stalled the scan for 20 seconds.
    hostile = "${A-" * 20_000
    assert dockerfile_images(f"FROM x:{hostile}\nFROM langflowai/langflow:1.2.0\n") == [
        ImageRef("langflowai/langflow", "1.2.0", 2)
    ]
    assert yaml_images(f"image: {hostile}\nimage: langflowai/langflow:1.2.0\n") == [
        ImageRef("langflowai/langflow", "1.2.0", 2)
    ]


def test_unclosed_variable_defaults_stay_cheap_below_the_line_limit():
    refs = dockerfile_images("FROM x:" + "${A-" * 800 + "\n")
    assert [r.line for r in refs] == [1]


def test_only_args_declared_before_the_first_from_reach_a_from_line():
    # Docker scopes an ARG declared inside a stage to that stage.
    text = (
        "ARG V=1.2.0\n"
        "FROM python:3.12 AS build\n"
        "ARG V=9.9.9\n"
        "ARG W=8.8.8\n"
        "FROM langflowai/langflow:${V}\n"
        "FROM langflowai/langflow:${W}\n"
    )
    assert [r.tag for r in dockerfile_images(text)] == ["3.12", "1.2.0", "${W}"]
