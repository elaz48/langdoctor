"""Category 2xx/4xx (exposure): untrusted-input and endpoint-exposure heuristics."""

from __future__ import annotations

import ast
import re

from ..analysis import find_calls, import_entries, load_sources, project_uses, read_project_file
from ..finding import Finding
from . import register_check

_WEB_FRAMEWORKS = ("fastapi", "flask", "starlette", "django", "sanic", "aiohttp")

_AUTOLOGIN_OFF = re.compile(
    r"LANGFLOW_AUTO_LOGIN\s*[:=]\s*[\"']?\s*(false|0|no|off)\b", re.IGNORECASE
)
_CONFIG_SUFFIXES = (".env", ".yml", ".yaml", ".toml", ".sh", ".cfg", ".ini", ".conf", ".py", ".txt")


@register_check(
    id="LD203", category="exposure", severity="high", heuristic=True,
    title="Checkpoint history filtered by user-controlled input",
)
def checkpoint_from_user_input(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        if sf.tree is None:
            continue
        modules = {mod for mod, _, _ in import_entries(sf.tree)}
        if not any(m.split(".")[0] in _WEB_FRAMEWORKS for m in modules):
            continue
        params = _handler_parameters(sf.tree)
        for call in find_calls(sf.tree, "get_state_history"):
            if _has_param_argument(call, params):
                findings.append(Finding(
                    id="LD203", severity="high", heuristic=True,
                    title="Checkpoint history filtered by user-controlled input",
                    detail=(
                        "get_state_history() is called with a value that appears to flow from a "
                        "request handler parameter. If the filter is attacker-controlled it may "
                        "enable checkpoint enumeration or injection. (heuristic)"
                    ),
                    file=sf.rel, line=call.lineno,
                ))
    return findings


def _handler_parameters(tree: ast.Module) -> set[str]:
    params: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.arg not in ("self", "cls"):
                    params.add(arg.arg)
    return params


def _has_param_argument(call: ast.Call, params: set[str]) -> bool:
    args = list(call.args) + [kw.value for kw in call.keywords]
    return any(isinstance(arg, ast.Name) and arg.id in params for arg in args)


@register_check(
    id="LD403", category="exposure", severity="critical",
    title="Langflow auto-login not explicitly disabled",
)
def langflow_autologin(project) -> list[Finding]:
    if not project_uses(project, "langflow"):
        return []
    if _autologin_disabled(project):
        return []
    return [Finding(
        id="LD403", severity="critical",
        title="Langflow auto-login not explicitly disabled",
        detail=(
            "Langflow enables unauthenticated auto-login by default — the actively exploited "
            "configuration behind CVE-2025-3248 and CVE-2026-5027. Set LANGFLOW_AUTO_LOGIN=false "
            "and configure real authentication before exposing the instance."
        ),
        fix="Set LANGFLOW_AUTO_LOGIN=false (env/compose/config) and enable authentication",
        refs=(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://docs.langflow.org/configuration-authentication",
        ),
    )]


def _autologin_disabled(project) -> bool:
    for rel in project.present_files:
        base = rel.split("/")[-1].lower()
        is_config = (
            base.startswith(".env")
            or base == "dockerfile"
            or rel.lower().endswith(_CONFIG_SUFFIXES)
        )
        if not is_config:
            continue
        if _AUTOLOGIN_OFF.search(read_project_file(project, rel)):
            return True
    return False
