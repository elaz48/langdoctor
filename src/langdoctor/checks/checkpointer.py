"""Category 2xx (state): checkpointer configuration checks."""

from __future__ import annotations

from ..analysis import call_kwargs, find_calls, load_sources, project_uses, read_project_file
from ..finding import Finding
from . import register_check

_PROD_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "fly.toml", "render.yaml", "render.yml", "Procfile", "railway.toml",
}
_K8S_MARKERS = ("kind: Deployment", "kind: StatefulSet", "kind: Pod", "apiVersion: apps/")


def _production_signals(project) -> list[str]:
    signals: list[str] = []
    for rel in project.present_files:
        base = rel.split("/")[-1]
        if base in _PROD_FILENAMES:
            signals.append(rel)
        elif base.endswith((".yaml", ".yml")):
            text = read_project_file(project, rel)
            if any(marker in text for marker in _K8S_MARKERS):
                signals.append(rel)
    return sorted(set(signals))


@register_check(
    id="LD201", category="checkpointer", severity="high",
    title="MemorySaver used in a production-bound project",
)
def memory_saver_in_prod(project) -> list[Finding]:
    signals = _production_signals(project)
    if not signals:
        return []
    hint = ", ".join(signals[:3])
    findings = []
    for sf in load_sources(project):
        for call in find_calls(sf.tree, "MemorySaver"):
            findings.append(Finding(
                id="LD201", severity="high",
                title="MemorySaver used in a production-bound project",
                detail=(
                    "MemorySaver keeps checkpoints in process memory — state is lost on restart "
                    f"and not shared across replicas. Production indicators present ({hint}). "
                    "Use a durable checkpointer."
                ),
                file=sf.rel, line=call.lineno,
                fix="Use PostgresSaver (or another durable checkpointer) in production",
                refs=("https://langchain-ai.github.io/langgraph/how-tos/persistence/",),
            ))
    return findings


@register_check(
    id="LD202", category="checkpointer", severity="medium",
    title="SqliteSaver may collapse under write concurrency",
)
def sqlite_saver_concurrency(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        calls = find_calls(sf.tree, "SqliteSaver") + find_calls(sf.tree, "AsyncSqliteSaver")
        for call in calls:
            findings.append(Finding(
                id="LD202", severity="medium",
                title="SqliteSaver may collapse under write concurrency",
                detail=(
                    "SqliteSaver serializes writes and degrades badly under concurrent load. "
                    "For production throughput, use PostgresSaver."
                ),
                file=sf.rel, line=call.lineno,
                fix="Use PostgresSaver for concurrent production workloads",
                refs=("https://langchain-ai.github.io/langgraph/how-tos/persistence/",),
            ))
    return findings


@register_check(
    id="LD204", category="checkpointer", severity="medium",
    title="Compiled graph with interrupts has no checkpointer",
)
def missing_checkpointer_with_interrupts(project) -> list[Finding]:
    if not project_uses(project, "langgraph"):
        return []
    findings = []
    for sf in load_sources(project):
        uses_interrupt = bool(find_calls(sf.tree, "interrupt"))
        for call in find_calls(sf.tree, "compile"):
            kwargs = call_kwargs(call)
            has_interrupt = (
                uses_interrupt or "interrupt_before" in kwargs or "interrupt_after" in kwargs
            )
            if has_interrupt and "checkpointer" not in kwargs:
                findings.append(Finding(
                    id="LD204", severity="medium",
                    title="Compiled graph with interrupts has no checkpointer",
                    detail=(
                        "A graph using interrupts / human-in-the-loop is compiled without a "
                        "checkpointer, so interrupted runs cannot resume. Pass checkpointer=..."
                    ),
                    file=sf.rel, line=call.lineno,
                    fix="Pass checkpointer=... to graph.compile()",
                ))
    return findings
