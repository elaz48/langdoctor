"""Category 3xx: graph & runtime configuration checks."""

from __future__ import annotations

from ..analysis import call_kwargs, find_calls, import_entries, load_sources, project_uses
from ..finding import Finding
from . import register_check

_INVOKE_METHODS = ("invoke", "ainvoke", "stream", "astream")

_CHAT_MODELS = {
    "ChatOpenAI", "AzureChatOpenAI", "ChatAnthropic", "ChatBedrock", "ChatBedrockConverse",
    "ChatGoogleGenerativeAI", "ChatVertexAI", "ChatMistralAI", "ChatCohere", "ChatOllama",
    "ChatGroq", "ChatFireworks",
}
_TIMEOUT_KWARGS = {"timeout", "request_timeout", "default_request_timeout"}

# (module, imported_name) pairs that indicate legacy pre-1.0 LangChain APIs.
_DEPRECATED_IMPORTS = {
    ("langchain.agents", "AgentExecutor"),
    ("langchain.agents", "initialize_agent"),
    ("langchain.chains", "LLMChain"),
    ("langchain.chains", "ConversationChain"),
    ("langchain.chains", "RetrievalQA"),
}


@register_check(
    id="LD301", category="config", severity="medium",
    title="No recursion_limit configured for a LangGraph run",
)
def no_recursion_limit(project) -> list[Finding]:
    if not project_uses(project, "langgraph"):
        return []
    invoked_at = None
    for sf in load_sources(project):
        if "recursion_limit" in sf.text:
            return []  # configured somewhere — good enough
        if invoked_at is None:
            for method in _INVOKE_METHODS:
                calls = find_calls(sf.tree, method)
                if calls:
                    invoked_at = (sf.rel, calls[0].lineno)
                    break
    if invoked_at is None:
        return []
    return [Finding(
        id="LD301", severity="medium",
        title="No recursion_limit configured for a LangGraph run",
        detail=(
            "A graph is invoked but no recursion_limit is set anywhere; a runaway loop can burn "
            "tokens and money before it stops. Set recursion_limit in the run config."
        ),
        file=invoked_at[0], line=invoked_at[1],
        fix="Pass config={'recursion_limit': N} when invoking the graph",
    )]


@register_check(
    id="LD302", category="config", severity="low", heuristic=True,
    title="LLM client created without a timeout",
)
def no_llm_timeout(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        for model in _CHAT_MODELS:
            for call in find_calls(sf.tree, model):
                if not (_TIMEOUT_KWARGS & call_kwargs(call)):
                    findings.append(Finding(
                        id="LD302", severity="low", heuristic=True,
                        title="LLM client created without a timeout",
                        detail=(
                            f"{model} is constructed without timeout/request_timeout; a hung "
                            "provider call can stall the agent indefinitely. (heuristic)"
                        ),
                        file=sf.rel, line=call.lineno,
                        fix=f"Pass timeout=... to {model}(...)",
                    ))
    return findings


@register_check(
    id="LD303", category="config", severity="info",
    title="Deprecated pre-1.0 LangChain import",
)
def deprecated_imports(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        for mod, name, lineno in import_entries(sf.tree):
            if (mod, name) in _DEPRECATED_IMPORTS:
                findings.append(Finding(
                    id="LD303", severity="info",
                    title="Deprecated pre-1.0 LangChain import",
                    detail=(
                        f"{mod}.{name} is a legacy pre-1.0 API scheduled for removal. "
                        "Migrate to LangGraph / current LangChain equivalents."
                    ),
                    file=sf.rel, line=lineno,
                ))
    return findings


@register_check(
    id="LD304", category="config", severity="high",
    title="Legacy load_prompt() usage",
)
def load_prompt_usage(project) -> list[Finding]:
    findings = []
    for sf in load_sources(project):
        for call in find_calls(sf.tree, "load_prompt"):
            findings.append(Finding(
                id="LD304", severity="high",
                title="Legacy load_prompt() usage",
                detail=(
                    "load_prompt() is a legacy API with a path-traversal history "
                    "(see LD104 / CVE-2026-34070). Avoid loading prompts from untrusted paths and "
                    "upgrade langchain-core."
                ),
                file=sf.rel, line=call.lineno,
                cve="CVE-2026-34070",
                refs=("https://nvd.nist.gov/vuln/detail/CVE-2026-34070",),
            ))
    return findings
