"""Intentionally vulnerable sample app — powers the langdoctor demo.

DO NOT copy this into a real project. Every line here is a footgun on purpose.
Run `langdoctor examples/vulnerable-agent` to see the findings.
"""

from fastapi import FastAPI
from langchain.agents import AgentExecutor  # LD303: deprecated pre-1.0 import
from langchain_core.prompts import load_prompt  # LD304: legacy load_prompt API
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph

# LD401: hardcoded credential (obviously-fake placeholder — NOT a real key)
OPENAI_API_KEY = "sk-proj-EXAMPLE-NOT-A-REAL-KEY-000000"

app = FastAPI()
llm = ChatOpenAI(model="gpt-4o")  # LD302: no timeout
saver = MemorySaver()  # LD201: in-memory checkpointer in a Dockerized service
prompt = load_prompt("prompts/base.yaml")

graph = StateGraph(dict).compile(checkpointer=saver)
executor = AgentExecutor(agent=None, tools=[])  # LD303: legacy orchestration


@app.get("/history")
def history(thread_id: str):
    # LD203: user-controlled value flows straight into checkpoint history
    return graph.get_state_history(thread_id)


def run():
    return graph.invoke({"input": "hi"})  # LD301: no recursion_limit
