"""Minimal realistic module so the fixture looks like a real project."""

from langgraph.graph import StateGraph


def build():
    graph = StateGraph(dict)
    return graph.compile()
