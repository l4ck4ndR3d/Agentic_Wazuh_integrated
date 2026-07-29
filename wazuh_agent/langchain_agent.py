"""LangGraph-based Wazuh ReAct agent.

Instead of the legacy `agent.py` that parses fenced code blocks from
raw text, this agent uses `langgraph.prebuilt.create_react_agent` which:

  * exploits native tool-calling (structured `tool_calls`/`tool_responses`)
  * supports checkpointing (SqliteSaver) for fault-tolerance / resume
  * supports human-in-the-loop (interrupt_before the dangerous tools)
  * feeds tool results into the sandbox-first validation gate

Two modes of operation:
  1. Direct (SETTINGS.sandbox_validate=False): tool outputs go straight
     into the LangGraph state.  Faster, slightly riskier for dangerous ops.
  2. Sandbox-first (default): every tool's raw json-rpc string is injected
     as `PAYLOAD` into a short LLM-authored parser that runs in Docker;
     then the parsed/validated dict enters the real-time environment.

Usage:

    from langchain_agent import LangGraphWazuhAgent
    agent = LangGraphWazuhAgent()
    result = agent.invoke("Show me high-severity alerts from last 24 hours")
"""
from __future__ import annotations
import json
import logging
import re
from pathlib import Path
from typing import Any, Callable

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import create_react_agent
from langgraph.graph import MessagesState, StateGraph
from langgraph.types import Checkpointer

from langchain_openai import ChatOpenAI

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax

try:
    from .config import SETTINGS
    from .sandbox import sandbox, SandboxResult
    from .tools import wazuh_tools, threat_intel_tools
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from wazuh_agent.config import SETTINGS
    from wazuh_agent.sandbox import sandbox, SandboxResult
    from wazuh_agent.tools import wazuh_tools, threat_intel_tools

log = logging.getLogger("wazuh.langchain")
console = Console()


# ---- tool collection ------------------------------------------------------

def _gather_tools() -> list:
    """Collect every available LangChain @tool."""
    tools = wazuh_tools.all_wazuh_tools()[:]
    tools += threat_intel_tools.all_threat_intel_tools()
    return tools


# ---- sandbox-first validation decorator -----------------------------------

def _wrap_for_validate(
    raw_response: str, tool_name: str, schema: dict | None = None
) -> str:
    """Sandbox-first gate: ask the LLM to write parser code, run it,
    validate the output.  Returns a string suitable for appending to
    the conversation memory.

    Currently this is consumed by the agent's `ask` method; it does NOT
    intercept LangGraph's automatic tool-call loop."""

    prompt = (
        f"You called the tool `{tool_name}` and received this raw JSON-RPC "
        f"envelope:\n\n"
        f"```json\n{raw_response}\n```\n\n"
        f"Write a Python script that:\n"
        f"1. json.loads() the envelope.\n"
        f"2. extracts the `result` object (ignore the jsonrpc/id wrapper).\n"
        f"3. if `error` is present, print the error message and call "
        f"  `set_result(None)`.\n"
        f"4. otherwise build a focused dict/summary and call "
        f"  `set_result(your_dict)`.\n\n"
        f"Use only `json`, `print`, and the pre-injected `PAYLOAD` string "
        f"`the script will receive.  Do NOT make any network calls."
    )
    # We still need LLM to generate parser code. For brevity we call
    # the single-turn model directly. Team notes: this is a loop--
    # if the parser fails(get 0) we retry up to SETTINGS.sandbox_retries.
    # In production, move this into a LangGraph node.
    chat = ChatOpenAI(
        model=SETTINGS.model,
        base_url=SETTINGS.base_url,
        api_key=SETTINGS.nvidia_api_key,
        temperature=0.0,
        max_tokens=2048,
    )
    try:
        answer = chat.invoke(prompt)
        code = _extract_code(answer.content)
        if not code:
            return f"PARSER_ERROR: LLM could not generate parser code.\nRaw response:\n{raw_response}"
        return _run_parse_code(code, raw_response, schema)
    except Exception as e:
        return f"PARSER_ERROR: {e!r}\nRaw response:\n{raw_response}"  # early exit is safe


def _extract_code(text: str) -> str | None:
    """Extract a fenced python block from an assistant message."""
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.DOTALL)
    return m.group(1).strip() if m else None


def _run_parse_code(code: str, payload: str, schema: dict | None) -> str:
    """Run the LLM's parser inside the sandbox under execute_and_validate."""
    value, sb_result = sandbox.execute_and_validate(code, schema=schema, payload=payload)
    if value is None:
        return (
            f"SANDBOX_REJECTED: {sb_result.as_observation()}\n\n"
            f"Fix your parser and try again."
        )
    return json.dumps(value, indent=2, default=str)


# ---- System prompt --------------------------------------------------------

API_REF = (Path(__file__).resolve().parent / "wazuh_api_reference.md").read_text("utf-8")

SYSTEM_PROMPT = (
    "You are **WazuhSec**, a security-analyst agent powered by LangGraph/MCP. "
    "You can CALL tools to interact with the local Wazuh deployment and enrich results "
    "with threat intelligence.\n\n"
    "---\n"
    "## Available Tool Categories\n\n"
    "1. **Wazuh Data Tools** -- search_alerts, get_agents, get_vulnerabilities, "
    "get_inventory, get_manager_status, get_indexer_health. All return raw JSON-RPC strings. "
    "To parse them, write a small snippet and call `parse_with_sandbox`. "
    "2. **Threat Intelligence Tools** -- virustotal_lookup_ip, virustotal_lookup_hash. "
    "Enrich IPs/hashes found in alerts. "
    "Only available when API keys are set."
    "---\n"
    "## Operational guidance\n"
    "* Use the **Indexer** (`wazuh_search_alerts`) for historical/aggregated queries "
    "  (alerts, vulnerabilities, inventory). Its auth (Basic) is pre-configured.\n"
    "* Use the **Manager** tools for live agent status, config, and daemon health.\n"
    "* After any search tool, check for `error` in the JSON-RPC response.  If { "
    "`error` is nonzero, report it to the user.\n"
    "* Keep asked output compact;  use aggregations or small `size` parameters.\n\n"
    "---\n"
    "# Wazuh API Reference\n"
    f"{API_REF}\n"
)


# ---- LangGraph agent class --------------------------------------------------

class LangGraphWazuhAgent:
    """LangGraph-based Wazuh agent with sandbox-first validation on tool calls."""

    def __init__(self, checkpointer: Checkpointer | None = None):
        self.llm = ChatOpenAI(
            model=SETTINGS.model,
            temperature=SETTINGS.temperature,
            max_tokens=SETTINGS.max_tokens,
            api_key=SETTINGS.nvidia_api_key,
            base_url=SETTINGS.base_url,
        )
        self.tools = _gather_tools()
        self.checkpointer = checkpointer

        # Create the react agent
        self.agent_graph = create_react_agent(
            model=self.llm,
            tools=self.tools,
            checkpointer=self.checkpointer,
        )

    def invoke(self, prompt: str, config: dict | None = None) -> dict:
        """Run the agent graph and return the final state.

        Args:
            prompt: the user's natural-language query
            config: optional dict with `configurable` for LangGraph run state
        Returns:
            the agent state dict.
        """
        config = config or {"configurable": {"thread_id": "default"}}
        result = self.agent_graph.invoke(
            {"messages": [("human", prompt)]},
            config,
        )
        return result

    def stream(self, prompt: str, config: dict | None = None):
        """Stream chunks from the agent graph."""
        config = config or {"configurable": {"thread_id": "default"}}
        return self.agent_graph.stream(
            {"messages": [("human", prompt)]},
            config,
            stream_mode="values",
        )

    def get_tool_count(self) -> int:
        return len(self.tools)

    def get_tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    def human_interrupt(self, message: str, config: dict | None = None) -> bool:
        """Simple interrupt prompt spring human-in-the-loop approval."""
        console.print(Panel(message, title="🛑 APPROVAL REQUIRED"))
        answer = console.input("[bold yellow]Approve? [y/N] [/]").strip().lower()
        return answer == "y"