from __future__ import annotations
import asyncio
import json
import logging
from typing import Annotated

from langchain_core.tools import tool

try:
    from ..config import SETTINGS
    from .. import mcp_server as _mcp
except ImportError:  # running as a script / REPL
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))
    from config import SETTINGS
    import mcp_server as _mcp

log = logging.getLogger("wazuh.tools.wazuh")


# ---- MCP client side ------------------------------------------------------

# Map internal tool names to MCP server tool names (which have _tool suffix)
_TOOL_NAME_MAP = {
    "search_alerts": "search_alerts_tool",
    "get_agents": "get_agents_tool",
    "get_agent": "get_agent_tool",
    "get_vulnerabilities": "get_vulnerabilities_tool",
    "get_inventory": "get_inventory_tool",
    "get_manager_status": "get_manager_status_tool",
    "get_indexer_health": "get_indexer_health_tool",
}


def _mcp_tool_name(internal_name: str) -> str:
    """Convert internal tool name to MCP server tool name."""
    return _TOOL_NAME_MAP.get(internal_name, internal_name)


async def _mcp_call_stdio(tool_name: str, **kw) -> str:
    """Spawn the MCP server as a subprocess and call one tool.

    For a real deployment you'd keep the session open; here we do a
    one-shot for simplicity.  Returns the json-rpc string from the server.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from pathlib import Path

    # Project root (parent of wazuh_agent/) so `python -m wazuh_agent.mcp_server` works
    project_root = Path(__file__).resolve().parent.parent.parent
    params = StdioServerParameters(
        command="python", 
        args=["-m", "wazuh_agent.mcp_server"],
        cwd=str(project_root)
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, kw)
            # result.content is a list of TextContent; join their .text
            return "".join(c.text for c in result.content if getattr(c, "text", None))


def _direct_call(tool_name: str, **kw) -> str:
    """Call the underlying function in mcp_server._raw_tools directly.

    Returns the same json-rpc envelope string that the MCP server would
    have returned over the wire.
    """
    fn = _mcp._raw_tools.get(tool_name)
    if fn is None:
        return json.dumps({"jsonrpc": "2.0", "id": -1,
                           "error": {"code": -32601,
                                     "message": f"unknown tool {tool_name!r}"}})
    return fn(**kw)


def _call(tool_name: str, **kw) -> str:
    """Dispatch to MCP transport or direct-call, per SETTINGS.use_mcp."""
    if not SETTINGS.use_mcp:
        return _direct_call(tool_name, **kw)
    # Map internal name to MCP server tool name (e.g., search_alerts -> search_alerts_tool)
    mcp_tool_name = _mcp_tool_name(tool_name)
    if SETTINGS.mcp_server_transport == "stdio":
        return asyncio.run(_mcp_call_stdio(mcp_tool_name, **kw))
    # HTTP transport not implemented in this boilerplate; fall back to direct
    return _direct_call(tool_name, **kw)


# ---- LangChain @tools -----------------------------------------------------

@tool
def wazuh_search_alerts(
    query: Annotated[dict | None, "OpenSearch DSL query dict, or null for all"] = None,
    index: Annotated[str, "Index pattern e.g. 'wazuh-alerts-*'"] = "wazuh-alerts-*",
    size: Annotated[int, "Max docs (cap 200)"] = 20,
    aggs: Annotated[dict | None, "Optional OpenSearch aggs dict"] = None,
    time_range: Annotated[str | None, "e.g. 'now-24h'"] = None,
) -> str:
    """Search Wazuh alerts.  Returns a JSON-RPC 2.0 envelope **as a string**.

    The LLM is expected to write a sandbox snippet that json.loads() this
    response and extracts the fields it needs -- **do not pre-parse it
    in the agent**.  Use the sandbox-first validation flow.
    """
    return _call("search_alerts", query=query, index=index, size=size,
                 aggs=aggs, time_range=time_range)


@tool
def wazuh_get_agents(
    status: Annotated[str | None, "active|disconnected|never_connected|pending"] = None,
    limit: Annotated[int, "Max agents (cap 30000)"] = 500,
) -> str:
    """List Wazuh agents.  Returns JSON-RPC envelope string."""
    return _call("get_agents", status=status, limit=limit)


@tool
def wazuh_get_agent(
    agent_id: Annotated[str, "Wazuh agent id, e.g. '001'"],
) -> str:
    """Detail for a single agent.  Returns JSON-RPC envelope string."""
    return _call("get_agent", agent_id=agent_id)


@tool
def wazuh_get_vulnerabilities(
    agent_id: Annotated[str, "Filter by agent id; '' for all"] = "",
    severity: Annotated[str | None, "low|medium|high|critical"] = None,
    size: Annotated[int, "Max docs (cap 200)"] = 50,
) -> str:
    """Search vulnerability-state index.  Returns JSON-RPC envelope string."""
    return _call("get_vulnerabilities", agent_id=agent_id,
                 severity=severity, size=size)


@tool
def wazuh_get_inventory(
    agent_id: Annotated[str, "Agent id (empty = all)"] = "",
    kind: Annotated[str, "packages|ports|processes|hardware|networks|users|system"] = "packages",
) -> str:
    """Pull a syscollector inventory doc-set.  Returns JSON-RPC envelope string."""
    return _call("get_inventory", agent_id=agent_id, kind=kind)


@tool
def wazuh_get_manager_status() -> str:
    """Wazuh manager daemon status.  Returns JSON-RPC envelope string."""
    return _call("get_manager_status")


@tool
def wazuh_get_indexer_health() -> str:
    """OpenSearch cluster health.  Returns JSON-RPC envelope string."""
    return _call("get_indexer_health")


def all_wazuh_tools():
    return [wazuh_search_alerts, wazuh_get_agents, wazuh_get_agent,
            wazuh_get_vulnerabilities, wazuh_get_inventory,
            wazuh_get_manager_status, wazuh_get_indexer_health]
