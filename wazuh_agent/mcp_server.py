"""MCP Server exposing Wazuh Indexer + Manager as MCP tools.

This is the LLM-facing "data plane" for Wazuh.  It speaks the Model Context
Protocol (JSON-RPC 2.0 over stdio or HTTP) so any MCP client -- including our
own LangChain tools -- can call it without embedding credentials or API docs
inside the prompt.

Key design choice:
    The MCP tools return the raw **JSON-RPC response** (id, jsonrpc, result,
    error) **as a string**, NOT a pre-parsed python dict.  The LLM then writes
    a short python snippet in the Docker sandbox to parse / aggregate that
    JSON-RPC payload.  This:

      * keeps the MCP server dumb (no business logic, thin Wazuh proxies)
      * pushes the xpath / aggregation / filtering into the sandbox (safe,
        resource-limited, observable)
      * lets the LLM flex its "write a parser" muscle instead of us committing
        to a fixed schema

Running it standalone (debug):

    source ~/Desktop/pyenv/bin/activate
    cd "/home/cyborg/Desktop/MCP-LLM-Blueteam/MCP & Agentic AI"
    python -m wazuh_agent.mcp_server
"""
from __future__ import annotations
import asyncio
import json
import logging
import base64
from typing import Any

import requests

try:
    from .config import SETTINGS
except ImportError:  # running as script
    from config import SETTINGS

log = logging.getLogger("wazuh.mcp")
requests.packages.urllib3.disable_warnings()


# ---- helpers ---------------------------------------------------------------

def _idx_request(method: str, path: str, body: dict | None = None,
                 timeout: int = 15) -> tuple[int, str]:
    """Hit the Wazuh Indexer (OpenSearch).  Returns (status, text)."""
    url = f"{SETTINGS.wazuh_indexer_url}{path}"
    try:
        r = requests.request(method, url,
                             auth=SETTINGS.indexer_auth, verify=False,
                             headers={"Content-Type": "application/json"},
                             data=json.dumps(body) if body else None,
                             timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

# gets JWT from Mnager API 
def _manager_token() -> str:
    """Login to the Manager API and return a JWT.  Caller caches it."""
    user, pw = SETTINGS.manager_auth
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    r = requests.post(
        f"{SETTINGS.wazuh_manager_url}/security/user/authenticate?raw=true",
        headers={"Authorization": f"Basic {tok}"}, verify=False, timeout=10,
    )
    r.raise_for_status()
    return r.text.strip()

_MGR_TOKEN: str | None = None

# queries manager API with cached JWT
def _mgr_request(method: str, path: str, params: dict | None = None,
                 timeout: int = 15) -> tuple[int, str]:
    """Hit the Wazuh Manager REST API.  Tokens are reused."""
    global _MGR_TOKEN
    if _MGR_TOKEN is None:
        _MGR_TOKEN = _manager_token()
    url = f"{SETTINGS.wazuh_manager_url}{path}"
    params = (params or {}).copy()
    params.setdefault("pretty", "true")
    try:
        r = requests.request(method, url,
                              headers={"Authorization": f"Bearer {_MGR_TOKEN}"},
                              params=params, verify=False, timeout=timeout)
        if r.status_code == 401:
            # token expired; refresh and retry once
            _MGR_TOKEN = _manager_token()
            r = requests.request(method, url,
                                  headers={"Authorization": f"Bearer {_MGR_TOKEN}"},
                                  params=params, verify=False, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def _wrap(id_: Any, result: Any = None, error: Any = None) -> str:
    """Wrap a payload into a JSON-RPC 2.0 envelope (returned as text)."""
    env = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        env["error"] = error
    else:
        env["result"] = result
    return json.dumps(env, default=str)


# ---- MCP server ------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None  # mcp package not installed -- mocking helper below

# When the real `mcp` package is unavailable, we still expose the underlying
# functions for direct import and for tests.  Tests can call e.g.
# `mcp_server.search_alerts(...)` directly and get the json-rpc string back.
_raw_tools: dict[str, Any] = {}


def _register(d):
    """Decorator that records a function so the __main__ block can build
    either a real FastMCP server or a direct-call test harness from it."""
    def deco(fn):
        d[fn.__name__] = fn
        return fn
    return deco


@_register(_raw_tools)
def search_alerts(
    id: Any = 1,
    query: dict | None = None,
    index: str = "wazuh-alerts-*",
    size: int = 20,
    aggs: dict | None = None,
    time_range: str | None = None,
) -> str:
    """Search Wazuh alerts in the Indexer.

    Args:
        query:  OpenSearch DSL query dict.  Defaults to match_all.
        index:  index pattern, e.g. 'wazuh-alerts-*'.
        size:   number of documents to return (cap 200).
        aggs:   optional OpenSearch aggs dict.
        time_range: shortcut for `{"range":{"@timestamp":{"gte":<this>}}}`.

    Returns:
        JSON-RPC 2.0 envelope (string).  On success, `result` holds
        the raw OpenSearch response (hits, aggregations, total).
    """
    size = max(0, min(int(size), 200))
    q = query or {"match_all": {}}
    if time_range:
        q = {"bool": {"must": [q], "filter": [
            {"range": {"@timestamp": {"gte": time_range}}}]}}
    body = {"query": q, "size": size, "sort": [{"@timestamp": "desc"}]}
    if aggs:
        body["size"] = 0
        body["aggs"] = aggs
    status, txt = _idx_request("POST", f"/{index}/_search", body)
    if status != 200:
        return _wrap(id, error={"code": status, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_agents(id: Any = 2, status: str | None = None,
               limit: int = 500) -> str:
    """List Wazuh agents via the Manager API."""
    params = {"select": "id,name,status,ip,os.name,last_keep_alive"}
    if status:
        params["q"] = f"status={status}"
    params["limit"] = str(max(1, min(int(limit), 30000)))
    st, txt = _mgr_request("GET", "/agents", params)
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_agent(id: Any = 3, agent_id: str = "") -> str:
    """Get detail for a single Wazuh agent by id."""
    if not agent_id:
        return _wrap(id, error={"code": -1, "message": "agent_id required"})
    st, txt = _mgr_request("GET", f"/agents/{agent_id}")
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_vulnerabilities(id: Any = 4, agent_id: str = "",
                        severity: str | None = None,
                        index: str = "wazuh-states-vulnerabilities-*",
                        size: int = 50) -> str:
    """Search Wazuh vulnerability-state index.

    Args:
        agent_id:   filter by agent.id (empty -> all).
        severity:   Low/Medium/High/Critical.
        index:      OpenSearch index pattern.
        size:       max docs returned (cap 200).
    """
    must = []
    if agent_id:
        must.append({"term": {"agent.id": agent_id}})
    if severity:
        must.append({"term": {"vulnerability.severity": severity.lower()}})
    q = {"bool": {"must": must}} if must else {"match_all": {}}
    body = {"query": q, "size": max(0, min(int(size), 200))}
    st, txt = _idx_request("POST", f"/{index}/_search", body)
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_inventory(id: Any = 5, agent_id: str = "",
                  kind: str = "packages") -> str:
    """Pull a syscollector inventory doc-set from the Indexer.

    kind: 'packages'|'ports'|'processes'|'hardware'|'networks'|'users'|'system'.
    """
    pat_map = {
        "packages":  "wazuh-states-inventory-packages-*",
        "ports":     "wazuh-states-inventory-ports-*",
        "processes": "wazuh-states-inventory-processes-*",
        "hardware":  "wazuh-states-inventory-hardware-*",
        "networks":  "wazuh-states-inventory-networks-*",
        "users":     "wazuh-states-inventory-users-*",
        "system":    "wazuh-states-inventory-system-*",
    }
    pattern = pat_map.get(kind, kind)
    must = []
    if agent_id:
        must.append({"term": {"agent.id": agent_id}})
    body = {"query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": 100, "sort": [{"@timestamp": "desc"}]}
    st, txt = _idx_request("POST", f"/{pattern}/_search", body)
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_manager_status(id: Any = 6) -> str:
    """Manager daemon-status JSON via Manager API."""
    st, txt = _mgr_request("GET", "/manager/status")
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


@_register(_raw_tools)
def get_indexer_health(id: Any = 7) -> str:
    """OpenSearch cluster health via Indexer API."""
    st, txt = _idx_request("GET", "/_cluster/health")
    if st != 200:
        return _wrap(id, error={"code": st, "message": txt})
    return _wrap(id, result=json.loads(txt))


# ---- build the FastMCP server when `mcp` is installed ----------------------

def build_server():
    """Construct a FastMCP server with all the Wazuh tools registered.

    Called from __main__.  Raises a helpful error if `mcp` not installed.
    """
    if FastMCP is None:
        raise RuntimeError(
            "The `mcp` package is not installed. Run "
            "`pip install -r requirements.txt` and retry."
        )
    server = FastMCP("wazuh-mcp")

    @server.tool()
    def search_alerts_tool(query: dict | None = None, index: str = "wazuh-alerts-*",
                            size: int = 20, aggs: dict | None = None,
                            time_range: str | None = None) -> str:
        return search_alerts(1, query, index, size, aggs, time_range)

    @server.tool()
    def get_agents_tool(status: str | None = None, limit: int = 500) -> str:
        return get_agents(2, status, limit)

    @server.tool()
    def get_agent_tool(agent_id: str) -> str:
        return get_agent(3, agent_id)

    @server.tool()
    def get_vulnerabilities_tool(agent_id: str = "", severity: str | None = None,
                                  size: int = 50) -> str:
        return get_vulnerabilities(4, agent_id, severity, size=size)

    @server.tool()
    def get_inventory_tool(agent_id: str = "", kind: str = "packages") -> str:
        return get_inventory(5, agent_id, kind)

    @server.tool()
    def get_manager_status_tool() -> str:
        return get_manager_status(6)

    @server.tool()
    def get_indexer_health_tool() -> str:
        return get_indexer_health(7)

    return server


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")
    server = build_server()
    server.run(transport=SETTINGS.mcp_server_transport)


if __name__ == "__main__":
    main()
