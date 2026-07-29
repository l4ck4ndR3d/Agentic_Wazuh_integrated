# Wazuh Agent Upgrade — LangChain + MCP + Sandbox-First Validation

---

## ARCHITECTURE DIAGRAM

```
                          ┌─────────────────┐
                          │   User / REPL   │
                          │  (main.py)      │
                          └──────┬──────────┘
                                 │ query
                                 ▼
               ┌─────────────────────────────────────┐
               │         Agent Engine (agent.py)     │
               │  ┌───────────┐  OR  ┌────────────┐  │
               │  │ Legacy    │      │ LangGraph  │  │
               │  │ ReAct Loop│      │ React Agent│  │
               │  └─────┬─────┘      └──────┬─────┘  │
               └────────┼───────────────────┼────────┘
                        │                   │
                        │   ┌───────────────┼──────────────┐
                        │   │  MCP Client  (tools/wazuh_   │
                        ▼   ▼  tools.py)                   │
              ┌─────────────────────────────┐   ┌──────────┴──────────┐
              │   MCP Server (mcp_server.py)│   │  LangChain @tools   │
              │   ┌───────────────────────┐ │   │  ├─ threat_intel    │
              │   │ search_alerts         │ │   │  ├─ notifications   │
              │   │ get_agents            │ │   │  ├─ monitoring      │
              │   │ get_vulnerabilities   │ │   │  └─ wazuh_data      │
              │   │ get_inventory         │ │   └─────────────────────┘
              │   │ get_manager_status    │ │
              │   │ get_indexer_health    │ │
              │   └───────┬───────────────┘ │
              │           │ json-rpc return │
              │           ▼                 │
              │   ┌───────────────────────┐ │
              │   │  Sandbox: validate    │◀┘
              │   │  parser code          │ |
              │   │  (sandbox.py)         │ |
              │   └───────────────────────┘ |
              └─────────────┬───────────────┘
                            │
                            ▼
                    Wazuh APIs (9200 / 55000)
```

## MCP JSON-RPC Flow

```
1. LangGraph agent invokes tool: wazuh_search_alerts(query={...})
2. tools/wazuh_tools.py dispatches to mcp_server.py _raw_tools
3. mcp_server.py queries Wazuh Indexer, wraps response in:
   {"jsonrpc":"2.0","id":1,"result":{"hits":{"total":...}}}
4. Tool returns RAW STRING (not parsed dict) to agent
5. Sandbox receives payload + parser code → parse → validate → promote
6. Parsed dict enters real-time environment
```

## SANDBOX-FIRST VALIDATION

```
LLM generates parser code → docker run script.py with PAYLOAD injected
   │
   ├── set_result({"hits": [...], "summary": ...}) called
   │   sandbox._extract_result_line() finds __RESULT__{...}
   │   sandbox._validate_schema() checks against expected schema
   │   ✓ SUCCESS → promote to real-time
   │
   └── No __RESULT__ line OR schema mismatch → RETRY (up to 3x)
       └── After retries, return raw response with SANDBOX_REJECTED marker
```

## KEY FILES ADDED / MODIFIED

### NEW:
* **mcp_server.py** — MCP FastMCP server + _raw_tools for direct call
* **langchain_agent.py** — LangGraph create_react_agent with checkpointer
* **tools/__init__.py** — empty module
* **tools/threat_intel_tools.py** — VirusTotal
* **tools/notification_tools.py** — Slack, email, PagerDuty
* **tools/monitoring_tools.py** — agent health, alert rate, errors
* **tools/wazuh_tools.py** — bridge to MCP client
* **tests/test_upgrade.py** — unit tests for json-rpc, config, memory

### MODIFIED:
* **config.py** — add new env vars for LangChain, MCP, intel, notif
* **sandbox.py** — add execute_and_validate(), PAYLOAD injection
* **sandbox/Dockerfile** — add pandas, jsonschema, pyyaml
* **agent.py** — keep legacy loop + add ask_langgraph() wrapper
* **main.py** — add --engine, --validate, --monitor flags, tool listing
* **requirements.txt** — add langchain, mcp, pydantic, pandas, slack-sdk

## USAGE COMMANDS

```bash
source ~/Desktop/pyenv/bin/activate
cd "/home/cyborg/Desktop/MCP-LLM-Blueteam/MCP & Agentic AI"

# Default (LangGraph + sandbox-first)
python -m wazuh_agent.main

# Legacy engine
python -m wazuh_agent.main --engine custom

# One-shot query through LangGraph
python -m wazuh_agent.main --once "Show high alerts last 24h"

# Monitoring loop (auto-sentry)
python -m wazuh_agent.main --monitor --engine langgraph

# REPL commands:
#   /tools          → list all LangChain tools
#   /validate       → toggle sandbox validation on/off
#   /monitor        → run one monitoring probe
#   /status         → show engine + tool summary
```

## ENVIRONMENT VARIABLES (new)

```bash
# Engine selection
AGENT_ENGINE=langgraph   # or 'custom' for legacy

# Sandbox validation
SANDBOX_VALIDATE=1         # 0=off, 1=on (default on)

# MCP
USE_MCP=1                 # 0=direct API calls, 1=MCP json-rpc
MCP_TRANSPORT=stdio       # 'stdio' (subprocess) or 'http'

# Threat intelligence (optional)
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
SHODAN_API_KEY=...

# Notification channels (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
SLACK_TOKEN=xoxb-...
SLACK_CHANNEL=#soc-alerts
SMTP_HOST=mail.soc.local
SMTP_USER=soc
SMTP_PASS=pass
SMTP_TO=soc@local
PAGERDUTY_ROUTING_KEY=...
```

## WHY LLM PARSES JSON-RPC IN THE SANDBOX (not in Python directly)

1. **Flexibility** — Wazuh schemas change; LLM adapts parser
2. **Safety** — All code executes in Docker (non-root, no-network-by-default)
3. **Visibility** — Full stdout/stderr captured → debug via LLM text if parser fails
4. **MCP contract** — MCP returns json-rpc 2.0 string, LLM pulls result/error
5. **No tight coupling** — MCP server stays "dumb" (thin Wazuh proxies)