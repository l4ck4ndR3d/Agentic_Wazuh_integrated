# Wazuh API Reference for Security Analyst Agents

Target deployment: Indexer `https://127.0.0.1:9200` (HTTP Basic `admin:SecretPassword`),
Manager `https://127.0.0.1:55000` (JWT via `POST /security/user/authenticate`).

---

## 1. INDEXER API (OpenSearch-compatible, port 9200)

### 1.1 Authentication — HTTP Basic
Every request carries credentials. No login endpoint.
```bash
curl -k -u admin:SecretPassword https://127.0.0.1:9200/_cluster/health?pretty
```

### 1.2 Search example (DSL body)
```bash
curl -k -u admin:SecretPassword -X POST \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?pretty" \
  -H "Content-Type: application/json" -d '{
  "size": 5,
  "query": {"bool": {"filter": [
    {"range": {"@timestamp": {"gte": "now-24h"}}},
    {"range": {"rule.level": {"gte": 10}}}
  ]}},
  "sort": [{"@timestamp": "desc"}]
}'
```

### 1.3 Recommended Indexer endpoints
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET  | `/_cluster/health` | Cluster status |
| GET  | `/_cat/indices?v` | List indices |
| POST | `/<index>/_search` | Search with DSL body |
| GET  | `/<index>/_search?q=...` | URI search |
| GET  | `/<index>/_count` | Document count |
| POST| `/_search` | Cross-index search |
| GET  | `/<index>/_mapping` | Field mappings |

### 1.4 Index patterns
| Pattern | Contents |
|---------|----------|
| `wazuh-alerts-*` | SIEM alerts (primary feed) |
| `wazuh-archives-*` | Raw events |
| `wazuh-monitoring-*` | Agent connection status |
| `wazuh-statistics-*` | Server perf metrics |
| `wazuh-states-vulnerabilities-*` | Vulnerability state per asset |
| `wazuh-states-inventory-hardware-*` | CPU/RAM |
| `wazuh-states-inventory-ports-*` | Open network ports |
| `wazuh-states-inventory-processes-*` | Running processes |
| `wazuh-states-inventory-packages-*` | Installed packages |
| `wazuh-states-inventory-networks-*` | IPs per interface |
| `wazuh-states-inventory-users-*` | User accounts |
| `wazuh-states-inventory-system-*` | OS / hostname |

### 1.5 Query DSL cheat-sheet
```json
{"query":{"match":{"rule.description":"SSH brute-force"}}}
{"query":{"range":{"@timestamp":{"gte":"now-1d","lt":"now"}}}}
{"query":{"range":{"rule.level":{"gte":10}}}}
{"query":{"terms":{"agent.name":["web01","web02"]}}}
{"query":{"bool":{"must":[{"match":{"data.srcip":"192.168.1.10"}}],
                   "filter":[{"range":{"rule.level":{"gte":7}}}]}}}
{"size":0,"aggs":{"top_rules":{"terms":{"field":"rule.description","size":10}}}}
{"size":0,"aggs":{"alerts_over_time":{"date_histogram":{"field":"@timestamp","calendar_interval":"1d"}}}}
```

### 1.6 Common alert fields (`wazuh-alerts-*`)
| Field | Notes |
|-------|-------|
| `@timestamp` | Event time (filter on this) |
| `rule.level` | 0-15 (>=7 informative, >=12 high) |
| `rule.description` | Human-readable rule text |
| `rule.id` | Numeric rule id |
| `rule.groups` | Rule groups array |
| `rule.mitre.id` | MITRE ATT&CK technique IDs |
| `data.srcip`, `data.dstip` | Source/Dest IP |
| `data.srcuser`, `data.dstuser` | Users |
| `agent.id`, `agent.name`, `agent.ip` | Agent metadata |
| `manager.name`, `manager.host` | Manager metadata |
| `decoder.name`, `location`, `full_log` | Source info |

### 1.7 Common vulnerability fields (`wazuh-states-vulnerabilities-*`)
| Field | Notes |
|-------|-------|
| `vulnerability.id` | CVE id |
| `vulnerability.severity` | Low/Medium/High/Critical |
| `vulnerability.status` | Active/Solved/Pending |
| `vulnerability.score` | CVSS |
| `package.name`, `package.version`, `package.vendor` | Affected package |
| `agent.id`, `agent.name` | Affected asset |
| `title`, `@timestamp` | Title / detection time |

### 1.8 Common inventory fields
| Pattern | Key fields |
|---------|-----------|
| `-hardware-*` | `host.cpu.cores`, `host.memory.total` |
| `-packages-*` | `package.name`, `package.version`, `package.vendor` |
| `-ports-*` | `port.local_port`, `port.remote_port`, `port.state`, `port.protocol` |
| `-processes-*` | `process.pid`, `process.name`, `process.cmd`, `process.user.name` |
| `-networks-*` | `netinfo.interface`, `netinfo.ip`, `netinfo.netmask` |
| `-users-*` | `user.name`, `user.uid`, `user.groups` |
| `-system-*` | `host.hostname`, `host.os.name`, `host.os.version` |

---

## 2. MANAGER API (REST + JWT, port 55000)

### 2.1 Authentication
```bash
TOKEN=$(curl -s -k -u admin:SecretPassword -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true")
curl -k -X GET "https://127.0.0.1:55000/agents?pretty=true&limit=5" \
  -H "Authorization: Bearer $TOKEN"
```

### 2.2 Recommended Manager endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | API version/hostname |
| GET | `/agents?limit=500&select=id,name,status,os.name` | List agents |
| GET | `/agents/{id}` | Agent detail |
| GET | `/agents/summary/status` | Active/disconnected counts |
| GET | `/manager/info` | Manager version |
| GET | `/manager/status` | Daemon status |
| GET | `/manager/logs?type_log=error&limit=100` | Manager logs |
| GET | `/rules` | List rules |
| GET | `/decoders` | List decoders |
| GET | `/syscollector/{agent_id}/hardware` | Hardware inv |
| GET | `/syscollector/{agent_id}/os` | OS info |
| GET | `/syscollector/{agent_id}/packages` | Packages |
| GET | `/syscollector/{agent_id}/ports` | Open ports |
| GET | `/syscollector/{agent_id}/processes` | Processes |
| GET | `/vulnerability/{agent_id}` | Vulnerabilities |
| GET | `/sca/{agent_id}` | Config assessment |
| GET | `/cluster/status` | Cluster status |
| GET | `/cluster/healthcheck` | Cluster health |

### 2.3 Response shape
```json
{"data":{"affected_items":[...],"total_affected_items":5,
         "failed_items":[],"total_failed_items":0},
 "message":"Operation completed successfully","error":0}
```
`error` 0=success, 1=fail, 2=partial. HTTP 401 = bad/missing JWT.

---

## 3. WQL (Wazuh Query Language) — Manager API `q=` param

Operators: `=` `!=` `<` `>` `~` (LIKE) `()` grouping
Separators: `,` (OR) and `;` (AND, URL-encode as `%3B`)

```bash
# Disconnected agents
curl -G -k --data-urlencode "q=status=disconnected" \
  "https://127.0.0.1:55000/agents?pretty=true&select=id,name,last_keep_alive" \
  -H "Authorization: Bearer $TOKEN"

# Ubuntu agents v>18
curl -G -k --data-urlencode "q=os.name=ubuntu;os.version>18" \
  "https://127.0.0.1:55000/agents?limit=500" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 4. Python skeleton (used inside the sandbox)
```python
import requests, json
requests.packages.urllib3.disable_warnings()

INDEXER = "https://127.0.0.1:9200"
MANAGER = "https://127.0.0.1:55000"
IDXR = ("admin", "SecretPassword")

def idx_search(pattern, body):
    r = requests.post(f"{INDEXER}/{pattern}/_search",
        headers={"Content-Type":"application/json"},
        auth=IDXR, verify=False, data=json.dumps(body))
    r.raise_for_status()
    return r.json()

def mgr_login(user="wazuh-wui", pw="MyS3cr37P450r.*-"):
    import base64
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    r = requests.post(f"{MANAGER}/security/user/authenticate?raw=true",
        headers={"Authorization": f"Basic {tok}"}, verify=False)
    r.raise_for_status()
    return r.text.strip()

def mgr_get(endpoint, token, **params):
    r = requests.get(f"{MANAGER}{endpoint}",
        headers={"Authorization": f"Bearer {token}"},
        params={"pretty":"true", **params}, verify=False)
    r.raise_for_status()
    return r.json()
```

## 5. Which API to use?
| Need | Use |
|------|-----|
| Historical alerts / SIEM search | Indexer `_search` |
| Current vulnerability state | Indexer `wazuh-states-vulnerabilities-*` |
| Agent list / status / inventory live | Manager `/agents`, `/syscollector/*` |
| Manager logs / daemon status | Manager `/manager/*`, `/cluster/*` |
| Build dashboards/aggs | Indexer `aggs` in `_search` |
