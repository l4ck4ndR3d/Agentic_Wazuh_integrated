"""Unit / integration tests for the upgraded Wazuh Agent (MCP + LangChain).

Run with:  source ~/Desktop/pyenv/bin/activate &&  pytest -v tests/

If docker is not available, tests that need the sandbox are skipped.
All MCP tests (json-rpc parsing) are mock-based and always run.
"""
from __future__ import annotations
import json
import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest  # type: ignore

os.environ["API"] = "mock_test_key"


class TestMCPJSONRPC:
    """Verify that the MCP server / tools emit properly-formatted json-rpc."""

    def test_search_alerts_rpc_shape(self):
        """Even with no Wazuh reachable, the wrapper returns a json-rpc string."""
        from wazuh_agent.tools.wazuh_tools import wazuh_search_alerts
        raw = wazuh_search_alerts.invoke({
            "query": {"match_all": {}},
            "index": "wazuh-alerts-*",
            "size": 5,
        })
        assert isinstance(raw, str), f"Expected str, got {type(raw)}"
        env = json.loads(raw)
        assert "jsonrpc" in env
        assert env["jsonrpc"] == "2.0"

    def test_error_envelope(self):
        """When the indexer returns a non-200 the error envelope is correct."""
        import requests
        from wazuh_agent.config import Settings
        s = Settings()
        from wazuh_agent.mcp_server import search_alerts, _wrap

        with patch.object(requests, "request") as mock_req:
            mock_req.return_value.status_code = 503
            mock_req.return_value.text = "Indexer down"
            mock_req.return_value.ok = False
            raw = search_alerts(query={"match_all": {}})
            env = json.loads(raw)
            assert "error" in env
            assert env["error"]["code"] == 503

    def test_direct_call_returns_rpc(self):
        """Direct-call tools return identically structured rpc strings"""
        from wazuh_agent.mcp_server import get_agent
        raw = get_agent(agent_id="001")
        env = json.loads(raw)
        assert "jsonrpc" in env
        assert "id" in env

    def test_threat_intel_missing_key(self):
        """Test threat intel tools return errors when keys not set."""
        from wazuh_agent.tools.threat_intel_tools import virustotal_lookup_ip
        result = virustotal_lookup_ip.invoke({"ip": "8.8.8.8"})
        parsed = json.loads(result)
        assert "error" in parsed or "VirusTotal API key not configured" in result


class TestBed:
    """Simple QA for bedrock components -- config, memory, agent init."""

    def test_config_defaults(self):
        from wazuh_agent.config import Settings
        cfg = Settings()
        assert cfg.model.startswith("nvidia/")
        assert cfg.sandbox_validate is True

    def test_memory_persistence(self):
        from wazuh_agent.memory import Memory
        m = Memory(session_id="test_q")
        m.reset()
        m.add("user", "hello")
        m.add("assistant", "world")
        assert len(m) == 2
        msgs = m.openai_messages(system_prompt="test")
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        m.reset()
        assert len(m) == 0

    def test_legacy_agent_init(self):
        from wazuh_agent.agent import Agent
        from wazuh_agent.memory import Memory
        ag = Agent(Memory(session_id="test_init"))
        assert ag is not None
        assert hasattr(ag, "ask")

    def test_parse_assistant_chart(self):
        import re
        from wazuh_agent.agent import parse_assistant
        # Final answer
        result = parse_assistant("Here is my <final_answer>Got 5 alerts</final_answer>. Done.")
        assert result["kind"] == "final"
        assert result["answer"] == "Got 5 alerts"
        # Code block
        code_block = "```python\nprint('hello')\n```"
        result2 = parse_assistant(code_block)
        assert result2["kind"] == "code"
        # Noop
        result3 = parse_assistant("just saying hello")
        assert result3["kind"] == "noop"

    def test_sandbox_result_line_extraction(self):
        from wazuh_agent.sandbox import sandbox
        val = sandbox._extract_result_line("hello\n__RESULT__{\"key\":\"val\"}")
        assert val == {"key": "val"}
        val_none = sandbox._extract_result_line("no result here")
        assert val_none is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])