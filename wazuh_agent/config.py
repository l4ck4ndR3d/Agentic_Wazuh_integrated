from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

_PROJ_ENV = Path(__file__).resolve().parent.parent / ".env"
if _PROJ_ENV.exists():
    load_dotenv(_PROJ_ENV)
load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    nvidia_api_key: str = os.getenv("API")
    model: str = os.getenv("MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
    base_url: str = os.getenv("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    temperature: float = float(os.getenv("TEMPERATURE", "0.1"))
    max_tokens: int = int(os.getenv("MAX_TOKENS", "16384"))
    reasoning_budget: int = int(os.getenv("REASONING_BUDGET", "16384"))

    
    max_iters: int = int(os.getenv("MAX_ITERS", "12"))

    
    agent_engine: str = os.getenv("AGENT_ENGINE", "langgraph")
    checkpointer_db: str = os.getenv("CHECKPOINTER_DB", "sqlite:///memory/checkpoints.db")
    sandbox_validate: bool = _bool("SANDBOX_VALIDATE", True)
    require_human_approval: bool = _bool("REQUIRE_HUMAN_APPROVAL", False)

    
    mcp_server_transport: str = os.getenv("MCP_TRANSPORT", "stdio")
    mcp_server_command: str = os.getenv("MCP_SERVER_COMMAND", "python -m wazuh_agent.mcp_server")
    mcp_server_url: str = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8765")
    use_mcp: bool = _bool("USE_MCP", True)

    # --- Wazuh Indexer (OpenSearch-compatible, port 9200) ---
    wazuh_indexer_url: str = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
    wazuh_indexer_user: str = os.getenv("WAZUH_INDEXER_USER", "admin")
    wazuh_indexer_pass: str = os.getenv("WAZUH_INDEXER_PASS", "SecretPassword")

    # --- Wazuh Manager API (REST + JWT, port 55000) ---
    wazuh_manager_url: str = os.getenv("WAZUH_MANAGER_URL", "https://127.0.0.1:55000")
    wazuh_manager_user: str = os.getenv("WAZUH_MANAGER_USER", "wazuh-wui")
    wazuh_manager_pass: str = os.getenv("WAZUH_MANAGER_PASS", "MyS3cr37P450r.*-")

    # --- Threat Intelligence ---
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY")
    threat_intel_timeout: int = int(os.getenv("THREAT_INTEL_TIMEOUT", "15"))

    # --- Docker sandbox ---
    sandbox_image: str = os.getenv("SANDBOX_IMAGE", "wazuh-agent-sandbox:latest")
    sandbox_network: str = os.getenv("SANDBOX_NETWORK", "host")
    sandbox_mem_limit: str = os.getenv("SANDBOX_MEM_LIMIT", "512m")
    sandbox_cpu_quota: int = int(os.getenv("SANDBOX_CPU_QUOTA", "50000"))
    sandbox_timeout: int = int(os.getenv("SANDBOX_TIMEOUT", "50"))
    sandbox_validate_retries: int = int(os.getenv("SANDBOX_VALIDATE_RETRIES", "3"))

    def __post_init__(self):
        if not self.nvidia_api_key:
            raise RuntimeError(
                "NVIDIA API key not set. Put `API=...` in "
                f"{_PROJ_ENV} or export NVIDIA_API_KEY."
            )

    # ---- grouped auth tuples ----
    @property
    def indexer_auth(self) -> tuple[str, str]:
        return (self.wazuh_indexer_user, self.wazuh_indexer_pass)

    @property
    def manager_auth(self) -> tuple[str, str]:
        return (self.wazuh_manager_user, self.wazuh_manager_pass)

    # ---- convenience flags ----
    @property
    def use_langgraph(self) -> bool:
        return self.agent_engine.lower() == "langgraph"

    @property
    def has_threat_intel(self) -> bool:
        return bool(self.virustotal_api_key)


SETTINGS = Settings()