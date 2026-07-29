from __future__ import annotations
import json
import logging
from typing import Annotated, Optional

import requests

from langchain_core.tools import tool

try:
    from ..config import SETTINGS
except ImportError:  # running as a script / REPL
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))
    from config import SETTINGS

log = logging.getLogger("wazuh.tools.threat_intel")
requests.packages.urllib3.disable_warnings()


# ---- VirusTotal ------------------------------------------------------------

@tool
def virustotal_lookup_ip(ip: Annotated[str, "IPv4 or IPv6 to enrich"]) -> str:
    """Return VirusTotal's report for an IP address.

    Output: a JSON string containing `last_analysis_stats`, `reputation`,
    `asn_owner`, `country`.  Caller (the sandbox) parses it.
    """
    if not SETTINGS.virustotal_api_key:
        return json.dumps({"error": "VirusTotal API key not configured"})
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url,
                         headers={"x-apikey": SETTINGS.virustotal_api_key},
                         timeout=SETTINGS.threat_intel_timeout)
        if r.status_code == 200:
            return json.dumps(r.json())
        return json.dumps({"error": f"HTTP {r.status_code}", "body": r.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def virustotal_lookup_hash(
    file_hash: Annotated[str, "SHA256 / SHA1 / MD5 hash to look up"]
) -> str:
    """Return VirusTotal's report for a file hash."""
    if not SETTINGS.virustotal_api_key:
        return json.dumps({"error": "VirusTotal API key not configured"})
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        r = requests.get(url,
                         headers={"x-apikey": SETTINGS.virustotal_api_key},
                         timeout=SETTINGS.threat_intel_timeout)
        if r.status_code == 200:
            return json.dumps(r.json())
        return json.dumps({"error": f"HTTP {r.status_code}", "body": r.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


def all_threat_intel_tools():
    """Return the list of threat-intel @tool objects -- empty if no keys."""
    out = []
    if SETTINGS.virustotal_api_key:
        out += [virustotal_lookup_ip, virustotal_lookup_hash]
    return out
