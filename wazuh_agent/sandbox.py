"""Docker-based sandbox for executing Python code the LLM writes.

Security model:
- Image: `wazuh-agent-sandbox:latest` (built from ./sandbox/Dockerfile).
- Network: `host` by default (configurable to `none`).
- Resource limits: 512 MB RAM, 0.5 CPU, 30-50s timeout.
- Runs as non-root user `sandbox` inside an isolated workdir.

Two execution modes:
1. `run(code)`                    -- fire-and-forget sandbox run (legacy).
2. `execute_and_validate(code, schema, payload)`  -- the sandbox-first
   validation gate:

       LLM writes a parser snippet:
           parsed_dict = sandbox.execute_and_validate(
               code=parser_code,            # parses `PAYLOAD`
               schema=expected_schema,      # json-schema of expected output
               payload=raw_mcp_jsonrpc,     # injected into the script
           )
       if parsed_dict is None:
           # sandbox rejected the output; ask LLM to fix the parser
       else:
           # use `parsed_dict` in the real-time environment

   The validating run wraps the LLM's parser code in a small harness that
   makes the python script emit a single JSON line on stdout, then checks
   that line against the supplied jsonschema.
"""
from __future__ import annotations
import io
import os
import json
import tarfile
import tempfile
import time
import textwrap
from pathlib import Path
from typing import Any, Callable

import docker
from docker.errors import ImageNotFound, APIError

try:
    from .config import SETTINGS
except ImportError:
    from config import SETTINGS


PRELUDE = textwrap.dedent('''
    # === orchestrator injected prelude ===
    import json as _json
    import sys
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    try:
        import pandas as _pd  # noqa: F401  (sandbox may need it)
    except Exception:
        _pd = None
    try:
        import yaml as _yaml   # noqa: F401
    except Exception:
        _yaml = None
    try:
        import jsonschema     # used by validation harness, do not shadow
    except Exception:
        jsonschema = None

    # Pre-fetched Wazuh context (if any). Populated by the orchestrator
    # before running this script so the sandbox can stay offline.
    CONTEXT = _CONTEXT_VALUE_  # noqa: F821  (replaced below)
    # Optionally injected raw payload (e.g. a JSON-RPC envelope string).
    PAYLOAD = _PAYLOAD_VALUE_   # noqa: F821  (replaced below, may be "")

    INDEXER = "https://127.0.0.1:9200"
    MANAGER = "https://127.0.0.1:55000"
    IDXR_USER, IDXR_PASS = "admin", "SecretPassword"
    MGR_USER, MGR_PASS = "wazuh-wui", "MyS3cr37P450r.*-"

    def print_json(obj, **kw):
        """Pretty-print a JSON-serialisable object."""
        print(_json.dumps(obj, indent=2, default=str, **kw))

    def emit_result(obj):
        """Validation harness: emit one JSON line on stdout as the final
        result.  Only the LAST line that starts with the magic prefix
        is captured by the validator."""
        line = _json.dumps(obj, default=str)
        print("__RESULT__" + line)

    def search_alerts(query=None, size=20, index="wazuh-alerts-*"):
        """helper: search the Wazuh indexer. Network must be enabled."""
        body = {"size": size, "query": query or {"match_all": {}},
                "sort": [{"@timestamp": "desc"}]}
        r = requests.post(f"{INDEXER}/{index}/_search",
            headers={"Content-Type":"application/json"},
            auth=(IDXR_USER, IDXR_PASS), verify=False,
            data=_json.dumps(body), timeout=15)
        r.raise_for_status()
        return r.json()
    # === end prelude ===
''').lstrip()


# Validation harness wraps the LLM's parser code and enforces the output schema.
VALIDATION_HARNESS = textwrap.dedent('''
    # === validation harness (orchestrator-injected) ===
    _USER_OUT = None
    def set_result(obj):
        global _USER_OUT
        _USER_OUT = obj
    ''')  # the user's code then calls set_result({...}) at the end

VALIDATION_SUFFIX = textwrap.dedent('''
    # === validation suffix ===
    import json as _vj
    if _USER_OUT is None:
        print("__RESULT__null")
    else:
        print("__RESULT__" + _vj.dumps(_USER_OUT, default=str))
''')


class SandboxResult:
    __slots__ = ("stdout", "stderr", "exit_code", "duration", "timed_out")

    def __init__(self, stdout, stderr, exit_code, duration, timed_out=False):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration = duration
        self.timed_out = timed_out

    def as_observation(self) -> str:
        parts = [f"[SANDBOX EXIT={self.exit_code} TIME={self.duration:.2f}s]"]
        if self.timed_out:
            parts.append("[TIMED OUT]")
        if self.stdout:
            parts.append("--- stdout ---\n" + self.stdout)
        if self.stderr:
            parts.append("--- stderr ---\n" + self.stderr)
        return "\n".join(parts)


class Sandbox:
    """Thin wrapper over docker SDK."""

    def __init__(self, settings: "Settings" = SETTINGS):
        self.s = settings
        self.client = docker.from_env()

    # ---- image management ----
    def ensure_image(self, rebuild: bool = False) -> str:
        name = self.s.sandbox_image
        if not rebuild:
            try:
                self.client.images.get(name)
                return name
            except ImageNotFound:
                pass
        dockerfile_dir = str(Path(__file__).resolve().parent / "sandbox")
        print(f"[sandbox] building {name} from {dockerfile_dir} ...")
        image, _logs = self.client.images.build(
            path=dockerfile_dir, tag=name, rm=True
        )
        # print last few build log lines if something went weird
        return image.tags[0] if image.tags else name

    # ---- code execution ----
    def run(self, code: str, context: dict | None = None,
            payload: str | None = None, timeout: int | None = None) -> SandboxResult:
        """Execute arbitrary Python in an isolated container.

        Args:
            code: Python source the LLM wrote (without the prelude).
            context: JSON-serialisable dict exposed to the code as `CONTEXT`.
            payload: optional raw string (e.g. an MCP json-rpc envelope) made
                available to the script as `PAYLOAD`.
            timeout: override Settings.sandbox_timeout.
        """
        image = self.ensure_image()
        timeout = timeout or self.s.sandbox_timeout
        context = context or {}

        # Build the runnable script: prelude + context/payload injection + user code.
        ctx_json = json.dumps(context, default=str)
        payload_json = json.dumps(payload or "", default=str)
        script = (PRELUDE
                  .replace("_CONTEXT_VALUE_", ctx_json)
                  .replace("_PAYLOAD_VALUE_", payload_json)
                  ) + "\n" + code + "\n"

        with tempfile.TemporaryDirectory(prefix="wazuh_sandbox_") as host_work:
            script_path = Path(host_work) / "script.py"
            script_path.write_text(script, "utf-8")

            # Create the container with a bind mount so we don't have to ship a tar.
            try:
                container = self.client.containers.create(
                    image=image,
                    command=["python", "/home/sandbox/work/script.py"],
                    working_dir="/home/sandbox/work",
                    volumes={
                        host_work: {"bind": "/home/sandbox/work", "mode": "rw"}
                    },
                    network=self.s.sandbox_network,        # 'none' by default
                    mem_limit=self.s.sandbox_mem_limit,
                    cpu_quota=self.s.sandbox_cpu_quota,
                    cpu_period=100000,
                    pids_limit=128,
                    read_only=False,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges"],
                    detach=True,
                    stdin_open=False,
                    tty=False,
                )
            except APIError as e:
                return SandboxResult("", f"docker create failed: {e}", -1, 0.0)

            start = time.time()
            try:
                container.start()
                # Poll for completion up to `timeout` seconds
                deadline = start + timeout
                while time.time() < deadline:
                    try:
                        container.wait(timeout=2)
                        break
                    except Exception:
                        # docker-py raises ConnectionError on short timeout; retry
                        try:
                            container.reload()
                            if container.status in ("exited", "dead"):
                                break
                        except Exception:
                            break
                else:
                    # Timed out: kill the container
                    try:
                        container.kill()
                    except Exception:
                        pass
                duration = time.time() - start

                # Collect logs (both streams are in stdout in docker logs)
                try:
                    logs = container.logs(stdout=True, stderr=True).decode(
                        "utf-8", errors="replace"
                    )
                except Exception as e:
                    logs = f"<failed to fetch logs: {e}>"

                # Best-effort exit code split: docker joins stdout+stderr so we
                # cannot precisely separate after the fact. We treat everything
                # as stdout; exit code comes from container.attrs.
                exit_code = container.attrs["State"].get("ExitCode", -1)
                timed_out = duration >= timeout and exit_code == 137
                return SandboxResult(logs, "", exit_code, duration, timed_out)
            finally:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    # ---- sandbox-first validation gate ------------------------------------

    @staticmethod
    def _extract_result_line(stdout: str) -> Any | None:
        """Pull the LLM-emitted JSON value out of the sandbox stdout.

        Looks for the last line whose body starts with `__RESULT__` and
        json-loads it.  Returns None if no such line or parse fails.
        """
        marker = "__RESULT__"
        last = None
        for ln in (stdout or "").splitlines():
            if ln.startswith(marker):
                last = ln[len(marker):]
        if last is None:
            return None
        try:
            return json.loads(last)
        except Exception:
            return None

    def _validate_schema(self, value: Any, schema: dict | None) -> bool:
        """Check `value` against a JSON Schema.  Returns True if ok or if no
        schema was supplied.  Uses `jsonschema` if available, else basic
        duck-typed type checks."""
        if not schema:
            return True
        try:
            import jsonschema  # type: ignore
        except Exception:
            # Fallback: only check `type` keyword.
            t = schema.get("type")
            if t == "object" and not isinstance(value, dict):
                return False
            if t == "array" and not isinstance(value, list):
                return False
            if t == "string" and not isinstance(value, str):
                return False
            if t == "number" and not isinstance(value, (int, float)):
                return False
            if t == "boolean" and not isinstance(value, bool):
                return False
            return True
        try:
            jsonschema.validate(instance=value, schema=schema)
            return True
        except Exception:
            return False

    def execute_and_validate(
        self,
        code: str,
        schema: dict | None = None,
        payload: str | None = None,
        context: dict | None = None,
        timeout: int | None = None,
    ) -> tuple[Any | None, SandboxResult]:
        """Sandbox-first validation gate.

        The LLM is given the raw `payload` (e.g. an MCP json-rpc envelope
        string) and asked to write a parser.  Its script is wrapped with a
        validation harness that:

            * injects `PAYLOAD` (raw string) into the sandbox
            * has the script call `set_result(<dict>)`
            * captures stdout, finds the line starting with
              `__RESULT__`, and json-loads it
            * checks the parsed value against `schema` (jsonschema)

        Returns:
            (parsed_value_or_None, SandboxResult)
            If parsed_value is None the sandbox rejected the output ---
            the caller should ask the LLM to fix the parser.
            If parsed_value is not None, it has been validated against
            the schema and can be promoted to the real-time environment.
        """
        wrapped_code = (
            VALIDATION_HARNESS
            + "\n# ---- user-generated parser code below ----\n"
            + code
            + "\n# ---- end user code ----\n"
            + VALIDATION_SUFFIX
        )
        res = self.run(wrapped_code, context=context, payload=payload,
                       timeout=timeout)
        if res.exit_code not in (0, None):
            return None, res
        value = self._extract_result_line(res.stdout)
        if value is None:
            return None, res
        if not self._validate_schema(value, schema):
            return None, res
        return value, res


# Convenience singleton
sandbox = Sandbox()
