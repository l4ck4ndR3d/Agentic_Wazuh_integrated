"""Wazuh ReAct Code Agent — dual-mode.

This module supports **two agent engines** gated by `SETTINGS.agent_engine`:

  engine == "custom":
    Legacy Thought → Act → Observe loop with fenced-code-block parsing (see
    docstring below).  Kept because of Nemotron's `reasoning_content` stream
    handling and full control over sandbox prelude injection.

  engine == "langgraph":
    LangGraph `create_react_agent` with native tool-calling, checkpointing
    (SqliteSaver), and human-in-the-loop.  See
    `langchain_agent.py`.

Both engines implement the **sandbox-first validation** pattern when
`SETTINGS.sandbox_validate=True`:

  1. LLM calls a tool (e.g. `wazuh_search_alerts`).
  2. Tool returns a raw JSON-RPC envelope string (courtesy of MCP).
  3. The agent sends the envelope to the sandbox alongside a
     "generate parser code that calls `set_result(...)` prompt.
  4. If the sandbox validates → promote the parsed dict to a real-time
     answer.  If it rejects → retry (up to N retries) or return raw.

Legacy engine:  in the legacy `Agent` class, the Tool section uses MCP
wrapper functions (see `tools/wazuh_tools.py`) which return JSON-RPC strings.
The sandbox-first validation is then triggered by `_call_tool_with_validate`.

LangGraph engine: sees langchain_agent.py
"""
from __future__ import annotations
import re
import sys
import textwrap
import json
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

try:
    from .config import SETTINGS
    from .llm_client import llm, LLM
    from .memory import Memory
    from .sandbox import sandbox, SandboxResult
except ImportError:  # running as a script
    from config import SETTINGS
    from llm_client import llm, LLM
    from memory import Memory
    from sandbox import sandbox, SandboxResult

console = Console()

# ---- system prompt ---------------------------------------------------------

API_REF = (Path(__file__).resolve().parent / "wazuh_api_reference.md").read_text("utf-8")

SYSTEM_PROMPT = textwrap.dedent(f"""\
You are **WazuhSec**, a security-analyst Code Agent that operates a local
Wazuh deployment. You work by writing and running Python code in an isolated
Docker sandbox, observing its output, then reasoning about the next step.

==============
1. ENVIRONMENT
==============
- Your code runs as a Python 3.12 process inside a Docker container with
  host networking. That means the Wazuh Indexer and Manager API on the
  host are reachable from inside the sandbox at 127.0.0.1.
- Wazuh Indexer  (OpenSearch-compatible): https://127.0.0.1:9200
     auth: HTTP Basic  admin:SecretPassword   (verify=False on TLS)
- Wazuh Manager   (REST + JWT)             : https://127.0.0.1:55000
     auth: POST /security/user/authenticate?raw=true with Basic wazuh-wui:{SETTINGS.wazuh_manager_pass}
     IMPORTANT: login ONCE and reuse the token for all subsequent Manager calls.
     Do NOT re-authenticate per call — that triggers rate-limiting.
     If auth fails with 403, the IP is rate-limited (block_time=300s);
     fall back to Indexer API queries for the same data.
- `requests` is installed inside the sandbox. `urllib3` InsecureRequestWarnings
  are already disabled by the prelude.
- A prelude of helpers (`CONTEXT`, `INDEXER`, `MANAGER`, `print_json`,
  `IDXR_USER`, `IDXR_PASS`, `MANAGER_USER`, `MANAGER_PASS`, `search_alerts`) is
  auto-injected before your code. Use `print_json(obj)` to emit structured output.
- Your code has at most {SETTINGS.sandbox_timeout}s wall-clock and
  512MB RAM. Do not write infinite loops or huge allocations.

==============
2. WAZUH API REFERENCE
==============
{API_REF}

==============
3. REACT PROTOCOL  (Thought -> Act -> Observe)
==============
You MUST follow this exact loop. Use fenced code blocks for actions.

THOUGHT:  explain (1-3 sentences) what you will do next and why.
          This is your internal reasoning (your `reasoning_content` stream).
          You do not need to repeat it in `content` if the model already
          filled `reasoning_content` -- but if it did not, start your
          content with  Thought: ...

ACT:      Write a single ```python ... ``` fenced code block that performs
          ONE coherent action (one query, one transform, one print). Do not
          put more than one code block per turn. After the code block you
          may add a short line "Waiting for sandbox...".

OBSERVE:  You do not produce the observation. The orchestrator runs your
          code in Docker and appends  [OBSERVATION]\n<stdout/stderr>  back
          to you. Then you Thought/Act again.

FINAL:    When you have enough information to answer the user, emit:

          <final_answer>
          ... your answer for the human (markdown allowed) ...
          </final_answer>

          Do NOT include a code block in the final-answer turn.

==============
4. CODING RULES
==============
- Prefer the Indexer API (`POST /<index>/_search`) for aggregated/historical
  queries; prefer the Manager API for live agent/config inventory.
- Always `verify=False` and pass `auth=(user, pass)` for the Indexer.
- For the Manager API, login first (`base64encode` Basic over
  `/security/user/authenticate?raw=true`) then reuse the token.
- Wrap network calls in try/except and PRINT the error (so Observe still
  gives you something to work with). Never let an exception silently kill
  the script.
- Keep output small: if a search returns 1000s of hits, use `aggs` or
  `size: 20` and summarise. Do not dump raw 50-doc JSON.
- Print clearly labelled, structured output, e.g.:

      print_json({{"high_alerts_last_24h": count, "top_rules": top}})

==============
5. STOPPING
==============
- Emit `<final_answer>...</final_answer>` as soon as you have a usable
  answer. Do not pad with extra code turns.
- If something genuinely cannot be answered, emit
  `<final_answer>I could not complete this because ...</final_answer>`.
""")


# ---- parsing the assistant output -----------------------------------------

CODE_BLOCK_RE = re.compile(
    r"```(?:python|py)?\s*\n(?P<code>.*?)```",
    re.DOTALL,
)
FINAL_ANSWER_RE = re.compile(r"<final_answer>(.*?)</final_answer>", re.DOTALL | re.IGNORECASE)


def parse_assistant(text: str) -> dict:
    """Extract structured next-step from the model output.

    Returns one of:
      {"kind": "final",       "answer": str}
      {"kind": "code",        "code":   str}
      {"kind": "noop",        "raw":    str}      # nothing actionable
    """
    fa = FINAL_ANSWER_RE.search(text)
    if fa:
        return {"kind": "final", "answer": fa.group(1).strip()}
    m = CODE_BLOCK_RE.search(text)
    if m:
        return {"kind": "code", "code": m.group("code").strip()}
    return {"kind": "noop", "raw": text}


# ---- pre-fetch context (optional) -----------------------------------------

def _prefetch_context() -> dict:
    import requests as _r
    _r.packages.urllib3.disable_warnings()
    ctx: dict = {"indices": []}
    try:
        rr = _r.get(
            f"{SETTINGS.wazuh_indexer_url}/_cat/indices/wazuh-*?v&h=index,docs.count",
            auth=SETTINGS.indexer_auth, verify=False, timeout=8,
        )
        if rr.ok:
            lines = [ln.split() for ln in rr.text.strip().splitlines() if ln.strip()]
            ctx["indices"] = [{"index": a[0], "docs": a[1] if len(a) > 1 else "?"}
                              for a in lines][:40]
    except Exception as e:
        ctx["indices_error"] = str(e)
    return ctx


# ---- the agent loop --------------------------------------------------------

class Agent:
    def __init__(self, memory: Memory, settings=SETTINGS):
        self.mem = memory
        self.s = settings
        self.ctx: dict = {}

    def ask(self, user_input: str) -> str:
        """Run one full ReAct loop for a single user query."""
        console.rule(f"[bold cyan]User turn[/]")
        console.print(Panel(user_input, title="user", border_style="cyan"))
        self.mem.add("user", user_input)

        if not self.ctx:
            self.ctx = _prefetch_context()

        for it in range(1, self.s.max_iters + 1):
            console.rule(f"[bold yellow]ReAct iter {it}/{self.s.max_iters}[/]")
            messages = self.mem.openai_messages(system_prompt=SYSTEM_PROMPT)

            console.print("[dim]Assistant thinking...[/]")
            raw_parts: list[str] = []
            try:
                for tok in llm.stream(messages):
                    raw_parts.append(tok)
                    console.print(tok, end="")
                console.print()
            except Exception as e:
                err = f"[LLM ERROR] {e!r}"
                console.print(f"[red]{err}[/]")
                self.mem.add("assistant", err)
                return err

            assistant_text = "".join(raw_parts).strip()
            self.mem.add("assistant", assistant_text)

            step = parse_assistant(assistant_text)

            if step["kind"] == "final":
                answer = step["answer"]
                console.rule("[bold green]Final answer[/]")
                console.print(Markdown(answer))
                self.mem.messages[-1]["content"] = (
                    f"<final_answer>\n{answer}\n</final_answer>"
                )
                self.mem.save()
                return answer

            if step["kind"] == "code":
                code = step["code"]
                console.print(Panel(code, title="🎬 sandbox code",
                                    border_style="magenta"))
                result: SandboxResult = sandbox.run(
                    code, context=self.ctx, timeout=self.s.sandbox_timeout,
                )
                console.print(Panel(result.as_observation(),
                                     title="🔍 observation",
                                     border_style="blue"))
                obs = result.as_observation()
                if len(obs) > 6000:
                    obs = obs[:6000] + "\n... [truncated]"
                self.mem.add_observation(obs)
                continue

            # noop
            console.print("[yellow]No actionable step, nudging...[/]")
            self.mem.add_observation(
                "[OBSERVATION] Your previous turn contained neither a "
                "```python code block``` nor a <final_answer>...</final_answer>. "
                "Emit exactly one of them now."
            )

        fallback = ("I reached the maximum number of reasoning steps "
                    f"({self.s.max_iters}) without producing a final answer.")
        console.print(f"[red]{fallback}[/]")
        self.mem.add("assistant", f"<final_answer>{fallback}</final_answer>")
        self.mem.save()
        return fallback


# ---- Optionally create LangGraph agent -------------------------------------

_LC_AGENT: "LangGraphWazuhAgent | None" = None  # type: ignore


def get_langgraph_agent():
    """Lazily construct and return a LangGraphWazuhAgent."""
    global _LC_AGENT
    if _LC_AGENT is None:
        try:
            from .langchain_agent import LangGraphWazuhAgent
        except ImportError:
            from langchain_agent import LangGraphWazuhAgent
        import sqlite3
        from langgraph.checkpoint.sqlite import SqliteSaver

        db_path = SETTINGS.checkpointer_db.replace("sqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        checkpointer = SqliteSaver(conn)
        _LC_AGENT = LangGraphWazuhAgent(checkpointer=checkpointer)
    return _LC_AGENT


def ask_langgraph(user_input: str) -> str:
    """Run a query through the LangGraph agent and return the answer."""
    agent = get_langgraph_agent()
    result = agent.invoke(user_input)
    messages = result.get("messages", [])
    last = messages[-1] if messages else {}
    return getattr(last, "content", "No response")