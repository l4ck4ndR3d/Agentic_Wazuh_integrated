"""Interactive REPL entry point for the Wazuh ReAct Code Agent — dual engine.

Usage:
    source ~/Desktop/pyenv/bin/activate
    cd "/home/cyborg/Desktop/MCP-LLM-Blueteam/MCP & Agentic AI"
    python -m wazuh_agent.main                     # default (langgraph engine)
    python -m wazuh_agent.main --engine custom     # legacy ReAct engine
    python -m wazuh_agent.main --engine langgraph  # LangGraph engine (default)
    python -m wazuh_agent.main --validate          # sandbox-first mode ON
    python -m wazuh_agent.main --no-validate       # sandbox-first mode OFF
    python -m wazuh_agent.main --session audit     # named session
    python -m wazuh_agent.main --reset             # wipe memory
    python -m wazuh_agent.main --build             # rebuild sandbox image
    python -m wazuh_agent.main --once "question"   # one-shot, then exit

Commands inside the REPL:
    /reset       clear memory
    /session <name>  switch session
    /sessions    list sessions
    /show        print current memory transcript
    /tools       list available tools (langgraph mode)
    /exit        quit

Engines:
  * "custom" – legacy Thought/Act/Observe loop with fenced-code-block
     parsing (original agent.py logic, supports Nemotron reasoning stream).
  * "langgraph" – LangGraph create_react_agent with native tool-calling,
    checkpointing (SqliteSaver).

Toggling sandbox validation:
    When SETTINGS.sandbox_validate=True (env SANDBOX_VALIDATE=1 or --validate),
    every tool call's raw JSON-RPC response is routed through the sandbox
    where the LLM writes parser code, runs it inside Docker, and only 
    promoted results that validate against the expected schema enter the
    real-time environment.
"""
from __future__ import annotations
import argparse
import os
import sys
import time
from pathlib import Path

# Make sure the package can be imported whether run as `python -m wazuh_agent.main`
# or `python wazuh_agent/main.py`
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

try:
    from .config import SETTINGS
    from .agent import Agent, get_langgraph_agent, ask_langgraph
    from .sandbox import sandbox
    from .memory import Memory, list_sessions
except ImportError:
    from config import SETTINGS
    from agent import Agent, get_langgraph_agent, ask_langgraph
    from sandbox import sandbox
    from memory import Memory, list_sessions

console = Console()

BANNER = r"""
 __        __           ____                            _   
 \ \      / /          / ___|___  _ __  _ __   ___  ___| |_ 
  \ \ /\ / /   _____  | |   / _ \| '_ | '_ \ / _ \/ __| __|
   \ V  V /   |_____| | |__| (_) | | | | | | |  __/ (__| | 
    \_/\_/             \____\___/|_| |_| |_| |_|\___|\___|_| - MBM

"""


def parse_args():
    p = argparse.ArgumentParser(description="Wazuh ReAct Code Agent")
    p.add_argument("--session", default="default", help="memory session id")
    p.add_argument("--reset", action="store_true", help="clear session memory and exit")
    p.add_argument("--build", action="store_true", help="(re)build sandbox docker image then exit")
    p.add_argument("--once", metavar="QUERY", help="answer one query and exit")
    p.add_argument("--engine", choices=["custom", "langgraph"], default="langgraph",
                   help="agent engine: 'custom' (legacy) or 'langgraph' (default)")
    p.add_argument("--validate", action="store_true", default=None,
                   help="enable sandbox-first validation")
    p.add_argument("--no-validate", dest="validate", action="store_false",
                   help="disable sandbox-first validation")
    return p.parse_args()


def _show_status(engine: str, validate: bool):
    """Display engine name, available flags, tool count, etc."""
    console.print(f"  [bold blue]Engine[/]       {engine}")
    console.print(f"  [bold blue]Validate[/]     {'✅ ON ' if validate else '❌ OFF'}")
    console.print(f"  [bold blue]MCP[/]        {'✅' if SETTINGS.use_mcp else '❌'}")
    if engine == "langgraph":
        try:
            ag = get_langgraph_agent()
            names = ag.get_tool_names()
            console.print(f"  [bold blue]Tools[/]       {len(names)} — {', '.join(n for n in names[:8])}"
                          f"{' ...' if len(names) > 8 else ''}")
        except Exception:
            console.print("  [bold blue]Tools[/]       (langgraph agent not loaded)")
    else:
        console.print("  [bold blue]Tools[/]       fenced code blocks only (legacy ReAct)")
    console.print()


def repl(args):
    global SETTINGS

    if args.build:
        console.print("[cyan]Building sandbox image...[/]")
        img = sandbox.ensure_image(rebuild=True)
        console.print(f"[green]Sandbox image ready: {img}[/]")
        return

    if args.engine == "custom":
        SETTINGS.agent_engine = "custom"

    if args.validate is not None:
        SETTINGS.sandbox_validate = args.validate

    engine = SETTINGS.agent_engine
    validate = SETTINGS.sandbox_validate

    mem = Memory(args.session)
    if args.reset:
        mem.reset()
        console.print(f"[green]Cleared session '[/green][white]{args.session}[/white][green]'.[/]")
        if not args.once and not any([args.build]):
            return

    console.print(Panel(BANNER, border_style="cyan"))
    console.print(f"[bold green]Session[/]  {args.session}  "
                  f"[bold green]Model[/]    {SETTINGS.model}  "
                  f"[bold green]Max Iters[/]  {SETTINGS.max_iters}")

    _show_status(engine=engine, validate=validate)

    if args.once:
        if engine == "langgraph":
            ans = ask_langgraph(args.once)
            console.print(Markdown(ans))
        else:
            agent = Agent(mem)
            agent.ask(args.once)
        return

    # Interactive REPL
    console.print("Type a security query about your Wazuh deployment:\n"
                  "  /reset, /session <name>, /sessions, /show, /exit[/]")

    agent = None
    if engine == "custom":
        agent = Agent(mem)

    try:
        while True:
            try:
                line = console.input("[bold magenta]you> [/]").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]bye[/]")
                break
            if not line:
                continue

            if line == "/exit":
                break
            elif line == "/reset":
                mem.reset()
                console.print("[green]memory cleared[/]")
            elif line.startswith("/session "):
                name = line.split(maxsplit=1)[1].strip()
                mem = Memory(name)
                if engine == "custom":
                    agent = Agent(mem)
                console.print(f"[green]switched to session '[/green]{name}[green]'[/]")
            elif line == "/sessions":
                for s in list_sessions():
                    console.print(f"  - {s}")
            elif line == "/show":
                for ln in mem.transcript():
                    console.print(ln)
            else:
                try:
                    if engine == "langgraph":
                        ans = ask_langgraph(line)
                        console.print(Markdown(ans or ""))
                    else:
                        agent.ask(line)
                except Exception as e:
                    console.print(f"[red]agent error: {e!r}[/]")
    finally:
        console.print("[yellow]goodbye[/]")


if __name__ == "__main__":
    args = parse_args()
    repl(args)