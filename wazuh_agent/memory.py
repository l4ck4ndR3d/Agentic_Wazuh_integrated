"""Conversation memory.

A simple JSON-backed rolling memory so chats persist across runs and within
a single ReAct session. Each entry has role (`user`/`assistant`/`system`) and
content; tool/code observations are stored as `assistant` turns tagged with
`[OBSERVATION]`.
"""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from typing import Iterable

MEMORY_DIR = Path(__file__).resolve().parent.parent / "memory"
MEMORY_DIR.mkdir(exist_ok=True)


class Memory:
    def __init__(self, session_id: str = "default"):
        self.session_id = session_id
        self.path = MEMORY_DIR / f"{session_id}.json"
        self.messages: list[dict] = []
        self._load()

    # ---- persistence ----
    def _load(self):
        if self.path.exists():
            try:
                self.messages = json.loads(self.path.read_text("utf-8"))
            except Exception:
                self.messages = []

    def save(self):
        self.path.write_text(json.dumps(self.messages, indent=2), "utf-8")


    def add(self, role: str, content:str):
        self.messages.append(
            {
                "role":role,
                "content": content,
                "ts": datetime.utcnow().isoformat() + "Z"
            }
        )
        self.save()

    def add_observation(self, observation: str):
        """Tool/sandbox outputs become assistant messages tagged with [OBSERVATION]."""
        self.add("assistant", f"[OBSERVATION]\n{observation}")

    def reset(self):
        self.messages = []
        if self.path.exists():
            self.path.unlink()

    # ---- views ----
    def openai_messages(self, system_prompt: str | None = None) -> list[dict]:
        """Return messages formatted for the OpenAI Chat Completions API.

        The first message is always a system prompt. If system_prompt is
        provided, we prepend it (overwriting any prior system prompt in this
        session) so a single long-running ReAct thread can keep it fresh.
        """
        out: list[dict] = []
        if system_prompt:
            out.append({"role": "system", "content": system_prompt})
        for m in self.messages:
            out.append({"role": m["role"], "content": m["content"]})
        # Guarantee the conversation starts with a system message
        if not out or out[0]["role"] != "system":
            out.insert(0, {"role": "system", "content": "You are a helpful security assistant."})
        return out

    def __len__(self):
        return len(self.messages)

    def transcript(self) -> Iterable[str]:
        for m in self.messages:
            yield f"[{m.get('ts','?')}] {m['role'].upper()}: {m['content']}"


def list_sessions() -> list[str]:
    return sorted(p.stem for p in MEMORY_DIR.glob("*.json"))
