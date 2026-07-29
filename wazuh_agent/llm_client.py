"""NVIDIA OpenAI-compatible LLM client.

Wraps the streaming chat-completions call. The Nemotron model emits
`reasoning_content` chunks (the model's "Thought") *before* the `content`
chunks. For ReAct we want BOTH:

* `reasoning_content`  -> the model's internal Thought -> wrapped as
  `<thought>...</thought>` for parsing.
* `content`            -> the actual Act output (code blocks, final answer).

We surface them concatenated in a single assistant string like:

    <thought>...</thought>
    <content>...</content>
"""
from __future__ import annotations
import re
from typing import Generator

from openai import OpenAI

try:
    from .config import SETTINGS
except ImportError:  # running as a script
    from config import SETTINGS


class LLM:
    def __init__(self, settings=SETTINGS):
        self.s = settings
        self.client = OpenAI(
            base_url=settings.base_url,
            api_key=settings.nvidia_api_key,
        )

    # ---- non-streaming helpers ----
    def chat(self, messages: list[dict]) -> str:
        """Single-shot completion. Returns the assembled assistant text."""
        return "".join(self._stream_text(messages))

    def stream(self, messages: list[dict]) -> Generator[str, None, None]:
        """Yield assistant content tokens for live display (reasoning included)."""
        yield from self._stream_text(messages)

    # ---- core streaming ----
    def _stream_text(self, messages: list[dict]) -> Generator[str, None, None]:
        completion = self.client.chat.completions.create(
            model=self.s.model,
            messages=messages,
            temperature=self.s.temperature,
            top_p=0.95,
            max_tokens=self.s.max_tokens,
            extra_body={
                "chat_template_kwargs": {"enable_thinking": True},
                "reasoning_budget": self.s.reasoning_budget,
            },
            stream=True,
        )

        in_thought = False
        for chunk in completion:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta

            reasoning = getattr(delta, "reasoning_content", None)
            if reasoning:
                if not in_thought:
                    yield "<thought>"
                    in_thought = True
                yield reasoning

            if delta.content:
                if in_thought:
                    yield "</thought>\n"
                    in_thought = False
                yield delta.content

        if in_thought:
            yield "</thought>\n"


def split_thought_content(text: str) -> tuple[str, str]:
    """Pull out <thought>...</thought> blocks from a completed assistant text.

    Returns (thought_join, content_without_thought).
    """
    thoughts: list[str] = []
    pattern = re.compile(r"<thought>(.*?)</thought>", re.DOTALL)
    for m in pattern.finditer(text):
        thoughts.append(m.group(1).strip())
    content = pattern.sub("", text).strip()
    return "\n\n".join(thoughts), content


llm = LLM()
