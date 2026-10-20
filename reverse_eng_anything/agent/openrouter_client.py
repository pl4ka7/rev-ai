"""Thin OpenRouter chat-completions client, built to spend as few tokens as
possible since OpenRouter calls are billed per token (free-tier models
excepted).

Cost controls, all on by default:
  - defaults to a free-tier model (override with OPENROUTER_MODEL)
  - small `max_tokens` ceiling per call (override per-call if you need more)
  - input truncation — callers pass already-short prompts; this client also
    hard-caps prompt length as a backstop
  - an in-process cache so an identical prompt is never billed twice in one run
  - a `TokenBudget` that stops issuing calls once a run-wide cap is hit,
    instead of silently spending past it

This client is deliberately synchronous and dependency-light (`requests`).
Parallelism is handled one layer up, in `agent_pool.py`, with a thread pool —
not by making this client async.
"""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field

import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free-tier model slugs change on OpenRouter over time — check
# https://openrouter.ai/models?max_price=0 and override via OPENROUTER_MODEL
# if this default has been retired.
DEFAULT_FREE_MODEL = "deepseek/deepseek-chat-v3.1:free"

DEFAULT_MAX_TOKENS = 256
DEFAULT_PROMPT_CHAR_CAP = 4000  # backstop truncation, ~1000 tokens


@dataclass
class TokenBudget:
    """Run-wide ceiling so a swarm of parallel agents can't overspend.
    Thread-safe: agent_pool.py calls this concurrently.
    """
    max_total_tokens: int = 20_000
    max_calls: int = 50
    spent_tokens: int = 0
    calls_made: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def try_reserve(self) -> bool:
        """Call before making a request. Returns False if the budget is exhausted."""
        with self._lock:
            if self.calls_made >= self.max_calls or self.spent_tokens >= self.max_total_tokens:
                return False
            self.calls_made += 1
            return True

    def record_actual(self, tokens_used: int) -> None:
        with self._lock:
            self.spent_tokens += tokens_used

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self.calls_made >= self.max_calls or self.spent_tokens >= self.max_total_tokens


@dataclass
class CompletionResult:
    text: str
    tokens_used: int
    model: str
    from_cache: bool = False


class BudgetExhausted(RuntimeError):
    pass


class OpenRouterClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        budget: TokenBudget | None = None,
        session: requests.Session | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.model = model or os.environ.get("OPENROUTER_MODEL", DEFAULT_FREE_MODEL)
        self.budget = budget or TokenBudget()
        self._session = session or requests.Session()
        self._cache: dict[str, CompletionResult] = {}

    @staticmethod
    def _cache_key(system: str, prompt: str, model: str, max_tokens: int) -> str:
        raw = f"{model}|{max_tokens}|{system}|{prompt}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def complete(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
    ) -> CompletionResult:
        if not self.api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set")

        # Backstop truncation — keep this call cheap even if a caller forgot to trim.
        prompt = prompt[:DEFAULT_PROMPT_CHAR_CAP]

        cache_key = self._cache_key(system, prompt, self.model, max_tokens)
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return CompletionResult(cached.text, tokens_used=0, model=cached.model, from_cache=True)

        if not self.budget.try_reserve():
            raise BudgetExhausted(
                f"token budget exhausted ({self.budget.spent_tokens}/{self.budget.max_total_tokens} "
                f"tokens, {self.budget.calls_made}/{self.budget.max_calls} calls) — raise the budget "
                "or reduce the number of parallel agent calls"
            )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self._session.post(
            OPENROUTER_URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()

        text = data["choices"][0]["message"]["content"]
        tokens_used = data.get("usage", {}).get("total_tokens", 0)
        self.budget.record_actual(tokens_used)

        result = CompletionResult(text=text, tokens_used=tokens_used, model=self.model)
        self._cache[cache_key] = result
        return result
