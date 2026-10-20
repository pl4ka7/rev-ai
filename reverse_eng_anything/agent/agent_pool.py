"""Runs a swarm of short, parallel OpenRouter calls against a shared
TokenBudget, for REA functions that benefit from fanning out (e.g.
classifying N crashes, or naming M decompiled modules) rather than one call
per item sequentially.

Parallelism is for latency, not for spending more — every worker shares the
same budget, so going wide never multiplies the token ceiling.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar

from .openrouter_client import BudgetExhausted, OpenRouterClient

T = TypeVar("T")


@dataclass
class AgentTaskResult(Generic[T]):
    item: T
    text: str | None
    error: str | None = None
    tokens_used: int = 0
    from_cache: bool = False


def run_pool(
    client: OpenRouterClient,
    items: list[T],
    prompt_fn: Callable[[T], str],
    system: str = "",
    max_tokens: int = 128,
    max_workers: int = 4,
) -> list[AgentTaskResult[T]]:
    """Fans `items` out to parallel workers, each making one minimal-token
    OpenRouter call via `client`. Stops issuing new calls once the client's
    budget is exhausted; items past that point come back with an error
    instead of silently being dropped.
    """
    results: dict[int, AgentTaskResult[T]] = {}

    def _call(idx: int, item: T) -> tuple[int, AgentTaskResult[T]]:
        prompt = prompt_fn(item)
        try:
            completion = client.complete(prompt, system=system, max_tokens=max_tokens)
            return idx, AgentTaskResult(
                item=item, text=completion.text, tokens_used=completion.tokens_used,
                from_cache=completion.from_cache,
            )
        except BudgetExhausted as exc:
            return idx, AgentTaskResult(item=item, text=None, error=str(exc))
        except Exception as exc:  # network errors, API errors — surfaced, not swallowed
            return idx, AgentTaskResult(item=item, text=None, error=str(exc))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_call, i, item) for i, item in enumerate(items)]
        for future in as_completed(futures):
            idx, result = future.result()
            results[idx] = result

    return [results[i] for i in range(len(items))]
