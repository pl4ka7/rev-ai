"""LLM-assisted REA functions, backed by OpenRouter (default: a free
DeepSeek model) so the swarm of parallel agents doesn't cost anything unless
you deliberately switch to a paid model via OPENROUTER_MODEL.

Three functions use this, all optional and off unless OPENROUTER_API_KEY is
set:
  - summarize_report()        one call, whole-report prose summary
  - classify_crashes_pool()   N crashes classified in parallel, tiny prompts
  - name_modules_pool()       M decompiled modules get a suggested real name

All three are advisory only — they read already-computed REA output and
return text. None of them are given the raw binary, write access, or asked
for exploit code; the system prompts say so explicitly.
"""
from __future__ import annotations

from ..core.decompile import ModuleSource
from ..core.report import RunReport
from ..core.triage import CrashClassification
from .agent_pool import AgentTaskResult, run_pool
from .openrouter_client import OpenRouterClient, TokenBudget

_SAFETY_SUFFIX = (
    " Do not propose exploit code, gadget chains, or weaponized payloads — "
    "classification/summary only."
)

_REPORT_SYSTEM = (
    "You summarize reverse-engineering triage reports for a human analyst, "
    "in plain English, briefly." + _SAFETY_SUFFIX
)
_CRASH_SYSTEM = (
    "In one short sentence, state the likely root cause category for this "
    "crash (e.g. buffer overflow, use-after-free, null deref, type confusion) "
    "from the signal/fault info given. One sentence only." + _SAFETY_SUFFIX
)
_MODULE_SYSTEM = (
    "Given decompiled C pseudocode, suggest a short, real module/file name "
    "(e.g. 'network_io', 'config_parser'). Reply with just the name, "
    "lowercase, underscores, no explanation." + _SAFETY_SUFFIX
)


def _default_client(client: OpenRouterClient | None, budget: TokenBudget | None) -> OpenRouterClient:
    return client or OpenRouterClient(budget=budget)


def summarize_report(
    report: RunReport, client: OpenRouterClient | None = None, budget: TokenBudget | None = None
) -> str:
    client = _default_client(client, budget)
    # Keep the report itself short: send only the first ~3000 chars (headline
    # sections) rather than a potentially huge crash table — the client also
    # backstops this, but trimming here saves a wasted truncation warning.
    result = client.complete(report.to_markdown()[:3000], system=_REPORT_SYSTEM, max_tokens=300)
    return result.text


def classify_crashes_pool(
    crashes: list[CrashClassification],
    client: OpenRouterClient | None = None,
    budget: TokenBudget | None = None,
    max_workers: int = 4,
) -> list[AgentTaskResult[CrashClassification]]:
    client = _default_client(client, budget)

    def _prompt(c: CrashClassification) -> str:
        # Minimal prompt: signal/fault/region only, never the full backtrace —
        # keeps each call a handful of tokens.
        return f"signal={c.signal} fault_type={c.fault_type} region={c.region_guess}"

    return run_pool(client, crashes, _prompt, system=_CRASH_SYSTEM, max_tokens=60, max_workers=max_workers)


def name_modules_pool(
    modules: list[ModuleSource],
    client: OpenRouterClient | None = None,
    budget: TokenBudget | None = None,
    max_workers: int = 4,
) -> list[AgentTaskResult[ModuleSource]]:
    client = _default_client(client, budget)

    def _prompt(m: ModuleSource) -> str:
        # Send only the first function's source, capped — enough context to
        # guess a name without burning tokens on the whole module.
        first_fn_src = m.functions[0].c_source[:400] if m.functions else ""
        return first_fn_src

    return run_pool(client, modules, _prompt, system=_MODULE_SYSTEM, max_tokens=20, max_workers=max_workers)
