# Agents in this repo — don't confuse the three

| | **Agent A — builder** | **Agent B — runtime orchestrator** | **Agent C — parallel OpenRouter swarm** |
|---|---|---|---|
| What | Claude Code / `scripts/dev_loop.py` | `agent/orchestrator.py` | `agent/agent_pool.py` + `agent/openrouter_client.py` |
| Role | Writes/fixes REA's own source | Decides which REA pipeline stage runs next | Does small, parallel, token-capped LLM calls *for* Agent B |
| Model | Claude (Code), or a free DeepSeek model via `dev_loop.py` | none — plain Python decision logic | OpenRouter, defaults to a free model |
| Touches | REA's source code, via git commits | A target binary's analysis pipeline | Already-computed REA output (crash summaries, backtraces, decompiled snippets) — never the raw binary |

Agent B calling Agent C is what you asked for: when `--use-agents` is set,
the orchestrator fans out to OpenRouter for two optional, cheap helper
functions (crash root-cause hints, module naming) instead of doing them with
plain heuristics. It's off by default — nothing is billed unless you opt in.

## Cost controls (why this stays cheap)

- **Default model is free**: `DEFAULT_FREE_MODEL` in `openrouter_client.py`
  is a `:free`-suffixed OpenRouter model. Override with `OPENROUTER_MODEL`
  if you want a paid one — nothing stops you, but nothing defaults to it
  either. Free-tier slugs on OpenRouter change over time; check
  https://openrouter.ai/models?max_price=0 if the default looks stale.
- **Shared `TokenBudget`**: every call in a run — however many crashes or
  modules get fanned out — draws from one `TokenBudget`. Parallelism changes
  latency, not spend. Once the budget's `max_total_tokens` or `max_calls`
  is hit, further calls raise `BudgetExhausted` and are logged, not retried.
- **Minimal prompts by construction**: `llm_advisor.py` never sends a full
  backtrace or a full decompiled module — just the few fields each function
  actually needs (e.g. `signal=SIGSEGV fault_type=write region=stack`),
  with a hard character cap as backstop in the client itself.
- **In-process cache**: an identical prompt is never billed twice within one
  run (`OpenRouterClient._cache`).
- **Tune per run**: `--agent-token-budget` / `--agent-call-budget` on
  `rea run`, or pass a custom `TokenBudget` programmatically.

## Agent A automation — `scripts/dev_loop.py`

A standalone script (not part of the REA package, not invoked by REA at
runtime) that drives the *builder* role with a free OpenRouter model instead
of Claude Code: it loops pytest → ask the model for a fixed file → write →
re-test → commit, up to `--max-iterations`, bounded by its own
`--token-budget` / `--call-budget`. Every write is a separate git commit so
nothing is irreversible. See the script's own docstring for details.

```bash
OPENROUTER_API_KEY=... python scripts/dev_loop.py --max-iterations 5 --token-budget 20000
```
