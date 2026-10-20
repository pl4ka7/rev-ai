# Using Claude Code as the builder agent (Agent A)

This repo is meant to be developed with an agentic coding tool (Claude Code,
on the CLI, in VS Code, or on the web) that can read files, write code, run
`pytest`, and call shell tools. It should never run the orchestrator's live
analysis loop itself — that's Agent B's job, not Agent A's.

## One-time setup

```bash
git clone <your-fork-url>
cd reverse-eng-anything
claude          # starts Claude Code in this directory
```

## Example tasks to hand it

- "Implement `core/fuzz.py`'s AFL++ wrapper: shell out to `afl-fuzz`, parse
  `fuzzer_stats`, and return a `FuzzRunResult`. Write tests that mock the
  subprocess call."
- "Add an x86-64 vs ARM64 path in `core/disasm.py`'s `Disassembler.analyze`."
- "Extend `core/triage.py` to also flag double-free patterns from a crash's
  backtrace. Add a unit test with a synthetic backtrace fixture."
- "Run `pytest -q` and fix any failing tests."

Give it one module/behavior at a time with an explicit "write tests too" —
it will edit the file, run the suite, and iterate until green.

## Guardrails for the agent

- Keep `core/triage.py` at classification only — no exploit primitive
  generation (no ROP/gadget search, no shellcode, no auto-generated PoC).
- `agent/llm_advisor.py` only *summarizes/classifies/names* already-computed
  findings; it must not be given write access to the target binary or
  network reach beyond the OpenRouter API, and every call must go through
  the shared `TokenBudget` in `agent/openrouter_client.py` (see
  [AGENTS.md](AGENTS.md) for the runtime-agent design and cost controls).
- All new modules get a matching file in `tests/`.
