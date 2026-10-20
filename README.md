# Reverse Eng Anything (REA)

Automated reverse-engineering triage framework. Red-team styled TUI, built to be
driven by an AI coding agent during development and to act as an autonomous
agent itself at runtime.

## Two agents — do not confuse them

| | **Agent A — the builder** | **Agent B — the program** |
|---|---|---|
| What it is | Claude Code (or any coding agent) | `reverse_eng_anything/agent/orchestrator.py` |
| Role | Writes, tests, and ships REA's source code | Runs REA's pipeline against a target binary |
| Lives | In your dev environment / CI | On the analyst's machine, invoked via the TUI or CLI |
| Output | Commits, test runs, PRs | Analysis reports (JSON/Markdown) about a binary |

Agent A is covered in [AGENT_DEV.md](AGENT_DEV.md) — how to point Claude Code at
this repo so it writes/extends modules and runs the test suite itself.
There's also a third one — see [AGENTS.md](AGENTS.md) for how Agent B can
fan out to a parallel swarm of cost-capped OpenRouter agents, and how
`scripts/dev_loop.py` lets a free OpenRouter model play Agent A's role too.

Agent B is the actual tool: it ingests a binary, disassembles it, diffs it
against a reference version, fuzzes it, and triages any crashes it finds —
autonomously deciding which step to run next based on what it discovers.

## Scope — what REA does and does not do

REA automates **analysis and triage**, not weaponization:

- ✅ Binary intake, hashing, format/arch detection
- ✅ Disassembly / decompilation via radare2 (`r2pipe`)
- ✅ Function-level binary diffing (e.g. patch-diffing two versions)
- ✅ Driving an existing fuzzer (AFL++) against a harness you supply
- ✅ Crash **classification**: signal, fault type (read/write/jump), module,
  faulting instruction, rough stack-vs-heap guess
- ✅ Structured reports for a human analyst to take the crash forward
- ✅ Optional: regenerate best-effort, modular **C source** from the binary
  and flag the modules that look "main" (entry points, high complexity) —
  see [Decompile + rewrite](#decompile--rewrite) below

REA deliberately stops at classification. It does **not** generate exploit
primitives, ROP chains, shellcode, or weaponized PoCs — that step is manual,
by design.

## Decompile + rewrite

With `--decompile`, after the normal pipeline REA regenerates the binary as
C source, grouped into modules (one `.c` file per module, plus a starter
`Makefile`). This is **best-effort**: decompiled output from a stripped or
optimized binary is pseudocode and will usually need manual cleanup before
it actually compiles — REA tags every function's confidence level rather
than pretending otherwise.

```bash
python -m reverse_eng_anything.cli run ./target --decompile --src-out rea_src
```

The run then flags the modules it thinks are "main" (contain `main`/`entry0`/
similar, or have multiple functions) so you know where to start. To rewrite
one with your own changes:

```bash
python -m reverse_eng_anything.cli rewrite ./target \
  --src-dir rea_src --module parse --file my_fixed_parse.c \
  --note "added bounds check on header length"
```

This swaps your source in for that module and re-emits the source tree —
REA never writes the replacement code itself, it only manages the merge.

## Parallel OpenRouter agents (optional, cost-capped)

```bash
OPENROUTER_API_KEY=... python -m reverse_eng_anything.cli run ./target --use-agents
```

Fans out crash classification and module naming to a swarm of parallel,
token-budgeted OpenRouter calls (default model: free). Off unless you pass
`--use-agents` and set the key. Full design and cost controls in
[AGENTS.md](AGENTS.md).

## Install

```bash
pip install -r requirements.txt
# radare2 must be installed separately and on PATH: https://github.com/radareorg/radare2
```

## Run

```bash
python -m reverse_eng_anything.cli tui              # launch the TUI
python -m reverse_eng_anything.cli run ./target_bin # headless, autonomous run
```

## Layout

```
reverse_eng_anything/
  core/           intake, disasm, diff, fuzz, triage, report — the building blocks
  agent/          orchestrator.py (Agent B) + llm_advisor.py (optional summaries)
  tui/            Textual-based red-team console UI
tests/            pytest suite
```
