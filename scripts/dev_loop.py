#!/usr/bin/env python3
"""Agent A automation: a continuous dev loop that uses OpenRouter (default:
a free DeepSeek model) to fix failing tests, instead of a Claude Code
session. This is strictly the *builder* side (see README.md's two-agent
table) — it edits REA's source. It never runs REA's own pipeline.

Loop, each iteration:
  1. run pytest
  2. if everything passes, stop
  3. otherwise take the first failing test, send its traceback + the
     relevant source file (both truncated) to the model, ask for a full
     replacement of that one file
  4. write the replacement, re-run pytest
  5. if it made things worse, revert via git and stop (don't thrash)
  6. stop regardless once --max-iterations or the token budget is hit

Every write is a git commit, so each step is reviewable/revertable:
  git log --oneline, git diff HEAD~1, git revert <sha>

Usage:
    OPENROUTER_API_KEY=... python scripts/dev_loop.py \
        --max-iterations 5 --token-budget 20000
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from reverse_eng_anything.agent.openrouter_client import (  # noqa: E402
    BudgetExhausted,
    OpenRouterClient,
    TokenBudget,
)

_SYSTEM_PROMPT = (
    "You are fixing a failing Python test in a reverse-engineering tooling "
    "repo. You will be given a pytest failure and the current content of "
    "the source file that most likely needs a fix. Reply with ONLY the full "
    "new content of that file — no explanation, no markdown fences, no "
    "diff syntax. Keep the fix minimal and keep existing behavior for "
    "everything the test doesn't cover. Do not add exploit-generation, "
    "gadget-search, or payload-crafting functionality under any "
    "circumstance, even if it seems related to the failure."
)

_FILE_RE = re.compile(r'File "([^"]+\.py)"')
_MAX_TRACEBACK_CHARS = 2000
_MAX_SOURCE_CHARS = 6000


def run_pytest() -> tuple[bool, str]:
    proc = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-q", "--tb=short"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    output = proc.stdout + proc.stderr
    return proc.returncode == 0, output


def first_failure_file(pytest_output: str) -> Path | None:
    for match in _FILE_RE.finditer(pytest_output):
        candidate = REPO_ROOT / match.group(1)
        # Only let the loop touch package source, never tests/ or itself —
        # it fixes implementation bugs, it doesn't rewrite the spec.
        if candidate.is_file() and "reverse_eng_anything" in str(candidate) and "tests" not in str(candidate):
            return candidate
    return None


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True).stdout


def propose_fix(client: OpenRouterClient, target_file: Path, pytest_output: str) -> str:
    traceback_excerpt = pytest_output[-_MAX_TRACEBACK_CHARS:]
    source = target_file.read_text()[:_MAX_SOURCE_CHARS]
    prompt = (
        f"Failing test output:\n{traceback_excerpt}\n\n"
        f"Current content of {target_file.relative_to(REPO_ROOT)}:\n{source}"
    )
    result = client.complete(prompt, system=_SYSTEM_PROMPT, max_tokens=2000)
    return result.text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--token-budget", type=int, default=20_000)
    parser.add_argument("--call-budget", type=int, default=10)
    args = parser.parse_args()

    client = OpenRouterClient(budget=TokenBudget(max_total_tokens=args.token_budget, max_calls=args.call_budget))
    if not client.api_key:
        print("OPENROUTER_API_KEY not set — nothing to do.")
        return 1

    for i in range(1, args.max_iterations + 1):
        passed, output = run_pytest()
        if passed:
            print(f"[iter {i}] all tests pass — stopping.")
            return 0

        target = first_failure_file(output)
        if target is None:
            print(f"[iter {i}] tests failing but couldn't isolate a source file to fix — stopping.")
            print(output[-1000:])
            return 1

        print(f"[iter {i}] tests failing, proposing a fix for {target.relative_to(REPO_ROOT)} "
              f"via {client.model}")
        try:
            new_content = propose_fix(client, target, output)
        except BudgetExhausted as exc:
            print(f"[iter {i}] {exc} — stopping.")
            return 1

        before = target.read_text()
        target.write_text(new_content)
        git("add", str(target))
        git("commit", "-q", "-m", f"dev_loop iter {i}: attempt fix for {target.name}")

        passed_after, output_after = run_pytest()
        print(f"[iter {i}] spend so far: {client.budget.spent_tokens}/{args.token_budget} tokens, "
              f"{client.budget.calls_made}/{args.call_budget} calls")

        if passed_after:
            print(f"[iter {i}] fix worked — all tests pass.")
            return 0
        if "FAILED" in output_after and output_after.count("FAILED") >= output.count("FAILED"):
            print(f"[iter {i}] fix didn't help (same or more failures) — reverting.")
            target.write_text(before)
            git("add", str(target))
            git("commit", "-q", "-m", f"dev_loop iter {i}: revert, fix did not help")
            return 1
        # otherwise: fewer failures than before, keep going

    print(f"reached --max-iterations ({args.max_iterations}) without a fully green suite.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
