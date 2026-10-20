"""Crash triage: classification only.

Given a crashing input (and optionally a gdb backtrace), this module answers
"what kind of crash is this" — signal, fault type, rough region — so a human
analyst can prioritize which crashes are worth deeper manual work.

Out of scope by design: this module never produces exploit primitives
(no gadget search, no controlled-offset calculation, no shellcode, no PoC
generation). It stops at classification.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CrashClassification:
    crash_input: Path
    signal: str = "unknown"
    fault_type: str = "unknown"  # read | write | exec | unknown
    faulting_instruction: str | None = None
    region_guess: str = "unknown"  # stack | heap | unknown
    severity_hint: str = "needs-review"  # informational only, never "exploitable"
    raw_backtrace: str = ""


_SIGNAL_RE = re.compile(r"Program received signal (SIG\w+)")
_FAULT_ADDR_RE = re.compile(r"(read|write) of (size|address) ")
_STACK_HINT_RE = re.compile(r"\b(rsp|esp|stack)\b", re.IGNORECASE)
_HEAP_HINT_RE = re.compile(r"\b(malloc|free|heap|chunk)\b", re.IGNORECASE)


def classify_from_gdb_backtrace(crash_input: str | Path, backtrace: str) -> CrashClassification:
    """Classify a crash from a gdb/lldb-style backtrace (caller runs gdb; we just parse)."""
    result = CrashClassification(crash_input=Path(crash_input), raw_backtrace=backtrace)

    sig_match = _SIGNAL_RE.search(backtrace)
    if sig_match:
        result.signal = sig_match.group(1)

    fault_match = _FAULT_ADDR_RE.search(backtrace)
    if fault_match:
        result.fault_type = fault_match.group(1)
    elif "SIGSEGV" in result.signal and "rip" in backtrace.lower():
        result.fault_type = "exec"

    if _STACK_HINT_RE.search(backtrace):
        result.region_guess = "stack"
    elif _HEAP_HINT_RE.search(backtrace):
        result.region_guess = "heap"

    first_line = backtrace.strip().splitlines()[0] if backtrace.strip() else ""
    result.faulting_instruction = first_line or None

    # Purely informational prioritization hint — "review sooner" vs "review later",
    # never a claim about exploitability.
    if result.fault_type in ("write", "exec"):
        result.severity_hint = "review-soon"

    return result


def run_gdb_backtrace(binary: str | Path, crash_input: str | Path, timeout: int = 30) -> str:
    """Run the crashing input once under gdb to capture a backtrace, for classification only."""
    gdb_cmds = (
        f"run < {crash_input}\n"
        "bt\n"
        "info registers\n"
        "quit\n"
    )
    try:
        proc = subprocess.run(
            ["gdb", "-batch", "-ex", gdb_cmds, str(binary)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout + proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"<gdb unavailable or timed out: {exc}>"


def triage_crash(binary: str | Path, crash_input: str | Path) -> CrashClassification:
    backtrace = run_gdb_backtrace(binary, crash_input)
    return classify_from_gdb_backtrace(crash_input, backtrace)
