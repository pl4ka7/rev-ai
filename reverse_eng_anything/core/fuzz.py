"""Drives an existing fuzzer (AFL++) against a harness supplied by the analyst.

REA does not write harnesses or fuzzing targets for you — you provide a
compiled AFL++-instrumented harness and a seed corpus. This module manages
the run and collects the crashing inputs it produces for triage.py.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FuzzRunResult:
    crashes_dir: Path
    num_crashes: int
    executions: int = 0
    raw_stats: dict = field(default_factory=dict)


class AflRunner:
    """Thin wrapper around the `afl-fuzz` binary. Mockable via runner=."""

    def __init__(self, afl_bin: str = "afl-fuzz", runner=None):
        self.afl_bin = afl_bin
        self._runner = runner or subprocess.run

    def run(
        self,
        harness: str | Path,
        seed_dir: str | Path,
        out_dir: str | Path,
        timeout_seconds: int = 300,
    ) -> FuzzRunResult:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.afl_bin,
            "-i", str(seed_dir),
            "-o", str(out_dir),
            "-V", str(timeout_seconds),
            "--",
            str(harness),
            "@@",
        ]
        self._runner(cmd, capture_output=True, text=True, timeout=timeout_seconds + 30)

        crashes_dir = out_dir / "default" / "crashes"
        num_crashes = 0
        if crashes_dir.is_dir():
            num_crashes = sum(1 for f in crashes_dir.iterdir() if f.name != "README.txt")

        stats = self._parse_stats(out_dir / "default" / "fuzzer_stats")
        return FuzzRunResult(
            crashes_dir=crashes_dir,
            num_crashes=num_crashes,
            executions=int(stats.get("execs_done", 0)),
            raw_stats=stats,
        )

    @staticmethod
    def _parse_stats(stats_path: Path) -> dict:
        if not stats_path.is_file():
            return {}
        out = {}
        for line in stats_path.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out
