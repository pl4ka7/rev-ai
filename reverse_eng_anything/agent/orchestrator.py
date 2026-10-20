"""Agent B: the autonomous pipeline that runs *against a target binary*.

This is the "program that is an agent itself" — not to be confused with the
coding agent that writes REA's source (see AGENT_DEV.md). At runtime this
module decides, step by step, which analysis stage to run next based on what
the previous stage found, and calls out to the core/ tool wrappers to do it.

Decision policy (deliberately simple and auditable — no hidden heuristics):
  1. intake          — always
  2. disasm          — always, if r2 available
  3. diff             — only if a reference binary was supplied
  4. fuzz             — only if a harness + seed corpus were supplied
  5. triage           — only for each crash fuzz produced
  6. report           — always, last
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core import decompile as decompile_mod
from ..core import diff as diff_mod
from ..core import fuzz as fuzz_mod
from ..core import intake as intake_mod
from ..core import report as report_mod
from ..core import triage as triage_mod
from ..core.disasm import Disassembler
from . import llm_advisor
from .openrouter_client import OpenRouterClient, TokenBudget


@dataclass
class RunConfig:
    target: Path
    reference: Path | None = None  # for diffing against a prior version
    harness: Path | None = None  # AFL++-instrumented harness, if fuzzing
    seed_dir: Path | None = None
    fuzz_timeout_seconds: int = 300
    report_path: Path = Path("rea_report.md")
    decompile: bool = False  # regenerate recompilable-best-effort C source at the end
    decompile_out_dir: Path = Path("rea_src")
    use_agents: bool = False  # fan out crash-classification / module-naming to OpenRouter agents
    agent_max_total_tokens: int = 20_000
    agent_max_calls: int = 50
    agent_max_workers: int = 4


class Step:
    INTAKE = "intake"
    DISASM = "disasm"
    DIFF = "diff"
    FUZZ = "fuzz"
    TRIAGE = "triage"
    DECOMPILE = "decompile"
    REPORT = "report"


class Orchestrator:
    """Runs the pipeline, logging each decision it makes and why."""

    def __init__(
        self,
        disassembler: Disassembler | None = None,
        afl_runner: fuzz_mod.AflRunner | None = None,
        decompiler: decompile_mod.Decompiler | None = None,
    ):
        self.disassembler = disassembler or Disassembler()
        self.afl_runner = afl_runner or fuzz_mod.AflRunner()
        self.decompiler = decompiler or decompile_mod.Decompiler()
        self.log: list[str] = []
        self.last_decompiled_project: decompile_mod.DecompiledProject | None = None

    def _say(self, msg: str) -> None:
        self.log.append(msg)

    def run(self, config: RunConfig) -> report_mod.RunReport:
        self._say(f"[{Step.INTAKE}] identifying {config.target}")
        binary_info = intake_mod.intake(config.target)
        self._say(f"[{Step.INTAKE}] {binary_info.fmt}/{binary_info.arch}, sha256={binary_info.sha256[:12]}...")

        disasm_result = None
        try:
            self._say(f"[{Step.DISASM}] running static analysis")
            disasm_result = self.disassembler.analyze(config.target)
            self._say(f"[{Step.DISASM}] found {len(disasm_result.functions)} functions")
        except RuntimeError as exc:
            self._say(f"[{Step.DISASM}] skipped: {exc}")

        diff_result = None
        if config.reference is not None:
            self._say(f"[{Step.DIFF}] reference supplied, diffing against {config.reference}")
            try:
                ref_disasm = self.disassembler.analyze(config.reference)
                if disasm_result:
                    diff_result = diff_mod.diff_functions(ref_disasm, disasm_result)
                    self._say(f"[{Step.DIFF}] {diff_result.summary}")
            except RuntimeError as exc:
                self._say(f"[{Step.DIFF}] skipped: {exc}")
        else:
            self._say(f"[{Step.DIFF}] no reference binary supplied — skipping")

        crashes: list[triage_mod.CrashClassification] = []
        if config.harness and config.seed_dir:
            self._say(f"[{Step.FUZZ}] harness supplied, launching AFL++ for {config.fuzz_timeout_seconds}s")
            fuzz_result = self.afl_runner.run(
                config.harness, config.seed_dir, Path("rea_fuzz_out"), config.fuzz_timeout_seconds
            )
            self._say(f"[{Step.FUZZ}] {fuzz_result.num_crashes} crash(es) found over {fuzz_result.executions} execs")

            if fuzz_result.num_crashes and fuzz_result.crashes_dir.is_dir():
                self._say(f"[{Step.TRIAGE}] classifying {fuzz_result.num_crashes} crash(es)")
                for crash_file in sorted(fuzz_result.crashes_dir.iterdir()):
                    if crash_file.name == "README.txt":
                        continue
                    classification = triage_mod.triage_crash(config.target, crash_file)
                    crashes.append(classification)
                    self._say(
                        f"[{Step.TRIAGE}] {crash_file.name}: {classification.signal}/"
                        f"{classification.fault_type} ({classification.severity_hint})"
                    )
        else:
            self._say(f"[{Step.FUZZ}] no harness/seed corpus supplied — skipping fuzz+triage")

        if config.decompile and disasm_result:
            self._say(f"[{Step.DECOMPILE}] regenerating best-effort C source to {config.decompile_out_dir}")
            try:
                project = self.decompiler.decompile(config.target, disasm_result, config.decompile_out_dir)
                self.last_decompiled_project = project
                self._say(
                    f"[{Step.DECOMPILE}] {len(project.modules)} module(s) written — "
                    f"review before attempting to build, pseudocode is best-effort"
                )
            except RuntimeError as exc:
                self._say(f"[{Step.DECOMPILE}] skipped: {exc}")
        elif config.decompile:
            self._say(f"[{Step.DECOMPILE}] skipped: no static analysis results to decompile from")

        if config.use_agents:
            self._run_agent_pools(config, crashes)

        self._say(f"[{Step.REPORT}] writing report to {config.report_path}")
        run_report = report_mod.RunReport(
            binary_info=binary_info, disasm=disasm_result, diff=diff_result, crashes=crashes
        )
        run_report.write(config.report_path)
        return run_report

    def _run_agent_pools(self, config: RunConfig, crashes: list[triage_mod.CrashClassification]) -> None:
        """Fans out to OpenRouter agents for optional, cheap, parallel helper
        work (crash root-cause hints, module naming). Shares one TokenBudget
        across both pools so enabling this can never spend more than the
        configured ceiling, no matter how many items are processed.
        """
        client = OpenRouterClient(
            budget=TokenBudget(
                max_total_tokens=config.agent_max_total_tokens, max_calls=config.agent_max_calls
            )
        )
        if not client.api_key:
            self._say("[agents] skipped: OPENROUTER_API_KEY not set")
            return

        if crashes:
            self._say(f"[agents] classifying {len(crashes)} crash(es) via {client.model} (parallel)")
            results = llm_advisor.classify_crashes_pool(
                crashes, client=client, max_workers=config.agent_max_workers
            )
            for crash, result in zip(crashes, results):
                if result.error:
                    self._say(f"[agents] {crash.crash_input.name}: {result.error}")
                else:
                    tag = "(cached)" if result.from_cache else f"({result.tokens_used} tok)"
                    self._say(f"[agents] {crash.crash_input.name}: {result.text.strip()} {tag}")

        if self.last_decompiled_project and self.last_decompiled_project.modules:
            modules = self.last_decompiled_project.modules
            self._say(f"[agents] naming {len(modules)} module(s) via {client.model} (parallel)")
            results = llm_advisor.name_modules_pool(
                modules, client=client, max_workers=config.agent_max_workers
            )
            for module, result in zip(modules, results):
                if result.error:
                    self._say(f"[agents] module '{module.name}': {result.error}")
                else:
                    tag = "(cached)" if result.from_cache else f"({result.tokens_used} tok)"
                    self._say(f"[agents] module '{module.name}' -> suggested '{result.text.strip()}' {tag}")

        self._say(
            f"[agents] total spend: {client.budget.spent_tokens} tokens over "
            f"{client.budget.calls_made} call(s)"
        )
