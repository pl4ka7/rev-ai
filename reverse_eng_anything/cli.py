"""CLI entry point: `python -m reverse_eng_anything.cli {tui|run} ...`"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent.orchestrator import Orchestrator, RunConfig
from .core.rewrite import RewriteSession


def _run_headless(args: argparse.Namespace) -> int:
    orchestrator = Orchestrator()
    config = RunConfig(
        target=Path(args.target),
        reference=Path(args.reference) if args.reference else None,
        harness=Path(args.harness) if args.harness else None,
        seed_dir=Path(args.seeds) if args.seeds else None,
        fuzz_timeout_seconds=args.fuzz_timeout,
        report_path=Path(args.out),
        decompile=args.decompile,
        decompile_out_dir=Path(args.src_out),
        use_agents=args.use_agents,
        agent_max_total_tokens=args.agent_token_budget,
        agent_max_calls=args.agent_call_budget,
    )
    run_report = orchestrator.run(config)
    for line in orchestrator.log:
        print(line)
    print(f"\nreport written to {config.report_path}")

    if config.decompile and orchestrator.last_decompiled_project:
        session = RewriteSession(project=orchestrator.last_decompiled_project)
        flagged = session.flagged_main_modules()
        print(f"\nmain modules flagged for review ({len(flagged)}):")
        for m in flagged:
            print(f"  - {m.name}  ({len(m.functions)} function(s))")
        print(
            "\nrewrite a module with:\n"
            f"  python -m reverse_eng_anything.cli rewrite {config.target} "
            f"--src-dir {config.decompile_out_dir} --module <name> --file <your_replacement.c>"
        )
    return 0 if run_report else 1


def _run_rewrite(args: argparse.Namespace) -> int:
    """Re-opens a prior decompile output and applies an analyst-supplied
    replacement for one module, then re-emits the source tree."""
    from .core.decompile import DecompiledProject, FunctionSource, ModuleSource

    src_dir = Path(args.src_dir)
    module_file = src_dir / f"{args.module}.c"
    if not module_file.is_file():
        print(f"no such module file: {module_file}")
        return 1

    original = module_file.read_text()
    replacement = Path(args.file).read_text()

    # Rebuild a minimal in-memory project around just this module so
    # RewriteSession can do the merge-and-rewrite without needing r2 again.
    project = DecompiledProject(
        source_dir=src_dir,
        modules=[ModuleSource(
            name=args.module,
            functions=[FunctionSource(name=args.module, offset=0, c_source=original)],
        )],
    )
    session = RewriteSession(project=project)
    session.propose_rewrite(args.module, replacement, note=args.note or "")
    session.apply(args.module)
    out_dir = session.commit_to_disk()
    print(session.diff_summary())
    print(f"\nupdated {module_file} under {out_dir} — review before rebuilding (see Makefile there)")
    return 0


def _run_tui(_: argparse.Namespace) -> int:
    from .tui.app import main as tui_main

    tui_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rea", description="Reverse Eng Anything")
    sub = parser.add_subparsers(dest="command", required=True)

    tui_p = sub.add_parser("tui", help="launch the interactive console")
    tui_p.set_defaults(func=_run_tui)

    run_p = sub.add_parser("run", help="headless autonomous run")
    run_p.add_argument("target", help="path to the target binary")
    run_p.add_argument("--reference", help="prior version of the binary, to diff against")
    run_p.add_argument("--harness", help="AFL++-instrumented harness to fuzz")
    run_p.add_argument("--seeds", help="seed corpus directory for fuzzing")
    run_p.add_argument("--fuzz-timeout", type=int, default=300)
    run_p.add_argument("--out", default="rea_report.md")
    run_p.add_argument(
        "--decompile", action="store_true",
        help="regenerate best-effort, recompilable-ish C source at the end of the run",
    )
    run_p.add_argument("--src-out", default="rea_src", help="output dir for --decompile")
    run_p.add_argument(
        "--use-agents", action="store_true",
        help="fan out crash-classification / module-naming to parallel OpenRouter agents "
        "(needs OPENROUTER_API_KEY; defaults to a free model, see agent/openrouter_client.py)",
    )
    run_p.add_argument("--agent-token-budget", type=int, default=20_000,
                        help="hard ceiling on total tokens spent across all agent calls this run")
    run_p.add_argument("--agent-call-budget", type=int, default=50,
                        help="hard ceiling on number of agent calls this run")
    run_p.set_defaults(func=_run_headless)

    rewrite_p = sub.add_parser("rewrite", help="rewrite one flagged module after a --decompile run")
    rewrite_p.add_argument("target", help="original binary path (kept for context/logging)")
    rewrite_p.add_argument("--src-dir", required=True, help="output dir from a prior --decompile run")
    rewrite_p.add_argument("--module", required=True, help="module name to rewrite, e.g. 'parse'")
    rewrite_p.add_argument("--file", required=True, help="path to your replacement C source for the module")
    rewrite_p.add_argument("--note", default="", help="optional note describing the change")
    rewrite_p.set_defaults(func=_run_rewrite)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
