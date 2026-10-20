"""Flags the main modules of a decompiled project and lets an analyst swap in
hand-written replacements, then re-emits a buildable source tree.

This is an editing interface, not a code generator: REA proposes which
modules look like "main" ones (heuristic below), the analyst supplies the
replacement C source, and this module merges it back in. Nothing here writes
functional code on its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .decompile import DecompiledProject, ModuleSource, write_project

# Functions whose presence usually means "this module does something a
# library stub wouldn't" — a cheap, inspectable signal for flagging.
_MAIN_SIGNAL_NAMES = {"main", "entry0", "init", "start", "run", "process", "handle"}


@dataclass
class RewriteRecord:
    module_name: str
    original_source: str
    new_source: str
    note: str = ""


@dataclass
class RewriteSession:
    project: DecompiledProject
    records: list[RewriteRecord] = field(default_factory=list)

    def flagged_main_modules(self) -> list[ModuleSource]:
        """Heuristic: a module is 'main' if it has >=2 functions, or contains
        a function whose name matches a common entry/control-flow signal, or
        is simply named 'core' (the catch-all bucket from grouping).
        """
        flagged = []
        for module in self.project.modules:
            has_signal = any(
                fn.name.split(".")[-1] in _MAIN_SIGNAL_NAMES for fn in module.functions
            )
            if has_signal or len(module.functions) >= 2 or module.name == "core":
                module.is_main_module = True
                flagged.append(module)
        return flagged

    def propose_rewrite(self, module_name: str, new_source: str, note: str = "") -> RewriteRecord:
        module = self.project.module_by_name(module_name)
        if module is None:
            raise KeyError(f"no such module: {module_name}")
        record = RewriteRecord(
            module_name=module_name,
            original_source=module.c_source,
            new_source=new_source,
            note=note,
        )
        self.records.append(record)
        return record

    def apply(self, module_name: str) -> None:
        """Commits the latest proposed rewrite for a module into the project
        in memory (does not touch disk — call `commit_to_disk` for that).
        """
        matching = [r for r in self.records if r.module_name == module_name]
        if not matching:
            raise KeyError(f"no pending rewrite proposed for module: {module_name}")
        latest = matching[-1]
        module = self.project.module_by_name(module_name)
        assert module is not None
        # Replace the module's rendered source wholesale: a rewritten module
        # is edited as one unit, not function-by-function, since the analyst
        # may restructure it.
        module.functions = [
            type(module.functions[0])(
                name=f"{module_name}_rewritten",
                offset=module.functions[0].offset if module.functions else 0,
                c_source=latest.new_source,
                confidence="analyst-authored",
            )
        ]

    def commit_to_disk(self) -> Path:
        write_project(self.project)
        return self.project.source_dir

    def diff_summary(self) -> str:
        lines = [f"{len(self.records)} rewrite(s) proposed:"]
        for r in self.records:
            lines.append(
                f"  - {r.module_name}: {len(r.original_source.splitlines())} -> "
                f"{len(r.new_source.splitlines())} lines" + (f"  ({r.note})" if r.note else "")
            )
        return "\n".join(lines)
