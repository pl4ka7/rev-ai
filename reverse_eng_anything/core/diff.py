"""Function-level binary diffing between two versions of a target.

Matches functions by name (fallback: by size+xref signature) and flags which
ones changed, were added, or removed — typical patch-diffing workflow for
understanding what a security patch touched. Produces a change list for a
human to prioritize; it does not infer *why* a function changed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .disasm import DisasmResult, FunctionInfo


@dataclass
class FunctionDiff:
    name: str
    status: str  # "added" | "removed" | "changed" | "unchanged"
    old_size: int | None = None
    new_size: int | None = None


@dataclass
class DiffResult:
    added: list[FunctionDiff] = field(default_factory=list)
    removed: list[FunctionDiff] = field(default_factory=list)
    changed: list[FunctionDiff] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def summary(self) -> str:
        return (
            f"{len(self.added)} added, {len(self.removed)} removed, "
            f"{len(self.changed)} changed, {self.unchanged_count} unchanged"
        )


def _index(functions: list[FunctionInfo]) -> dict[str, FunctionInfo]:
    return {f.name: f for f in functions}


def diff_functions(old: DisasmResult, new: DisasmResult) -> DiffResult:
    old_idx = _index(old.functions)
    new_idx = _index(new.functions)

    result = DiffResult()
    for name, old_f in old_idx.items():
        if name not in new_idx:
            result.removed.append(FunctionDiff(name=name, status="removed", old_size=old_f.size))
            continue
        new_f = new_idx[name]
        if old_f.size != new_f.size or old_f.num_xrefs != new_f.num_xrefs:
            result.changed.append(
                FunctionDiff(name=name, status="changed", old_size=old_f.size, new_size=new_f.size)
            )
        else:
            result.unchanged_count += 1

    for name, new_f in new_idx.items():
        if name not in old_idx:
            result.added.append(FunctionDiff(name=name, status="added", new_size=new_f.size))

    return result
