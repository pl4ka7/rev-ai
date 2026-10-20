"""Disassembly / analysis via radare2 (r2pipe).

Wraps `r2 -A` style auto-analysis and exposes function lists, a given
function's disassembly, and cross-references. No code is executed — r2 runs
in its static analysis mode.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import r2pipe  # type: ignore
except ImportError:  # pragma: no cover - exercised only when r2pipe missing
    r2pipe = None


@dataclass
class FunctionInfo:
    name: str
    offset: int
    size: int
    num_xrefs: int = 0


@dataclass
class DisasmResult:
    binary: Path
    functions: list[FunctionInfo] = field(default_factory=list)
    strings_count: int = 0
    imports: list[str] = field(default_factory=list)


class Disassembler:
    """Thin, mockable wrapper around r2pipe so tests don't need radare2 installed."""

    def __init__(self, r2_factory: Any = None):
        self._r2_factory = r2_factory or (r2pipe.open if r2pipe else None)

    def analyze(self, path: str | Path) -> DisasmResult:
        if self._r2_factory is None:
            raise RuntimeError(
                "r2pipe is not available — install radare2 and `pip install r2pipe`"
            )
        p = Path(path)
        r2 = self._r2_factory(str(p))
        try:
            r2.cmd("aaa")  # full auto-analysis, static only
            funcs_raw = r2.cmdj("aflj") or []
            imports_raw = r2.cmdj("iij") or []
            strings_raw = r2.cmdj("izj") or []
        finally:
            r2.quit()

        functions = [
            FunctionInfo(
                name=f.get("name", "sub_unknown"),
                offset=f.get("offset", 0),
                size=f.get("size", 0),
                num_xrefs=f.get("xrefs", {}).get("in", 0) if isinstance(f.get("xrefs"), dict) else 0,
            )
            for f in funcs_raw
        ]
        imports = [i.get("name", "") for i in imports_raw if i.get("name")]

        return DisasmResult(
            binary=p,
            functions=functions,
            strings_count=len(strings_raw),
            imports=imports,
        )

    def disassemble_function(self, path: str | Path, offset_or_name: str) -> str:
        if self._r2_factory is None:
            raise RuntimeError("r2pipe is not available")
        r2 = self._r2_factory(str(path))
        try:
            r2.cmd("aaa")
            r2.cmd(f"s {offset_or_name}")
            return r2.cmd("pdf") or ""
        finally:
            r2.quit()
