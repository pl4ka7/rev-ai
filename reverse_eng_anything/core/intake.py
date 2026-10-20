"""Binary intake: hashing, format/arch detection, basic metadata.

This module performs no analysis of code semantics — just identification,
so every later stage (disasm, diff, fuzz, triage) knows what it's looking at.
"""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BinaryInfo:
    path: Path
    size_bytes: int
    sha256: str
    file_type: str  # output of `file`, e.g. "ELF 64-bit LSB executable, x86-64"
    arch: str = "unknown"
    fmt: str = "unknown"  # ELF / PE / Mach-O / unknown
    notes: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_type(path: Path) -> str:
    try:
        out = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() or "unrecognized"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unrecognized (file(1) unavailable)"


def _guess_format_arch(file_type: str) -> tuple[str, str]:
    ft = file_type.lower()
    if "elf" in ft:
        fmt = "ELF"
    elif "pe32" in ft or "ms-dos" in ft or "mz executable" in ft:
        fmt = "PE"
    elif "mach-o" in ft:
        fmt = "Mach-O"
    else:
        fmt = "unknown"

    arch = "unknown"
    for token in ("x86-64", "x86_64", "aarch64", "arm64", "arm", "i386", "mips", "risc-v"):
        if token in ft:
            arch = token
            break
    return fmt, arch


def intake(path: str | Path) -> BinaryInfo:
    """Identify a target binary without executing it."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such file: {p}")

    file_type = _file_type(p)
    fmt, arch = _guess_format_arch(file_type)
    info = BinaryInfo(
        path=p,
        size_bytes=p.stat().st_size,
        sha256=_sha256(p),
        file_type=file_type,
        arch=arch,
        fmt=fmt,
    )
    if fmt == "unknown":
        info.notes.append("could not determine executable format; downstream stages may fail")
    return info
