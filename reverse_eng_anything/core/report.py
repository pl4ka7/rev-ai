"""Renders a REA run into a Markdown report for a human analyst."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .diff import DiffResult
from .disasm import DisasmResult
from .intake import BinaryInfo
from .triage import CrashClassification


@dataclass
class RunReport:
    binary_info: BinaryInfo
    disasm: DisasmResult | None = None
    diff: DiffResult | None = None
    crashes: list[CrashClassification] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_markdown(self) -> str:
        lines = [
            "# REA Analysis Report",
            f"_generated {self.generated_at.isoformat()}_",
            "",
            "## Target",
            f"- Path: `{self.binary_info.path}`",
            f"- Format / Arch: {self.binary_info.fmt} / {self.binary_info.arch}",
            f"- SHA-256: `{self.binary_info.sha256}`",
            f"- Size: {self.binary_info.size_bytes} bytes",
        ]
        if self.binary_info.notes:
            lines += ["- Notes: " + "; ".join(self.binary_info.notes)]

        if self.disasm:
            lines += [
                "",
                "## Static analysis",
                f"- Functions found: {len(self.disasm.functions)}",
                f"- Imports: {len(self.disasm.imports)}",
                f"- Strings: {self.disasm.strings_count}",
            ]

        if self.diff:
            lines += [
                "",
                "## Diff vs. reference",
                f"- {self.diff.summary}",
            ]
            if self.diff.changed:
                lines.append("- Changed functions:")
                for fd in self.diff.changed[:50]:
                    lines.append(f"  - `{fd.name}` ({fd.old_size} → {fd.new_size} bytes)")

        if self.crashes:
            lines += ["", "## Crash triage", ""]
            lines.append("| Input | Signal | Fault | Region | Priority |")
            lines.append("|---|---|---|---|---|")
            for c in self.crashes:
                lines.append(
                    f"| {c.crash_input.name} | {c.signal} | {c.fault_type} "
                    f"| {c.region_guess} | {c.severity_hint} |"
                )
            lines += [
                "",
                "_Triage is classification only. Exploit development from a "
                "flagged crash is a manual, separate step._",
            ]

        return "\n".join(lines) + "\n"

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(self.to_markdown())
        return p
