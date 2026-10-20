from pathlib import Path

from reverse_eng_anything.core.intake import BinaryInfo
from reverse_eng_anything.core.report import RunReport
from reverse_eng_anything.core.triage import CrashClassification


def test_report_renders_markdown(tmp_path: Path):
    info = BinaryInfo(
        path=Path("/bin/target"),
        size_bytes=1024,
        sha256="a" * 64,
        file_type="ELF 64-bit",
        arch="x86-64",
        fmt="ELF",
    )
    crash = CrashClassification(
        crash_input=Path("crash-001"),
        signal="SIGSEGV",
        fault_type="write",
        region_guess="stack",
        severity_hint="review-soon",
    )
    report = RunReport(binary_info=info, crashes=[crash])

    md = report.to_markdown()

    assert "REA Analysis Report" in md
    assert "a" * 64 in md
    assert "SIGSEGV" in md
    assert "manual, separate step" in md


def test_report_write_creates_file(tmp_path: Path):
    info = BinaryInfo(
        path=Path("/bin/target"), size_bytes=1, sha256="b" * 64,
        file_type="ELF", arch="x86-64", fmt="ELF",
    )
    report = RunReport(binary_info=info)
    out = tmp_path / "out.md"

    report.write(out)

    assert out.is_file()
    assert "REA Analysis Report" in out.read_text()
