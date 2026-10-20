from pathlib import Path

from reverse_eng_anything.agent.orchestrator import Orchestrator, RunConfig
from reverse_eng_anything.core.disasm import Disassembler, DisasmResult


class _FakeDisassembler(Disassembler):
    def __init__(self):
        pass  # skip r2pipe setup entirely

    def analyze(self, path):
        return DisasmResult(binary=Path(path), functions=[], strings_count=0, imports=[])


def test_orchestrator_skips_optional_stages_when_not_configured(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    report_path = tmp_path / "report.md"

    orchestrator = Orchestrator(disassembler=_FakeDisassembler())
    config = RunConfig(target=target, report_path=report_path)

    run_report = orchestrator.run(config)

    assert report_path.is_file()
    assert run_report.diff is None
    assert run_report.crashes == []
    assert any("no reference binary supplied" in line for line in orchestrator.log)
    assert any("no harness/seed corpus supplied" in line for line in orchestrator.log)


def test_orchestrator_logs_every_stage(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    orchestrator = Orchestrator(disassembler=_FakeDisassembler())
    orchestrator.run(RunConfig(target=target, report_path=tmp_path / "r.md"))

    joined = "\n".join(orchestrator.log)
    for stage in ("intake", "disasm", "diff", "fuzz", "report"):
        assert f"[{stage}]" in joined
