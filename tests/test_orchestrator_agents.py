from pathlib import Path

from reverse_eng_anything.agent.orchestrator import Orchestrator, RunConfig
from reverse_eng_anything.core.disasm import Disassembler, DisasmResult


class _FakeDisassembler(Disassembler):
    def __init__(self):
        pass

    def analyze(self, path):
        return DisasmResult(binary=Path(path), functions=[], strings_count=0, imports=[])


def test_agents_skipped_without_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    target = tmp_path / "t.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 10)

    orchestrator = Orchestrator(disassembler=_FakeDisassembler())
    orchestrator.run(RunConfig(target=target, report_path=tmp_path / "r.md", use_agents=True))

    assert any("OPENROUTER_API_KEY not set" in line for line in orchestrator.log)


def test_agents_off_by_default(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 10)

    orchestrator = Orchestrator(disassembler=_FakeDisassembler())
    orchestrator.run(RunConfig(target=target, report_path=tmp_path / "r.md"))

    assert not any("[agents]" in line for line in orchestrator.log)
