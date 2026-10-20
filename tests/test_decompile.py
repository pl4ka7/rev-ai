from pathlib import Path

from reverse_eng_anything.core.decompile import (
    Decompiler,
    group_into_modules,
    write_project,
)
from reverse_eng_anything.core.disasm import DisasmResult, FunctionInfo


def test_group_into_modules_by_prefix():
    functions = [
        FunctionInfo(name="parse_header", offset=1, size=10),
        FunctionInfo(name="parse_body", offset=2, size=10),
        FunctionInfo(name="validate_input", offset=3, size=10),
        FunctionInfo(name="entry0", offset=4, size=10),
        FunctionInfo(name="sym.imp.memcpy", offset=5, size=10),
    ]

    groups = group_into_modules(functions)

    assert {f.name for f in groups["parse"]} == {"parse_header", "parse_body"}
    assert [f.name for f in groups["validate"]] == ["validate_input"]
    assert [f.name for f in groups["core"]] == ["entry0"]  # no underscore -> core bucket
    assert "sym.imp.memcpy" not in {f.name for g in groups.values() for f in g}


class _FakeR2:
    def __init__(self, *_args, **_kwargs):
        self.calls = []

    def cmd(self, c):
        self.calls.append(c)
        if c.startswith("pdg"):
            return "void parse_header() { /* fake decompiled body */ }"
        return ""

    def quit(self):
        pass


def test_decompiler_writes_modules(tmp_path: Path):
    disasm = DisasmResult(
        binary=Path("x"),
        functions=[FunctionInfo(name="parse_header", offset=0x100, size=10)],
    )
    decompiler = Decompiler(r2_factory=lambda path: _FakeR2())

    project = decompiler.decompile("fake_binary", disasm, tmp_path / "src")

    assert len(project.modules) == 1
    assert project.modules[0].name == "parse"
    c_file = tmp_path / "src" / "parse.c"
    assert c_file.is_file()
    assert "fake decompiled body" in c_file.read_text()
    assert (tmp_path / "src" / "Makefile").is_file()


def test_decompiler_requires_r2pipe_when_unavailable(monkeypatch):
    import reverse_eng_anything.core.decompile as decompile_mod

    monkeypatch.setattr(decompile_mod, "r2pipe", None)
    decompiler = decompile_mod.Decompiler(r2_factory=None)
    disasm = DisasmResult(binary=Path("x"), functions=[])

    try:
        decompiler.decompile("x", disasm, "out")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
