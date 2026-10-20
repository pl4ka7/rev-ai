from pathlib import Path

from reverse_eng_anything.core.diff import diff_functions
from reverse_eng_anything.core.disasm import DisasmResult, FunctionInfo


def _disasm(functions):
    return DisasmResult(binary=Path("x"), functions=functions)


def test_diff_detects_added_removed_changed():
    old = _disasm([
        FunctionInfo(name="parse_header", offset=0x100, size=50),
        FunctionInfo(name="legacy_only", offset=0x200, size=30),
        FunctionInfo(name="unchanged_fn", offset=0x300, size=20),
    ])
    new = _disasm([
        FunctionInfo(name="parse_header", offset=0x100, size=80),  # changed (size)
        FunctionInfo(name="unchanged_fn", offset=0x300, size=20),  # unchanged
        FunctionInfo(name="new_validator", offset=0x400, size=40),  # added
    ])

    result = diff_functions(old, new)

    assert {f.name for f in result.added} == {"new_validator"}
    assert {f.name for f in result.removed} == {"legacy_only"}
    assert {f.name for f in result.changed} == {"parse_header"}
    assert result.unchanged_count == 1


def test_diff_summary_format():
    result = diff_functions(_disasm([]), _disasm([]))
    assert "0 added" in result.summary
