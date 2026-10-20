from pathlib import Path

import pytest

from reverse_eng_anything.core.intake import intake


def test_intake_basic(tmp_path: Path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    info = intake(target)

    assert info.size_bytes == 64
    assert len(info.sha256) == 64
    assert info.path == target


def test_intake_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        intake(tmp_path / "does_not_exist.bin")


def test_intake_sha256_is_deterministic(tmp_path: Path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"consistent content")

    info_a = intake(target)
    info_b = intake(target)

    assert info_a.sha256 == info_b.sha256
