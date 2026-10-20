from pathlib import Path

from reverse_eng_anything.core.decompile import DecompiledProject, FunctionSource, ModuleSource
from reverse_eng_anything.core.rewrite import RewriteSession


def _project(tmp_path: Path) -> DecompiledProject:
    return DecompiledProject(
        source_dir=tmp_path / "src",
        modules=[
            ModuleSource(name="parse", functions=[
                FunctionSource(name="parse_header", offset=1, c_source="void parse_header() {}")
            ]),
            ModuleSource(name="main", functions=[
                FunctionSource(name="main", offset=2, c_source="int main() { return 0; }")
            ]),
            ModuleSource(name="util", functions=[
                FunctionSource(name="util_helper", offset=3, c_source="void util_helper() {}")
            ]),
        ],
    )


def test_flags_main_modules_by_signal_name(tmp_path: Path):
    session = RewriteSession(project=_project(tmp_path))

    flagged = session.flagged_main_modules()
    names = {m.name for m in flagged}

    assert "main" in names  # contains a function literally named "main"
    assert all(m.is_main_module for m in flagged)


def test_propose_and_apply_rewrite(tmp_path: Path):
    session = RewriteSession(project=_project(tmp_path))
    new_src = "void parse_header(void) {\n    /* analyst rewrite: bounds-checked */\n}\n"

    session.propose_rewrite("parse", new_src, note="added bounds check")
    session.apply("parse")

    module = session.project.module_by_name("parse")
    assert module is not None
    assert "bounds-checked" in module.c_source
    assert module.functions[0].confidence == "analyst-authored"


def test_apply_without_proposal_raises(tmp_path: Path):
    session = RewriteSession(project=_project(tmp_path))
    try:
        session.apply("parse")
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_commit_to_disk_writes_files(tmp_path: Path):
    session = RewriteSession(project=_project(tmp_path))
    session.propose_rewrite("util", "void util_helper(void) { /* rewritten */ }", note="cleanup")
    session.apply("util")

    out_dir = session.commit_to_disk()

    assert (out_dir / "util.c").is_file()
    assert "rewritten" in (out_dir / "util.c").read_text()


def test_diff_summary_lists_proposals(tmp_path: Path):
    session = RewriteSession(project=_project(tmp_path))
    session.propose_rewrite("parse", "void parse_header(void) {}\n", note="simplify")

    summary = session.diff_summary()

    assert "1 rewrite(s) proposed" in summary
    assert "parse" in summary
    assert "simplify" in summary
