"""Red-team styled TUI for REA, built with Textual."""
from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Footer, Header, Input, Log, Static

from ..agent.orchestrator import Orchestrator, RunConfig
from ..core.rewrite import RewriteSession

BANNER = r"""
 ____  _______     __    _   _  _____   _____ _   _  ____
|  _ \| ____\ \   / /   / \ | |/ / _ \ |_   _| | | |/ ___|
| |_) |  _|  \ \ / /   / _ \|   / | | |  | | | |_| | |  _
|  _ <| |___  \ V /   / ___ \|  \ |_| |  | | |  _  | |_| |
|_| \_\_____|  \_/   /_/   \_\_|\_\___/   |_| |_| |_|\____|
            REVERSE ENG ANYTHING :: triage console
"""

CSS = """
Screen {
    background: #0a0a0a;
    color: #e0e0e0;
}
#banner {
    color: #ff2b2b;
    text-style: bold;
    content-align: center top;
    padding: 1 0;
}
#target_input {
    border: heavy #ff2b2b;
    background: #111111;
}
Button {
    background: #1a1a1a;
    color: #ff2b2b;
    border: tall #ff2b2b;
}
Button:hover {
    background: #ff2b2b;
    color: #0a0a0a;
}
#log {
    border: round #444444;
    background: #0d0d0d;
    color: #c0c0c0;
}
#status {
    color: #00ff66;
    padding: 0 1;
}
"""


class REAApp(App):
    CSS = CSS
    TITLE = "REA :: Reverse Eng Anything"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(BANNER, id="banner")
        with Vertical():
            with Horizontal():
                yield Input(placeholder="/path/to/target_binary", id="target_input")
                yield Checkbox("regenerate C source", id="decompile_check")
                yield Button("RUN", id="run_btn", variant="error")
            yield Static("status: idle", id="status")
            yield Log(id="log", highlight=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run_btn":
            self._run_pipeline()

    def _run_pipeline(self) -> None:
        target_str = self.query_one("#target_input", Input).value.strip()
        status = self.query_one("#status", Static)
        log = self.query_one("#log", Log)
        log.clear()

        if not target_str:
            status.update("status: [error] no target specified")
            return

        target = Path(target_str)
        if not target.is_file():
            status.update(f"status: [error] no such file: {target}")
            return

        decompile = self.query_one("#decompile_check", Checkbox).value
        status.update("status: running...")
        orchestrator = Orchestrator()
        try:
            run_report = orchestrator.run(RunConfig(target=target, decompile=decompile))
        except Exception as exc:  # surfaced to the analyst, not swallowed
            log.write_line(f"FATAL: {exc}")
            status.update("status: [error] run failed")
            return

        for line in orchestrator.log:
            log.write_line(line)

        if decompile and orchestrator.last_decompiled_project:
            session = RewriteSession(project=orchestrator.last_decompiled_project)
            flagged = session.flagged_main_modules()
            log.write_line("")
            log.write_line(f"-- {len(flagged)} main module(s) flagged for review --")
            for m in flagged:
                log.write_line(f"  * {m.name}  ({len(m.functions)} function(s))")
            log.write_line(
                "rewrite one with: rea rewrite <target> --src-dir "
                f"{orchestrator.last_decompiled_project.source_dir} --module <name> --file <replacement.c>"
            )

        status.update("status: done — report at rea_report.md")


def main() -> None:
    REAApp().run()


if __name__ == "__main__":
    main()
