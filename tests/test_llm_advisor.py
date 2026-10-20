from pathlib import Path

from reverse_eng_anything.agent import llm_advisor
from reverse_eng_anything.agent.openrouter_client import OpenRouterClient, TokenBudget
from reverse_eng_anything.core.decompile import FunctionSource, ModuleSource
from reverse_eng_anything.core.triage import CrashClassification


class _FakeResponse:
    def __init__(self, text, tokens):
        self._text, self._tokens = text, tokens

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._text}}], "usage": {"total_tokens": self._tokens}}


class _FakeSession:
    def __init__(self):
        self.calls = 0
        self.last_payload = None

    def post(self, *_a, json=None, **_kw):
        self.calls += 1
        self.last_payload = json
        return _FakeResponse("buffer overflow in parser", 12)


def test_classify_crashes_pool_uses_minimal_prompt():
    session = _FakeSession()
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget())
    crash = CrashClassification(
        crash_input=Path("c1"), signal="SIGSEGV", fault_type="write", region_guess="stack",
        raw_backtrace="a very long backtrace " * 200,  # must NOT end up in the prompt
    )

    results = llm_advisor.classify_crashes_pool([crash], client=client)

    assert results[0].text == "buffer overflow in parser"
    sent_prompt = session.last_payload["messages"][-1]["content"]
    assert "SIGSEGV" in sent_prompt
    assert "very long backtrace" not in sent_prompt  # full backtrace deliberately excluded


def test_name_modules_pool_caps_source_sent():
    session = _FakeSession()
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget())
    module = ModuleSource(name="parse", functions=[
        FunctionSource(name="parse_header", offset=1, c_source="x" * 5000)
    ])

    results = llm_advisor.name_modules_pool([module], client=client)

    assert results[0].text == "buffer overflow in parser"
    sent_prompt = session.last_payload["messages"][-1]["content"]
    assert len(sent_prompt) <= 400


def test_summarize_report_truncates_input():
    from reverse_eng_anything.core.intake import BinaryInfo
    from reverse_eng_anything.core.report import RunReport

    session = _FakeSession()
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget())
    info = BinaryInfo(path=Path("x"), size_bytes=1, sha256="a" * 64, file_type="ELF", arch="x86-64", fmt="ELF")
    report = RunReport(binary_info=info)

    summary = llm_advisor.summarize_report(report, client=client)

    assert summary == "buffer overflow in parser"
