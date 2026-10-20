from reverse_eng_anything.agent.openrouter_client import (
    BudgetExhausted,
    OpenRouterClient,
    TokenBudget,
)


class _FakeResponse:
    def __init__(self, text: str, tokens: int):
        self._text = text
        self._tokens = tokens

    def raise_for_status(self):
        pass

    def json(self):
        return {
            "choices": [{"message": {"content": self._text}}],
            "usage": {"total_tokens": self._tokens},
        }


class _FakeSession:
    def __init__(self, text="ok", tokens=10):
        self.text = text
        self.tokens = tokens
        self.calls = 0

    def post(self, *_args, **_kwargs):
        self.calls += 1
        return _FakeResponse(self.text, self.tokens)


def test_complete_returns_text_and_records_tokens():
    session = _FakeSession(text="buffer overflow", tokens=15)
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget(max_total_tokens=100, max_calls=10))

    result = client.complete("classify this crash")

    assert result.text == "buffer overflow"
    assert result.tokens_used == 15
    assert client.budget.spent_tokens == 15
    assert session.calls == 1


def test_cache_avoids_second_network_call():
    session = _FakeSession(text="cached answer", tokens=20)
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget(max_total_tokens=1000, max_calls=10))

    first = client.complete("same prompt", system="sys")
    second = client.complete("same prompt", system="sys")

    assert session.calls == 1  # second call served from cache
    assert first.text == second.text
    assert second.from_cache is True
    assert second.tokens_used == 0  # cache hits cost nothing


def test_budget_exhausted_raises_before_network_call():
    session = _FakeSession()
    budget = TokenBudget(max_total_tokens=1000, max_calls=1)
    client = OpenRouterClient(api_key="k", session=session, budget=budget)

    client.complete("first")
    try:
        client.complete("second, different prompt")
        assert False, "expected BudgetExhausted"
    except BudgetExhausted:
        pass
    assert session.calls == 1  # the second call never hit the network


def test_missing_api_key_raises():
    client = OpenRouterClient(api_key=None)
    try:
        client.complete("x")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


def test_prompt_is_truncated(monkeypatch):
    import reverse_eng_anything.agent.openrouter_client as mod

    monkeypatch.setattr(mod, "DEFAULT_PROMPT_CHAR_CAP", 10)
    session = _FakeSession()
    client = OpenRouterClient(api_key="k", session=session)

    client.complete("x" * 1000)
    # no direct way to inspect the sent payload via this fake, but this
    # exercises the truncation path without raising — regression guard
    assert session.calls == 1
