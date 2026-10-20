from reverse_eng_anything.agent.agent_pool import run_pool
from reverse_eng_anything.agent.openrouter_client import OpenRouterClient, TokenBudget


class _FakeResponse:
    def __init__(self, text, tokens):
        self._text, self._tokens = text, tokens

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._text}}], "usage": {"total_tokens": self._tokens}}


class _FakeSession:
    def __init__(self, tokens_per_call=5):
        self.tokens_per_call = tokens_per_call
        self.calls = 0

    def post(self, *_a, **_kw):
        self.calls += 1
        return _FakeResponse(f"result-{self.calls}", self.tokens_per_call)


def test_run_pool_processes_all_items_in_order():
    session = _FakeSession()
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget(max_total_tokens=1000, max_calls=10))
    items = ["a", "b", "c"]

    results = run_pool(client, items, prompt_fn=lambda x: x, max_workers=3)

    assert [r.item for r in results] == items
    assert all(r.error is None for r in results)
    assert session.calls == 3


def test_run_pool_shares_budget_across_workers():
    session = _FakeSession(tokens_per_call=50)
    client = OpenRouterClient(api_key="k", session=session, budget=TokenBudget(max_total_tokens=120, max_calls=10))
    items = list(range(5))  # 5 items * 50 tokens = 250 > 120 budget

    results = run_pool(client, items, prompt_fn=lambda x: str(x), max_workers=5)

    succeeded = [r for r in results if r.error is None]
    failed = [r for r in results if r.error is not None]
    assert len(succeeded) <= 3  # budget caps total calls well before all 5 run
    assert len(failed) >= 1
    assert client.budget.spent_tokens <= 150  # never overshoots by more than one in-flight call


def test_run_pool_reports_errors_without_crashing():
    class _BrokenSession(_FakeSession):
        def post(self, *_a, **_kw):
            raise ConnectionError("network down")

    client = OpenRouterClient(api_key="k", session=_BrokenSession(), budget=TokenBudget())

    results = run_pool(client, ["x"], prompt_fn=lambda x: x)

    assert results[0].error is not None
    assert "network down" in results[0].error
