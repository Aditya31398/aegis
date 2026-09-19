"""Async kernel: `ainvoke` must be exactly as strict as `invoke`.

No pytest-asyncio dependency: each test drives its own loop with asyncio.run.
"""
from __future__ import annotations

import asyncio
import copy
import threading
from pathlib import Path

import pytest
import yaml

from aegis import Agent, Grant, Kernel, PolicyViolation, load_policy, parse_policy
from aegis.conformance import build_fixture_registry

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "policies" / "base.yaml"


def _setup(extra_tools=None, *, policy=None, **kernel_kw):
    policy = policy or load_policy(BASE)
    registry, rec = build_fixture_registry(policy)
    for name, fn in (extra_tools or {}).items():
        registry._tools.pop(name, None)
        registry.register(name, fn, effects={"read"}, classification="internal",
                          description=f"async double for {name}")
    kernel = Kernel(registry, **kernel_kw)
    return kernel, Grant.root(policy), rec


def _async_recorder(name, entered, result="async ok"):
    async def _fn(**kwargs):
        entered.append((name, kwargs))
        await asyncio.sleep(0)
        return result
    return _fn


# ----------------------------------------------------------------------
# Parity: the same decisions on both paths
# ----------------------------------------------------------------------
def test_ainvoke_allows_what_invoke_allows():
    kernel, grant, rec = _setup()
    sync = kernel.invoke(grant, "fs.read", path="/workspace/a.txt")
    result = asyncio.run(kernel.ainvoke(grant, "fs.read", path="/workspace/a.txt"))
    assert result == sync
    assert rec.count("fs.read") == 2


@pytest.mark.parametrize("tool,args,rule", [
    ("fs.read", {"path": "/etc/passwd"}, "capability.arg_prefix"),
    ("shell.exec", {"cmd": "id"}, "capability.not_granted"),
    ("agent.spawn", {}, "kernel.spawn_requires_api"),
])
def test_ainvoke_denies_what_invoke_denies_without_side_effect(tool, args, rule):
    kernel, grant, rec = _setup()
    with pytest.raises(PolicyViolation) as sync_exc:
        kernel.invoke(grant, tool, **args)
    with pytest.raises(PolicyViolation) as async_exc:
        asyncio.run(kernel.ainvoke(grant, tool, **args))
    assert sync_exc.value.verdict.rule == async_exc.value.verdict.rule == rule
    assert rec.calls == []


def test_async_post_guards_taint_the_grant():
    """A confidential read taints the grant on the async path too, so even a
    PII-free body cannot then leave through a sink."""
    kernel, grant, rec = _setup()
    assert asyncio.run(kernel.ainvoke(grant, "db.query", sql="SELECT id FROM t"))
    with pytest.raises(PolicyViolation) as exc:
        asyncio.run(kernel.ainvoke(
            grant, "http.post", url="https://api.internal.corp/v1/x",
            body="summary only"))
    assert exc.value.verdict.rule == "data.taint_egress_blocked"
    assert rec.count("http.post") == 0


def test_async_post_guards_discard_over_ceiling_result():
    raw = copy.deepcopy(yaml.safe_load(BASE.read_text(encoding="utf-8")))
    raw["data"]["max_classification"] = "internal"
    raw["data"]["egress"]["max_classification"] = "public"
    kernel, grant, rec = _setup(policy=parse_policy(raw))
    with pytest.raises(PolicyViolation) as exc:
        asyncio.run(kernel.ainvoke(grant, "db.query", sql="SELECT id FROM t"))
    assert exc.value.verdict.rule == "data.classification_exceeded"
    assert rec.count("db.query") == 1      # ran, but the result never returned


# ----------------------------------------------------------------------
# Coroutine tools
# ----------------------------------------------------------------------
def test_coroutine_tool_is_awaited_on_the_loop():
    entered: list = []
    kernel, grant, _ = _setup({"kb.search": _async_recorder("kb.search", entered)})
    assert kernel.registry.spec("kb.search").is_async
    out = asyncio.run(kernel.ainvoke(grant, "kb.search", query="x"))
    assert out == "async ok"
    assert entered == [("kb.search", {"query": "x"})]


def test_coroutine_tool_denied_on_sync_path_before_charge():
    """Sync invoke of an async tool would return an unawaited coroutine and
    skip the post-guards. It must be refused before anything is spent."""
    entered: list = []
    kernel, grant, _ = _setup({"kb.search": _async_recorder("kb.search", entered)})
    before = grant.ledger.tool_calls
    with pytest.raises(PolicyViolation) as exc:
        kernel.invoke(grant, "kb.search", query="x")
    assert exc.value.verdict.rule == "kernel.async_tool_requires_ainvoke"
    assert entered == []
    assert grant.ledger.tool_calls == before


def test_sync_tool_returning_coroutine_is_refused_on_sync_path():
    entered: list = []
    inner = _async_recorder("kb.search", entered)
    kernel, grant, _ = _setup({"kb.search": lambda **kw: inner(**kw)})
    assert not kernel.registry.spec("kb.search").is_async
    with pytest.raises(PolicyViolation) as exc:
        kernel.invoke(grant, "kb.search", query="x")
    assert exc.value.verdict.rule == "kernel.async_tool_requires_ainvoke"
    assert entered == []          # coroutine was closed, never ran
    # ...but the async path handles the same tool correctly.
    assert asyncio.run(kernel.ainvoke(grant, "kb.search", query="x")) == "async ok"


def test_callable_object_with_async_call_is_detected():
    class Tool:
        async def __call__(self, **kw):
            return "obj"
    kernel, grant, _ = _setup({"kb.search": Tool()})
    assert kernel.registry.spec("kb.search").is_async
    assert asyncio.run(kernel.ainvoke(grant, "kb.search", query="q")) == "obj"


def test_blocking_sync_tool_runs_off_the_loop():
    seen: list[str] = []

    def blocking(**kw):
        seen.append(threading.current_thread().name)
        return "done"

    kernel, grant, _ = _setup({"kb.search": blocking})

    async def main():
        loop_thread = threading.current_thread().name
        await kernel.ainvoke(grant, "kb.search", query="q")
        return loop_thread

    loop_thread = asyncio.run(main())
    assert seen and seen[0] != loop_thread


def test_dry_run_never_awaits():
    entered: list = []
    kernel, grant, _ = _setup({"kb.search": _async_recorder("kb.search", entered)},
                              dry_run=True)
    assert asyncio.run(kernel.ainvoke(grant, "kb.search", query="x")) is None
    assert entered == []


# ----------------------------------------------------------------------
# Concurrency: budgets hold under gather()
# ----------------------------------------------------------------------
def test_concurrent_calls_cannot_overspend_tool_call_budget():
    raw = copy.deepcopy(yaml.safe_load(BASE.read_text(encoding="utf-8")))
    raw["budget"]["tool_calls"] = 5
    policy = parse_policy(raw)
    entered: list = []
    kernel, grant, _ = _setup({"kb.search": _async_recorder("kb.search", entered)},
                              policy=policy)

    async def main():
        return await asyncio.gather(
            *(kernel.ainvoke(grant, "kb.search", query=str(i)) for i in range(20)),
            return_exceptions=True)

    results = asyncio.run(main())
    ok = [r for r in results if r == "async ok"]
    denied = [r for r in results if isinstance(r, PolicyViolation)]
    assert len(ok) == 5 == len(entered)
    assert len(denied) == 15
    assert {d.verdict.rule for d in denied} == {"budget.tool_calls_exceeded"}
    assert kernel.audit.verify()


def test_sibling_swarm_cannot_outspend_root_concurrently():
    raw = copy.deepcopy(yaml.safe_load(BASE.read_text(encoding="utf-8")))
    raw["budget"]["tool_calls"] = 12
    policy = parse_policy(raw)
    kernel, grant, rec = _setup(policy=policy)
    root = Agent(grant, kernel)

    async def main():
        kids = [await root.aspawn(f"w{i}", ["kb.search"], budget_fraction=1.0)
                for i in range(3)]
        calls = [k.atools.kb__search(query="q") for k in kids for _ in range(10)]
        return await asyncio.gather(*calls, return_exceptions=True)

    results = asyncio.run(main())
    succeeded = [r for r in results if not isinstance(r, BaseException)]
    # 3 spawns + successful tool calls may never exceed the root's 12.
    assert 3 + len(succeeded) <= 12
    assert rec.count("kb.search") == len(succeeded)
    assert all(isinstance(r, PolicyViolation) for r in results
               if isinstance(r, BaseException))


# ----------------------------------------------------------------------
# Runtime surface
# ----------------------------------------------------------------------
def test_async_toolbox_exposes_no_callable():
    kernel, grant, _ = _setup()
    agent = Agent(grant, kernel)
    proxy = agent.atools["fs.read"]
    assert not hasattr(proxy, "fn")
    with pytest.raises(AttributeError):
        agent.atools._kernel_impl       # private names never become proxies
    assert asyncio.run(agent.atools.fs__read(path="/workspace/a")) == \
        "workspace file contents"


# ----------------------------------------------------------------------
# Async fuzzing: invariants re-checked while calls are in flight
# ----------------------------------------------------------------------
from aegis.conformance import afuzz  # noqa: E402


@pytest.mark.parametrize("seed", range(6))
def test_invariants_hold_under_async_fuzz(seed):
    violations = afuzz(load_policy(BASE), rounds=40, batch=12, seed=seed)
    assert not violations, [f"{v.invariant}: {v.detail}" for v in violations]


class _CheckThenChargeKernel(Kernel):
    """Planted bug: checks the budget, awaits the tool, charges afterwards.
    Sequentially this is indistinguishable from the real kernel; under
    concurrency every in-flight call passes the same stale check."""

    async def ainvoke(self, grant, tool, /, **args):
        ledger = grant.ledger
        ledger.charge = ledger.check            # admit without reserving
        try:
            spec, call = self._admit(grant, tool, args, is_async=True)
        finally:
            del ledger.charge
        result = await self._aexecute(spec, call)
        ledger.charge(usd=call.est_usd, tokens=call.est_tokens, calls=1)
        return self._release(grant, call, result)


def _tight_policy():
    raw = copy.deepcopy(yaml.safe_load(BASE.read_text(encoding="utf-8")))
    raw["budget"]["tool_calls"] = 30
    return parse_policy(raw)


def test_async_fuzz_catches_check_then_charge_race():
    """Negative control: a kernel that charges *after* awaiting the tool lets
    an effect exist unpaid-for. The fuzzer must find it on most seeds."""
    caught = sum(
        any(v.invariant == "every_effect_was_charged"
            for v in afuzz(_tight_policy(), rounds=20, batch=12, seed=s,
                           kernel_factory=_CheckThenChargeKernel))
        for s in range(6))
    assert caught >= 4, f"planted race found on only {caught}/6 seeds"


def test_fuzz_workload_reaches_budget_exhaustion():
    """The fuzzer is only as good as the states it reaches. If the workload
    stops admitting calls (e.g. a policy tightening makes every benign call
    fail), budget invariants go vacuously green. Guard against that."""
    from aegis.conformance import invariants as inv
    made = []

    def factory(reg):
        made.append(Kernel(reg))
        return made[-1]

    assert not afuzz(_tight_policy(), rounds=20, batch=12, seed=0,
                     kernel_factory=factory)
    rules = {r.rule for r in made[0].audit.records}
    assert "budget.tool_calls_exceeded" in rules
    assert inv._BENIGN_CALLS and all(t in load_policy(BASE).tool_names
                                     for t, _ in inv._BENIGN_CALLS)
