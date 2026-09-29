"""Kernel.restrict: take authority away from a grant already in use, without revoking it.

The grant keeps working with what is left. It may only ever narrow -- tools, budget, the whole subtree --
and every invariant the fuzzers check must still hold after it."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis import Grant, Kernel, PolicyViolation, SpawnRequest, ToolRegistry, load_policy
from aegis.conformance.invariants import INVARIANTS, afuzz, fuzz
from aegis.conformance.fixtures import build_fixture_registry
from aegis.policy import PolicyError

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "policies" / "base.yaml"


def _kernel():
    policy = load_policy(BASE)
    registry = ToolRegistry()
    for name in ("kb.search", "fs.read", "fs.write", "http.get", "http.post", "db.query"):
        registry.register(name, lambda **kw: "ok", effects={"read"})
    return Kernel(registry), Grant.root(policy, "root")


def test_a_restricted_tool_is_refused_and_the_rest_keep_working():
    kernel, root = _kernel()
    assert kernel.invoke(root, "fs.read", path="/workspace/a.md") == "ok"
    kernel.restrict(root, remove={"fs.read"}, reason="probing fs.read")
    with pytest.raises(PolicyViolation) as exc:
        kernel.invoke(root, "fs.read", path="/workspace/a.md")
    assert exc.value.verdict.rule == "capability.not_granted"
    assert kernel.invoke(root, "kb.search", query="q") == "ok"
    assert root.is_active(), "restricted, not revoked"


def test_the_whole_subtree_loses_it_and_cannot_spawn_it_back():
    kernel, root = _kernel()
    child = kernel.spawn(root, SpawnRequest("researcher", frozenset({"kb.search", "fs.read"}), budget_fraction=0.4))
    kernel.restrict(root, remove={"fs.read"})
    assert "fs.read" not in child.policy.tool_names
    with pytest.raises(PolicyViolation):
        kernel.invoke(child, "fs.read", path="/workspace/a.md")
    with pytest.raises(PolicyViolation) as exc:
        kernel.spawn(root, SpawnRequest("again", frozenset({"fs.read"})))
    assert exc.value.verdict.rule == "spawn.privilege_escalation"


def test_restricting_a_child_leaves_its_parent_alone():
    kernel, root = _kernel()
    child = kernel.spawn(root, SpawnRequest("researcher", frozenset({"kb.search", "fs.read"}), budget_fraction=0.4))
    kernel.restrict(child, remove={"kb.search"})
    assert "kb.search" in root.policy.tool_names
    assert kernel.invoke(root, "kb.search", query="q") == "ok"


def test_budget_keeps_only_a_share_of_what_remains():
    kernel, root = _kernel()
    for _ in range(10):
        kernel.invoke(root, "kb.search", query="q")
    kernel.restrict(root, budget_fraction=0.5)
    assert root.ledger.limit.tool_calls == 10 + (250 - 10) // 2
    assert root.policy.budget == root.ledger.limit
    kernel.restrict(root, budget_fraction=0.0)
    with pytest.raises(PolicyViolation) as exc:
        kernel.invoke(root, "kb.search", query="q")
    assert exc.value.verdict.rule == "budget.tool_calls_exceeded"


def test_it_never_widens():
    kernel, root = _kernel()
    for bad in (1.5, -0.1):
        with pytest.raises(PolicyError, match="grant.restrict_widens"):
            kernel.restrict(root, budget_fraction=bad)
    root.ledger.record(usd=9.0)                     # real spend booked past the $5 limit
    before = root.ledger.limit
    kernel.restrict(root, budget_fraction=1.0)
    assert root.ledger.limit.le(before), "an overrun must not raise the limit"
    kernel.restrict(root, remove={"shell.exec"})    # a tool it never held: nothing to take, nothing given
    assert "shell.exec" not in root.policy.tool_names


def test_it_is_audited():
    kernel, root = _kernel()
    kernel.restrict(root, remove={"fs.write", "http.post"}, budget_fraction=0.5, reason="trust 42")
    rec = [r for r in kernel.audit.records if r.tool == "agent.restrict"]
    assert len(rec) == 1 and rec[0].allowed and rec[0].rule == "grant.restricted_subtree"
    assert kernel.audit.verify()


@pytest.mark.parametrize("seed", range(6))
def test_invariants_hold_when_grants_are_restricted_at_random(seed):
    violations = fuzz(load_policy(BASE), steps=350, seed=seed)
    assert not violations, [f"{v.invariant}: {v.detail}" for v in violations]
    assert not afuzz(load_policy(BASE), rounds=20, seed=seed)


def test_the_fuzzers_actually_restrict():
    """So the test above can't pass on a fuzzer that never calls restrict."""
    calls = []
    orig = Kernel.restrict

    def spy(self, grant, **kw):
        calls.append(kw)
        return orig(self, grant, **kw)
    Kernel.restrict = spy
    try:
        fuzz(load_policy(BASE), steps=200, seed=1)
    finally:
        Kernel.restrict = orig
    assert len(calls) > 3
    assert any(kw["remove"] for kw in calls), "some take tools away"
    assert any(kw["budget_fraction"] is not None for kw in calls), "some cut the budget"


def test_a_restriction_that_widened_would_be_caught():
    """Negative control: a restrict that hands a child a tool its parent lost breaks attenuation."""
    policy = load_policy(BASE)
    registry, recorder = build_fixture_registry(policy)
    kernel, root = Kernel(registry), Grant.root(policy, "root")
    child = kernel.spawn(root, SpawnRequest("c", frozenset({"kb.search"}), budget_fraction=0.4))
    root.policy = root.policy.restricted_to(set(root.policy.tool_names - {"kb.search"}))   # parent only
    found = [v for inv in INVARIANTS for v in inv(root, kernel=kernel, recorder=recorder)]
    assert any(v.invariant == "attenuation" for v in found)
    assert child.is_active()
