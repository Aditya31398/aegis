"""The regression gate. Everything here is a required CI check."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aegis import Grant, Kernel, PolicyViolation, load_policy, parse_policy
from aegis.conformance import (ConformanceRunner, build_fixture_registry, check_drift,
                         format_report, fuzz, load_suite, widenings)

ROOT = Path(__file__).resolve().parents[1]
SUITES = sorted((ROOT / "suites").glob("*.yaml"))
BASE = ROOT / "policies" / "base.yaml"


# ----------------------------------------------------------------------
# 1. Scenario conformance -- one pytest node per case, so a failure names
#    the exact rule that regressed.
# ----------------------------------------------------------------------
def _all_cases():
    for path in SUITES:
        suite = load_suite(path)
        for case in suite.cases:
            yield pytest.param(path, case.id, id=f"{suite.name}::{case.id}")


@pytest.mark.parametrize("suite_path,case_id", list(_all_cases()))
def test_conformance_case(suite_path, case_id):
    runner = ConformanceRunner(root=ROOT)
    result = runner.run_suite(load_suite(suite_path))
    cres = next(c for c in result.cases if c.case.id == case_id)
    assert cres.ok, format_report(result)
    assert cres.audit_intact


# ----------------------------------------------------------------------
# 2. Coverage -- every tool the policy grants must be exercised somewhere.
# ----------------------------------------------------------------------
def test_every_granted_tool_is_exercised():
    runner = ConformanceRunner(root=ROOT)
    covered: set[str] = set()
    for path in SUITES:
        covered |= runner.run_suite(load_suite(path)).exercised_tools
    policy = load_policy(BASE)
    gaps = sorted(policy.tool_names - covered - {"agent.spawn"})
    assert not gaps, f"no conformance scenario exercises: {gaps}"


# ----------------------------------------------------------------------
# 3. Invariants under random workloads.
# ----------------------------------------------------------------------
@pytest.mark.parametrize("seed", range(12))
def test_invariants_hold_under_fuzz(seed):
    violations = fuzz(load_policy(BASE), steps=350, seed=seed)
    assert not violations, [f"{v.invariant}: {v.detail}" for v in violations]


# ----------------------------------------------------------------------
# 4. Privilege drift -- the check that catches "the policy got weaker".
# ----------------------------------------------------------------------
def test_identical_policy_has_no_drift():
    ok, deltas = check_drift(BASE, BASE)
    assert ok and not deltas


def test_derived_policy_only_narrows():
    base, restricted = load_policy(BASE), load_policy(ROOT / "policies/restricted.yaml")
    assert not widenings(base, restricted)


@pytest.mark.parametrize("mutation,expected_code", [
    ({"tools": {"allow": [{"name": "shell.exec"}]}}, "tools.added"),
    ({"budget": {"usd": 500.0}}, "budget.usd_raised"),
    ({"spawn": {"max_depth": 9}}, "spawn.max_depth_raised"),
    ({"spawn": {"max_fanout": 50}}, "spawn.max_fanout_raised"),
    ({"data": {"max_classification": "restricted"}}, "data.read_ceiling_raised"),
    ({"data": {"egress": {"max_classification": "restricted"}}},
     "data.egress_ceiling_raised"),
    ({"data": {"egress": {"block_pii": ["email"]}}}, "data.pii_check_removed"),
    ({"data": {"egress": {"sinks": []}}}, "data.egress_sink_unmonitored"),
    ({"data": {"egress": {"redact_instead_of_deny": True}}},
     "data.deny_downgraded_to_redact"),
])
def test_widening_is_detected(mutation, expected_code):
    """Each way of weakening the policy must be caught by name."""
    import copy
    import yaml
    raw = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    merged = _deep_merge(copy.deepcopy(raw), mutation)
    if "tools" in mutation:  # append rather than replace the allowlist
        merged["tools"]["allow"] = raw["tools"]["allow"] + mutation["tools"]["allow"]
    candidate = parse_policy(merged)
    codes = {d.code for d in widenings(load_policy(BASE), candidate)}
    assert expected_code in codes, f"missed {expected_code}; saw {sorted(codes)}"


def _deep_merge(a: dict, b: dict) -> dict:
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _deep_merge(a[k], v)
        else:
            a[k] = v
    return a


def test_constraint_relaxation_is_detected():
    import yaml
    raw = yaml.safe_load(BASE.read_text(encoding="utf-8"))
    for entry in raw["tools"]["allow"]:
        if entry["name"] == "fs.read":
            entry["args"]["path"]["prefix"] = "/"          # escape the sandbox
            del entry["args"]["path"]["forbid_matches"]
    codes = {d.code for d in widenings(load_policy(BASE), parse_policy(raw))}
    assert "tools.constraint_relaxed" in codes


# ----------------------------------------------------------------------
# 5. Structural guarantee: exactly one call site reaches a tool impl.
# ----------------------------------------------------------------------
_CALL_SITES = {"_execute", "_aexecute"}


def _execution_path_offenders(files, root):
    """Tool implementations may be touched only inside Kernel._execute and
    Kernel._aexecute. Not just *called* -- any `.fn` attribute access counts,
    because `asyncio.to_thread(spec.fn, ...)` or `functools.partial(spec.fn)`
    is a call site the guard chain never sees."""
    offenders = []
    for py in files:
        tree = ast.parse(py.read_text(encoding="utf-8"))
        allowed: set[int] = set()
        if py.name == "kernel.py":
            for fn in ast.walk(tree):
                if (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and fn.name in _CALL_SITES):
                    allowed |= {id(n) for n in ast.walk(fn)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr == "fn"
                    and id(node) not in allowed):
                offenders.append(f"{py.relative_to(root)}:{node.lineno}")
    return offenders


def test_kernel_is_the_only_execution_path():
    offenders = _execution_path_offenders((ROOT / "aegis").rglob("*.py"), ROOT)
    assert not offenders, f"tool implementations reached outside the kernel: {offenders}"


@pytest.mark.parametrize("src", [
    # smuggled through a thread pool, inside kernel.py but outside a call site
    "import asyncio\nclass Kernel:\n"
    "    async def fast(self, spec):\n        return await asyncio.to_thread(spec.fn)\n",
    # a plain second call site
    "class Kernel:\n    def shortcut(self, spec, a):\n        return spec.fn(**a)\n",
])
def test_execution_path_check_has_teeth(tmp_path, src):
    """Negative control: the check must flag a planted bypass."""
    planted = tmp_path / "kernel.py"
    planted.write_text(src, encoding="utf-8")
    assert _execution_path_offenders([planted], tmp_path)


def test_agent_cannot_reach_raw_callable():
    from aegis.runtime import Agent
    policy = load_policy(BASE)
    registry, rec = build_fixture_registry(policy)
    agent = Agent(Grant.root(policy), Kernel(registry))
    exposed = [v for v in vars(agent).values() if callable(v)]
    assert not exposed
    proxy = agent.tools["fs.read"]
    assert not hasattr(proxy, "fn")
    assert not any("fn" in str(s) for s in getattr(proxy, "__slots__", ()))


# ----------------------------------------------------------------------
# 6. Fail-closed behaviour.
# ----------------------------------------------------------------------
def test_crashing_guard_denies():
    class Exploding:
        name = "boom"

        def check(self, grant, call):
            raise RuntimeError("guard blew up")

    policy = load_policy(BASE)
    registry, rec = build_fixture_registry(policy)
    kernel = Kernel(registry, guards=(Exploding(),))
    with pytest.raises(PolicyViolation) as ei:
        kernel.invoke(Grant.root(policy), "kb.search", query="x")
    assert ei.value.verdict.rule == "guard.internal_error"
    assert rec.calls == []


def test_policy_allowed_but_unregistered_tool_is_denied():
    policy = parse_policy({"name": "t", "tools": {"allow": ["ghost.tool"]},
                           "budget": {"usd": 1, "tokens": 10, "wall_clock_s": 60,
                                      "tool_calls": 10}})
    from aegis.registry import ToolRegistry
    kernel = Kernel(ToolRegistry())
    with pytest.raises(PolicyViolation) as ei:
        kernel.invoke(Grant.root(policy), "ghost.tool")
    assert ei.value.verdict.rule == "registry.unknown_tool"


def test_audit_tampering_is_detected():
    from dataclasses import replace
    policy = load_policy(BASE)
    registry, _ = build_fixture_registry(policy)
    kernel = Kernel(registry)
    grant = Grant.root(policy)
    kernel.invoke(grant, "kb.search", query="a")
    assert kernel.audit.verify()
    kernel.audit._records[0] = replace(kernel.audit._records[0], allowed=False)
    assert not kernel.audit.verify()


def test_sibling_swarm_cannot_outspend_root():
    """Each child is within its own budget; together they must still be capped."""
    policy = load_policy(BASE)
    registry, _ = build_fixture_registry(policy)
    kernel = Kernel(registry)
    root = Grant.root(policy)
    from aegis.grant import SpawnRequest
    kids = [kernel.spawn(root, SpawnRequest(f"k{i}", frozenset({"db.query"}),
                                            budget_fraction=1.0))
            for i in range(3)]
    spent = 0
    for _ in range(300):
        for k in kids:
            try:
                kernel.invoke(k, "db.query", sql="SELECT 1")
                spent += 1
            except PolicyViolation:
                pass
    assert root.ledger.usd <= policy.budget.usd + 1e-9
    assert root.ledger.tool_calls <= policy.budget.tool_calls
