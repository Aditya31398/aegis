"""Observability hooks and model-spend reservation.

These hooks exist so an external tool (tracing, APM) can correlate and gate,
never so it can change a verdict. The tests pin both halves: the data flows
out, and nothing an observer does can flip a DENY or break the audit chain.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis import (BudgetExhausted, PolicyViolation, SpawnRequest, ToolRegistry, build_kernel,
                   dump_policy, load_policy, parse_policy, policy_digest)
from aegis.observe import current_context, register_context_provider

ROOT = Path(__file__).resolve().parent.parent


def _kernel():
    registry = ToolRegistry()

    @registry.tool("fs.read", effects={"read"}, classification="internal")
    def read_file(path: str) -> str:
        return f"<{path}>"

    return build_kernel(load_policy(ROOT / "examples" / "quickstart-policy.yaml"), registry)


def test_records_unchanged_without_provider():
    kernel, root = _kernel()
    kernel.invoke(root, "fs.read", path="/workspace/a.md")
    assert "ctx" not in kernel.audit.records[-1].details


def test_context_provider_correlates_every_record():
    kernel, root = _kernel()
    off = register_context_provider(lambda: {"run_id": "run-7", "workflow": "support", "bad": object()})
    try:
        kernel.invoke(root, "fs.read", path="/workspace/a.md")
        with pytest.raises(PolicyViolation):
            kernel.invoke(root, "fs.read", path="/etc/passwd")
    finally:
        off()
    for rec in kernel.audit.records:
        assert rec.details["ctx"] == {"run_id": "run-7", "workflow": "support"}  # non-scalars dropped
    assert kernel.audit.verify()
    assert current_context() == {}


def test_failing_provider_cannot_change_a_verdict():
    kernel, root = _kernel()

    def broken():
        raise RuntimeError("tracing backend down")
    off = register_context_provider(broken)
    try:
        with pytest.warns(RuntimeWarning):
            with pytest.raises(PolicyViolation) as exc:
                kernel.invoke(root, "fs.read", path="/etc/passwd")
    finally:
        off()
    assert exc.value.verdict.rule == "capability.arg_prefix"


def test_subscriber_sees_every_decision_and_cannot_break_enforcement():
    kernel, root = _kernel()
    seen = []
    unsub = kernel.audit.subscribe(seen.append)

    def explode(rec):
        raise ValueError("observer bug")
    kernel.audit.subscribe(explode)
    with pytest.warns(RuntimeWarning):
        assert kernel.invoke(root, "fs.read", path="/workspace/a.md") == "</workspace/a.md>"
    with pytest.raises(PolicyViolation):
        kernel.invoke(root, "fs.read", path="/etc/passwd")
    assert [(r.tool, r.allowed, r.rule) for r in seen] == [
        ("fs.read", True, "kernel.admitted"), ("fs.read", False, "capability.arg_prefix")]
    unsub()
    kernel.invoke(root, "fs.read", path="/workspace/b.md")
    assert len(seen) == 2
    assert kernel.audit.verify()


def test_spend_reservation_gates_model_calls_hierarchically():
    kernel, root = _kernel()                               # budget: $1.00, 100k tokens
    r = kernel.reserve_spend(root, usd=0.40, tokens=20_000, label="claude-sonnet-5")
    assert root.ledger.usd == pytest.approx(0.40)
    kernel.settle_spend(r, usd=0.25, tokens=12_000)        # actual was cheaper
    assert root.ledger.usd == pytest.approx(0.25)
    assert root.ledger.tokens == 12_000
    assert root.ledger.tool_calls == 0                     # model spend is not a tool call
    with pytest.raises(BudgetExhausted) as exc:
        kernel.reserve_spend(root, usd=0.80)
    assert exc.value.verdict.rule == "budget.usd_exceeded"
    rules = [rec.rule for rec in kernel.audit.records]
    assert rules == ["budget.reserved", "budget.settled", "budget.usd_exceeded"]
    assert kernel.audit.verify()


def test_settle_records_an_overrun_and_blocks_the_next_call():
    kernel, root = _kernel()
    r = kernel.reserve_spend(root, usd=0.10)
    kernel.settle_spend(r, usd=1.50)                       # the call cost more than the whole budget
    assert root.ledger.usd == pytest.approx(1.50)          # real spend is never under-reported
    with pytest.raises(BudgetExhausted):
        kernel.reserve_spend(root)                         # zero estimate = pre-flight check


def test_child_spend_debits_the_root():
    policy = parse_policy({**dump_policy(load_policy(ROOT / "policies" / "base.yaml"))}, source="base")
    registry = ToolRegistry()
    for name in ("kb.search", "fs.read", "fs.write", "http.get", "http.post", "db.query"):
        registry.register(name, lambda **kw: "ok", effects={"read"})
    from aegis import Kernel, Grant
    kernel, root = Kernel(registry), Grant.root(policy)
    child = kernel.spawn(root, SpawnRequest("researcher", frozenset({"kb.search"}), budget_fraction=0.4))
    r = kernel.reserve_spend(child, usd=0.5)
    kernel.settle_spend(r, usd=0.5)
    assert root.ledger.usd == pytest.approx(0.5)


def test_revoked_grant_cannot_reserve_spend():
    kernel, root = _kernel()
    kernel.revoke(root, reason="watchdog")
    with pytest.raises(PolicyViolation) as exc:
        kernel.reserve_spend(root)
    assert exc.value.verdict.rule == "grant.revoked"
    assert not isinstance(exc.value, BudgetExhausted)


@pytest.mark.parametrize("path", ["policies/base.yaml", "policies/restricted.yaml",
                                  "examples/quickstart-policy.yaml"])
def test_dump_policy_round_trips(path):
    policy = load_policy(ROOT / path)
    assert parse_policy(dump_policy(policy), source="dump") == policy
    assert policy_digest(policy) == policy_digest(parse_policy(dump_policy(policy)))


def test_digest_changes_when_policy_widens():
    policy = load_policy(ROOT / "policies" / "base.yaml")
    wider = dump_policy(policy)
    wider["budget"]["usd"] = 50.0
    assert policy_digest(parse_policy(wider)) != policy_digest(policy)


def test_file_backed_audit_log_is_used(tmp_path):
    """Regression: an empty AuditLog is falsy (it has __len__), and `audit or AuditLog()` replaced it,
    so `AuditLog(path=...)` never wrote its file."""
    from aegis import AuditLog
    path = tmp_path / "audit.jsonl"
    registry = ToolRegistry()
    registry.register("fs.read", lambda path: "x", effects={"read"}, classification="internal")
    log = AuditLog(path=path)
    kernel, root = build_kernel(load_policy(ROOT / "examples" / "quickstart-policy.yaml"), registry, audit=log)
    assert kernel.audit is log
    kernel.invoke(root, "fs.read", path="/workspace/a.md")
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
