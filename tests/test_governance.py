"""Regression gate for the governance layer: constitution + loophole hunting."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from aegis.constitution import (Constitution, UnconstitutionalPolicy,
                                default_constitution)
from aegis.guards.data import normalize, scan_pii
from aegis.kernel import build_kernel
from aegis.policy import load_policy, parse_policy
from conformance.fixtures import build_fixture_registry
from conformance.loopholes import (SEVERITIES, hunt, metamorphic_findings,
                                   probe_findings, static_findings)
from conformance.spec import load_suite

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "policies" / "base.yaml"
SUITES = sorted((ROOT / "suites").glob("*.yaml"))
BASELINE = ROOT / "loopholes.baseline.yaml"


def _raw():
    return copy.deepcopy(yaml.safe_load(BASE.read_text()))


def _merge(a: dict, b: dict) -> dict:
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _merge(a[k], v)
        else:
            a[k] = v
    return a


# ======================================================================
# Constitution
# ======================================================================
@pytest.mark.parametrize("path", sorted((ROOT / "policies").glob("*.yaml")))
def test_shipped_policies_are_ratified(path):
    policy = load_policy(path)
    registry, _ = build_fixture_registry(policy)
    assert default_constitution().review(policy, registry) == []


def test_kernel_refuses_an_unratified_policy():
    raw = _merge(_raw(), {"budget": {"usd": 0}})
    policy = parse_policy(raw)
    registry, _ = build_fixture_registry(policy)
    with pytest.raises(UnconstitutionalPolicy) as ei:
        build_kernel(policy, registry)
    assert any(v.clause == "C1" for v in ei.value.violations)


@pytest.mark.parametrize("clause,mutation", [
    ("C1", {"budget": {"tokens": 0}}),
    ("C2", {"data": {"egress": {"sinks": ["http.post"]}}}),          # fs.write unscreened
    ("C2", {"data": {"egress": {"block_pii": []}}}),
    ("C4", {"spawn": {"child_budget_fraction": 1.0}}),
    ("C4", {"spawn": {"max_depth": 9}}),
    ("C5", {"data": {"egress": {"max_classification": "confidential"}}}),
    ("C6", {"data": {"egress": {"block_pii": ["email", "passport_number"]}}}),
])
def test_each_clause_rejects_its_violation(clause, mutation):
    """Every clause must actually fire. A clause that can't fail is decoration."""
    policy = parse_policy(_merge(_raw(), mutation))
    registry, _ = build_fixture_registry(policy)
    clauses = {v.clause for v in default_constitution().review(policy, registry)}
    assert clause in clauses, f"{clause} did not fire; saw {sorted(clauses)}"


def test_c7_catches_a_phantom_grant():
    raw = _raw()
    raw["tools"]["allow"].append({"name": "not.registered.anywhere"})
    policy = parse_policy(raw)
    registry, _ = build_fixture_registry(policy)
    # the fixture registry auto-registers policy tools, so use a bare one
    from aegis.registry import ToolRegistry
    clauses = {v.clause for v in default_constitution().review(policy, ToolRegistry())}
    assert "C7" in clauses


def test_constitution_flags_an_unimplemented_clause():
    con = Constitution(version=1, clauses={"C99": {"id": "C99", "enabled": True}})
    policy = load_policy(BASE)
    assert any(v.clause == "C99" for v in con.review(policy))


# ======================================================================
# Loophole hunting
# ======================================================================
def test_no_new_loopholes():
    """The gate. Findings may be accepted in the baseline with a reason;
    anything new at high or above fails."""
    report = hunt(load_policy(BASE), suite_paths=SUITES, baseline=BASELINE)
    blocking = report.blocking("high")
    assert not blocking, "\n".join(str(f) for f in blocking)


def test_baseline_entries_all_have_reasons_and_still_apply():
    raw = yaml.safe_load(BASELINE.read_text())
    report = hunt(load_policy(BASE), suite_paths=SUITES)
    live = {f.fingerprint for f in report.findings}
    for entry in raw["accepted"]:
        assert entry.get("reason", "").strip(), f"{entry['fingerprint']} has no reason"
        assert entry.get("owner"), f"{entry['fingerprint']} has no owner"
        # A stale acceptance hides the fact that the hole is gone.
        assert entry["fingerprint"] in live, (
            f"{entry['fingerprint']} is accepted but no longer found; "
            f"remove it from the baseline")


@pytest.mark.parametrize("mutation,expect_category", [
    # A loosened path prefix must resurface as admitted traversal payloads.
    ({"tools": ("fs.read", "path", "prefix", "/")}, "payload_admitted"),
    # Dropping the SQL denylist must resurface the dangerous SELECTs.
    ({"tools": ("db.query", "sql", "forbid_matches", None)}, "payload_admitted"),
])
def test_weakening_a_constraint_produces_new_findings(mutation, expect_category):
    raw = _raw()
    tool, arg, key, value = mutation["tools"]
    for entry in raw["tools"]["allow"]:
        if entry["name"] == tool:
            if value is None:
                entry["args"][arg].pop(key, None)
            else:
                entry["args"][arg][key] = value
    policy = parse_policy(raw)
    registry, _ = build_fixture_registry(policy)
    cats = {f.category for f in probe_findings(policy, registry)}
    assert expect_category in cats


def test_removing_a_pii_detector_is_caught_statically():
    raw = _merge(_raw(), {"data": {"egress": {"block_pii": ["email", "made_up"]}}})
    policy = parse_policy(raw)
    registry, _ = build_fixture_registry(policy)
    assert any(f.category == "dead_rule"
               for f in static_findings(policy, registry))


def test_unscreened_egress_is_caught_statically():
    raw = _merge(_raw(), {"data": {"egress": {"sinks": ["http.post"]}}})
    policy = parse_policy(raw)
    registry, _ = build_fixture_registry(policy)
    findings = static_findings(policy, registry)
    assert any(f.category == "unscreened_exit" and f.tool == "fs.write"
               for f in findings)


def test_metamorphic_engine_detects_a_planted_bypass():
    """Sanity-check the mutation engine itself: strip normalisation from the
    PII scanner and the zero-width bypass must come back."""
    import aegis.guards.data as data_mod
    original = data_mod.normalize
    data_mod.normalize = lambda t: t                  # plant the regression
    try:
        policy = load_policy(BASE)
        registry, _ = build_fixture_registry(policy)
        steps = [s for p in SUITES for c in load_suite(p).cases for s in c.steps]
        findings = metamorphic_findings(policy, registry, steps)
        assert any(f.category == "mutation_bypass" for f in findings)
    finally:
        data_mod.normalize = original


# ======================================================================
# Normalisation (the fix the hunter prompted)
# ======================================================================
@pytest.mark.parametrize("payload", [
    "asha.rao@example.com",
    "asha.rao@\u200bexample.com",
    "a\u200bs\u200bh\u200ba.rao@example.com",
    "asha·rao@example·com",
    "ＡＳＨＡ.rao@example.com",
    "Y29udGFjdCBhc2hhLnJhb0BleGFtcGxlLmNvbQ==",
])
def test_obfuscated_pii_is_still_detected(payload):
    assert scan_pii(payload, frozenset({"email"}))


def test_normalisation_does_not_create_false_positives():
    assert not scan_pii("row count 42, status ok", frozenset({"email", "phone_in"}))


def test_findings_have_stable_fingerprints():
    a = hunt(load_policy(BASE), suite_paths=SUITES)
    b = hunt(load_policy(BASE), suite_paths=SUITES)
    assert [f.fingerprint for f in a.findings] == [f.fingerprint for f in b.findings]
    assert all(f.severity in SEVERITIES for f in a.findings)
