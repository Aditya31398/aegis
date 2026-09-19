"""Conformance runner.

For every step the runner checks three things, not one:
  1. allowed/denied matches the expectation
  2. on deny, the *rule id* matches exactly (catches a rule firing for the
     wrong reason -- e.g. a budget denial masking a missing capability check)
  3. on deny, the tool implementation was not entered (no side effect leaked)

It also verifies the audit chain after every case and reports which policy
rules were never exercised, so the suite can fail on coverage gaps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.audit import AuditLog
from aegis.decision import PolicyViolation
from aegis.grant import Grant, SpawnRequest
from aegis.kernel import Kernel
from aegis.policy import Policy, load_policy

from .fixtures import SideEffectRecorder, build_fixture_registry
from .spec import Case, Step, Suite, load_suite


@dataclass
class StepResult:
    step: Step
    ok: bool
    observed_rule: str
    message: str = ""


@dataclass
class CaseResult:
    case: Case
    ok: bool
    steps: list[StepResult] = field(default_factory=list)
    audit_intact: bool = True

    @property
    def failures(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok]


@dataclass
class SuiteResult:
    suite: Suite
    cases: list[CaseResult] = field(default_factory=list)
    exercised_rules: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.cases)

    @property
    def failed(self) -> list[CaseResult]:
        return [c for c in self.cases if not c.ok]

    def uncovered_tools(self, policy: Policy) -> list[str]:
        return sorted(policy.tool_names - self.exercised_tools)

    exercised_tools: set[str] = field(default_factory=set)


class ConformanceRunner:
    def __init__(self, root: str | Path = "."):
        self.root = Path(root)

    # ------------------------------------------------------------------
    def run_suite(self, suite: Suite) -> SuiteResult:
        result = SuiteResult(suite=suite)
        for case in suite.cases:
            result.cases.append(self._run_case(case, suite, result))
        return result

    def run_file(self, path: str | Path) -> SuiteResult:
        return self.run_suite(load_suite(path))

    # ------------------------------------------------------------------
    def _run_case(self, case: Case, suite: Suite, agg: SuiteResult) -> CaseResult:
        policy = load_policy(self.root / (case.policy or suite.policy))
        registry, recorder = build_fixture_registry(policy)
        kernel = Kernel(registry, audit=AuditLog())
        root = Grant.root(policy, "root")
        bound: dict[str, Grant] = {"root": root}

        cres = CaseResult(case=case, ok=True)

        for step in case.steps:
            for _ in range(step.repeat):
                sres = self._run_step(kernel, bound, step, recorder, agg)
                cres.steps.append(sres)
                if not sres.ok:
                    cres.ok = False
                agg.exercised_rules.add(sres.observed_rule)
                if step.kind == "invoke":
                    agg.exercised_tools.add(step.tool)

        cres.audit_intact = kernel.audit.verify()
        if not cres.audit_intact:
            cres.ok = False
        return cres

    # ------------------------------------------------------------------
    def _run_step(self, kernel: Kernel, bound: dict[str, Grant], step: Step,
                  recorder: SideEffectRecorder, agg: SuiteResult) -> StepResult:
        grant = bound.get(step.agent)
        if grant is None:
            return StepResult(step, False, "runner.unbound_agent",
                              f"agent alias '{step.agent}' was never bound")

        before = len(recorder.calls)
        observed_rule = "allow.default"
        denied = False
        err = ""

        try:
            if step.kind == "invoke":
                kernel.invoke(grant, step.tool, **step.args)
            elif step.kind == "spawn":
                child = kernel.spawn(grant, SpawnRequest(
                    name=step.name, tools=frozenset(step.tools),
                    budget_fraction=step.budget_fraction))
                bound[step.bind or step.name] = child
            elif step.kind == "revoke":
                kernel.revoke(bound[step.name])
            observed_rule = _last_rule(kernel)
        except PolicyViolation as pv:
            denied = True
            observed_rule = pv.verdict.rule
            err = str(pv)

        want_deny = step.expect == "deny"

        if denied != want_deny:
            return StepResult(
                step, False, observed_rule,
                f"expected {step.expect} but got "
                f"{'deny' if denied else 'allow'}"
                + (f" ({err})" if err else ""))

        if want_deny:
            if step.rule and observed_rule != step.rule:
                return StepResult(
                    step, False, observed_rule,
                    f"denied by '{observed_rule}' but case pins '{step.rule}'")
            # Strong assertion: nothing executed.
            if len(recorder.calls) != before:
                leaked = recorder.calls[before:]
                return StepResult(
                    step, False, observed_rule,
                    f"DENY LEAKED A SIDE EFFECT: {leaked}")

        return StepResult(step, True, observed_rule)


def _last_rule(kernel: Kernel) -> str:
    recs = kernel.audit.records
    return recs[-1].rule if recs else "allow.default"


# ----------------------------------------------------------------------
def format_report(result: SuiteResult) -> str:
    lines = [f"suite: {result.suite.name}  ({result.suite.source})"]
    for c in result.cases:
        mark = "PASS" if c.ok else "FAIL"
        lines.append(f"  [{mark}] {c.case.id} -- {c.case.description}")
        for s in c.failures:
            lines.append(f"        step {s.step.kind}:{s.step.tool or s.step.name}"
                         f" -> {s.message}")
        if not c.audit_intact:
            lines.append("        AUDIT CHAIN BROKEN")
    passed = sum(1 for c in result.cases if c.ok)
    lines.append(f"  {passed}/{len(result.cases)} cases passed")
    return "\n".join(lines)
