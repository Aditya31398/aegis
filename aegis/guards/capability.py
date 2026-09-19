from __future__ import annotations

from ..decision import Verdict
from ..grant import Grant
from .base import Call


class CapabilityGuard:
    """Default-deny tool allowlist with per-argument constraints."""

    name = "capability"

    def check(self, grant: Grant, call: Call) -> Verdict:
        if not grant.is_active():
            return Verdict.deny("grant.revoked",
                                f"grant {grant.grant_id} is revoked", self.name)

        rule = grant.policy.rule_for(call.tool)
        if rule is None:
            return Verdict.deny(
                "capability.not_granted",
                f"tool '{call.tool}' is not in the grant for '{grant.agent_name}'",
                self.name, held=sorted(grant.policy.tool_names))

        missing = [a for a in rule.require_args if a not in call.args]
        if missing:
            return Verdict.deny("capability.missing_arg",
                                f"required args missing: {missing}", self.name)

        if rule.deny_extra_args:
            extra = set(call.args) - set(rule.args)
            if extra and rule.args:
                return Verdict.deny(
                    "capability.unexpected_arg",
                    f"args not permitted by policy: {sorted(extra)}", self.name)

        for arg, constraint in rule.args.items():
            if arg not in call.args:
                continue
            failed = constraint.check(call.args[arg])
            if failed:
                return Verdict.deny(
                    f"capability.arg_{failed}",
                    f"argument '{arg}' violates {failed} constraint on '{call.tool}'",
                    self.name, arg=arg)

        return Verdict.allow("capability.granted", self.name)
