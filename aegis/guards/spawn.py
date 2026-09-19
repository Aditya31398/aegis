from __future__ import annotations

from ..decision import Verdict
from ..grant import Grant
from .base import Call


class SpawnGuard:
    """Structural limits on the agent tree: depth, fan-out, total descendants.

    Checked against the *root* for descendants so a wide-but-shallow swarm is
    caught as well as a deep chain.
    """

    name = "spawn"

    SPAWN_TOOL = "agent.spawn"

    def check(self, grant: Grant, call: Call) -> Verdict:
        if call.tool != self.SPAWN_TOOL:
            return Verdict.allow("spawn.not_applicable", self.name)

        sp = grant.policy.spawn

        if sp.max_depth <= 0:
            return Verdict.deny("spawn.not_permitted",
                                f"'{grant.agent_name}' holds no spawn authority",
                                self.name)

        if grant.depth + 1 > sp.max_depth:
            return Verdict.deny(
                "spawn.max_depth_exceeded",
                f"depth {grant.depth + 1} exceeds max_depth {sp.max_depth}",
                self.name, depth=grant.depth + 1)

        if len(grant.children) + 1 > sp.max_fanout:
            return Verdict.deny(
                "spawn.max_fanout_exceeded",
                f"fan-out {len(grant.children) + 1} exceeds max_fanout {sp.max_fanout}",
                self.name, fanout=len(grant.children) + 1)

        root = grant.root_grant()
        total = len(root.descendants()) + 1
        cap = root.policy.spawn.max_descendants
        if cap and total > cap:
            return Verdict.deny(
                "spawn.max_descendants_exceeded",
                f"tree size {total} exceeds max_descendants {cap}",
                self.name, total=total)

        return Verdict.allow("spawn.permitted", self.name)
