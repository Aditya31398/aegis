"""Runnable end-to-end demo:  python examples/demo.py

A supervisor reads data and delegates to workers. Every attempt to step
outside the policy is refused by the kernel, regardless of what the agent
code tries to do.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis import Agent, Grant, Kernel, PolicyViolation, load_policy
from aegis.decision import Classification, Effect
from aegis.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]
registry = ToolRegistry()


@registry.tool("kb.search", effects={Effect.READ},
               classification=Classification.INTERNAL, cost_usd=0.001,
               description="Search the internal knowledge base")
def kb_search(query: str):
    return [f"result for {query!r}"]


@registry.tool("fs.read", effects={Effect.READ},
               classification=Classification.INTERNAL,
               description="Read a file under /workspace")
def fs_read(path: str):
    return f"<contents of {path}>"


@registry.tool("db.query", effects={Effect.READ},
               classification=Classification.CONFIDENTIAL, cost_usd=0.02,
               description="Read-only SQL against the analytics replica")
def db_query(sql: str):
    return [{"id": 1, "email": "asha.rao@example.com"}]


@registry.tool("http.get", effects={Effect.NETWORK, Effect.EGRESS},
               description="GET the internal API")
def http_get(url: str):
    return {"status": 200}


@registry.tool("http.post", effects={Effect.NETWORK, Effect.EGRESS},
               cost_usd=0.01, description="POST to the internal API")
def http_post(url: str, body: str):
    return {"status": 202}


@registry.tool("fs.write", effects={Effect.WRITE, Effect.EGRESS},
               description="Write under /workspace/out")
def fs_write(path: str, content: str):
    return {"written": len(content)}


class Supervisor(Agent):
    def run(self):
        print(f"\n{self!r}")
        print("tool manifest given to the model:",
              [t["name"] for t in self.tools.manifest()])

        attempt(lambda: self.tools["kb.search"](query="onboarding docs"),
                "search the knowledge base")
        attempt(lambda: self.tools["fs.read"](path="/workspace/plan.md"),
                "read an in-sandbox file")
        attempt(lambda: self.tools["fs.read"](path="/etc/passwd"),
                "read outside the sandbox")
        attempt(lambda: self.tools["http.get"](url="https://evil.example.com/x"),
                "call an external host")

        worker = self.spawn("researcher", tools=["kb.search", "fs.read"])
        print(f"\nspawned {worker!r}")
        attempt(lambda: worker.tools["kb.search"](query="pricing"),
                "worker uses a delegated tool")
        attempt(lambda: worker.tools["db.query"](sql="SELECT 1"),
                "worker reaches for a tool it was never given")
        attempt(lambda: worker.spawn("rogue", tools=["fs.write"]),
                "worker tries to escalate a child above itself")

        attempt(lambda: self.tools["db.query"](sql="SELECT * FROM customers"),
                "read confidential data (taints the agent)")
        attempt(lambda: self.tools["http.post"](
            url="https://api.internal.corp/v1/sink", body="summary"),
                "egress after touching confidential data")


def attempt(fn, label: str):
    try:
        fn()
        print(f"  ALLOW  {label}")
    except PolicyViolation as pv:
        print(f"  DENY   {label}\n           -> {pv.verdict.rule}: {pv.verdict.reason}")


if __name__ == "__main__":
    policy = load_policy(ROOT / "policies" / "base.yaml")
    kernel = Kernel(registry)
    sup = Supervisor(Grant.root(policy, "supervisor"), kernel)
    sup.run()

    print(f"\naudit: {len(kernel.audit)} records, "
          f"{len(kernel.audit.denials())} denials, "
          f"chain intact = {kernel.audit.verify()}")
    print(f"spend: ${sup.grant.ledger.usd:.4f} / ${policy.budget.usd:.2f}, "
          f"calls {sup.grant.ledger.tool_calls}/{policy.budget.tool_calls}")
