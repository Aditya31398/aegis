"""The README quickstart, runnable. `tests/test_examples.py` executes it, so
the snippet in the README cannot silently rot.

    python examples/quickstart.py
"""
import asyncio
from pathlib import Path

from aegis import Agent, PolicyViolation, ToolRegistry, build_kernel, load_policy

registry = ToolRegistry()


@registry.tool("fs.read", effects={"read"}, classification="internal")
def read_file(path: str) -> str:
    return f"<contents of {path}>"           # your real implementation here


policy = load_policy(Path(__file__).with_name("quickstart-policy.yaml"))
kernel, root = build_kernel(policy, registry)  # refuses an unconstitutional policy
agent = Agent(root, kernel)

print(agent.tools.fs__read(path="/workspace/notes.md"))          # allowed

try:
    agent.tools.fs__read(path="/etc/passwd")                      # never executes
except PolicyViolation as exc:
    print("denied:", exc.verdict.rule)


async def main():
    print(await agent.atools.fs__read(path="/workspace/a.md"))    # async runtimes


asyncio.run(main())
print("audit log intact:", kernel.audit.verify(), f"({len(kernel.audit)} records)")
