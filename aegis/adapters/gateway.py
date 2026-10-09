"""MCP gateway: the kernel between any MCP client and any MCP server.

An agent that speaks MCP (Claude Code, Claude Desktop, Cursor, an Agent SDK app...) can only reach a tool the
way its client is configured to. Configure it to start

    aegis gateway --policy policy.yaml -- <the server's own command>

instead of the server, and the gateway starts the server, relays the protocol, and runs every `tools/call`
through `Kernel.invoke`: the allowlist and argument constraints, the budget, the data and integrity guards,
the audit log. The tool's registered implementation is a forwarder to the server, called from
`Kernel._execute` like any other, so the server only ever sees calls the kernel admitted. A refusal comes back
as a tool error the model can read.

  * tools/list is filtered to the tools the grant holds: the model is not shown what it may not use.
  * Each server tool is registered with the effects `infer_effects_detailed` finds (annotations may only widen
    them), and a tool that reaches the network counts as untrusted input. The policy is ratified against that
    registry, as `build_kernel` does; until it passes, every call is refused (fail closed) and stderr says why.
  * resources/read, resources/subscribe and prompts/get carry content into the model without a tool call, so
    they are refused unless `allow` names them. A method the gateway doesn't know is refused.
  * Requests the server makes of the client (sampling, roots, elicitation), and notifications both ways, pass
    through untouched.

Speaks newline-delimited JSON-RPC (the MCP stdio transport) on both sides. Standard library only.
"""
from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable

from ..audit import AuditLog
from ..decision import Classification, Effect, PolicyViolation
from ..grant import Grant
from ..kernel import Kernel
from ..policy import Policy
from ..registry import ToolRegistry
from .mcp import _tool, infer_effects_detailed

# relayed as they are (tools/list is filtered on the way back)
PASS = frozenset({"initialize", "ping", "tools/list", "resources/list", "resources/templates/list",
                  "prompts/list", "completion/complete", "logging/setLevel"})
# content into the model without a tool call: only when --allow names the family
GUARDED = {"resources": frozenset({"resources/read", "resources/subscribe", "resources/unsubscribe"}),
           "prompts": frozenset({"prompts/get"})}
METHOD_NOT_FOUND, INTERNAL = -32601, -32603


class UpstreamError(Exception):
    """The server answered a request with a JSON-RPC error."""

    def __init__(self, error: dict):
        self.error = error
        super().__init__(error.get("message", "error"))


class Upstream:
    """The real server: a child process speaking newline-delimited JSON-RPC on its stdin and stdout."""

    def __init__(self, argv: list[str], on_message: Callable[[dict], None], env: dict | None = None):
        exe = shutil.which(argv[0]) or argv[0]          # npx is npx.cmd on Windows
        self.proc = subprocess.Popen([exe, *argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     env=env, bufsize=0)
        self._write_lock = threading.Lock()
        self._lock = threading.Lock()
        self._pending: dict[str, Callable[[dict], None]] = {}
        self._ids = itertools.count(1)
        self._on_message = on_message
        self.closed = threading.Event()
        threading.Thread(target=self._read, name="aegis-upstream", daemon=True).start()

    def send(self, msg: dict) -> None:
        data = (json.dumps(msg) + "\n").encode("utf-8")
        with self._write_lock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def request(self, method: str, params: dict | None, on_reply: Callable[[dict], None]) -> str:
        """Send a request under an id of our own; `on_reply(message)` gets the response."""
        rid = f"aegis-{next(self._ids)}"
        with self._lock:
            self._pending[rid] = on_reply
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return rid

    def call(self, method: str, params: dict | None, timeout: float | None = None) -> Any:
        """A request, waited for: its result, or UpstreamError."""
        done, box = threading.Event(), {}

        def reply(m):
            box["m"] = m
            done.set()
        self.request(method, params, reply)
        if not done.wait(timeout):
            raise UpstreamError({"code": INTERNAL, "message": f"{method}: the server did not answer"})
        m = box["m"]
        if "error" in m:
            raise UpstreamError(m["error"])
        return m.get("result")

    def _read(self) -> None:
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            for m in msg if isinstance(msg, list) else [msg]:
                if not isinstance(m, dict):
                    continue
                if "method" not in m and "id" in m:
                    with self._lock:
                        cb = self._pending.pop(m["id"], None)
                    if cb:
                        cb(m)
                        continue
                self._on_message(m)
        self.closed.set()
        with self._lock:
            pending, self._pending = self._pending, {}
        for cb in pending.values():         # the server is gone: nobody will answer these
            cb({"error": {"code": INTERNAL, "message": "the server exited"}})

    def stop(self, wait: float = 5.0) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(wait)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()


class Gateway:
    """One client session in front of one server. `write(msg)` sends to the client."""

    def __init__(self, policy: Policy, upstream_argv: list[str], write: Callable[[dict], None], *,
                 agent: str | None = None, audit: AuditLog | None = None, prefix: str = "",
                 allow: Iterable[str] = (), classify: dict[str, str] | None = None,
                 log: Callable[[str], None] | None = None, env: dict | None = None, constitution=None):
        self.policy = policy
        self.write = write
        self.prefix = prefix
        self.allowed = frozenset().union(*(GUARDED[a] for a in allow)) if allow else frozenset()
        self.classify = dict(classify or {})
        self.log = log or (lambda s: print(f"aegis gateway: {s}", file=sys.stderr, flush=True))
        self.constitution = constitution
        self.registry = ToolRegistry()
        self.kernel = Kernel(self.registry, audit=audit)
        self.grant = Grant.root(policy, agent or policy.name)
        self.unratified: str | None = "the server's tools have not been listed yet"
        self._tools_lock = threading.Lock()
        self._listed = threading.Event()
        self._client_ids: dict[str, Any] = {}           # our upstream id -> the client's id, for cancellations
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="aegis-call")
        self._local = threading.local()
        self.up = Upstream(upstream_argv, self._from_server, env=env)

    # ---------------------------------------------------------------- client -> server
    def handle(self, msg: dict) -> None:
        method = msg.get("method")
        if method is None:                          # the client's answer to a request the server made
            self.up.send(msg)
            return
        if "id" not in msg:                         # a notification
            if method == "notifications/cancelled":
                rid = (msg.get("params") or {}).get("requestId")
                ours = next((k for k, v in list(self._client_ids.items()) if v == rid), None)
                if ours:
                    msg = dict(msg, params=dict(msg["params"], requestId=ours))
            self.up.send(msg)
            if method == "notifications/initialized":
                self._pool.submit(self._list_tools)
            return
        if method == "tools/call":
            self._pool.submit(self._call, msg)
        elif method in PASS or method in self.allowed:
            self._forward(msg)
        else:
            why = ("refused by the Aegis gateway: content this way reaches the model without a tool call "
                   "(allow it with --allow)" if any(method in g for g in GUARDED.values())
                   else f"the Aegis gateway does not relay {method}")
            self.write({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": METHOD_NOT_FOUND, "message": why}})

    def _forward(self, msg: dict) -> None:
        cid, method = msg["id"], msg["method"]

        def reply(m):
            self._client_ids.pop(rid, None)
            out = {"jsonrpc": "2.0", "id": cid}
            if "error" in m:
                out["error"] = m["error"]
            else:
                result = m.get("result")
                if method == "tools/list" and isinstance(result, dict):
                    self._register(result.get("tools") or ())
                    result = dict(result, tools=[t for t in result.get("tools") or () if self._holds(t.get("name"))])
                out["result"] = result
            self.write(out)
        rid = self.up.request(method, msg.get("params"), reply)
        self._client_ids[rid] = cid

    # ---------------------------------------------------------------- server -> client
    def _from_server(self, msg: dict) -> None:
        if msg.get("method") == "notifications/tools/list_changed":
            self._listed.clear()
            self._pool.submit(self._list_tools)
        self.write(msg)

    # ---------------------------------------------------------------- tools
    def _holds(self, name: Any) -> bool:
        return isinstance(name, str) and (self.prefix + name) in self.grant.policy.tool_names

    def _list_tools(self) -> None:
        """Every page of the server's tools, registered, then the policy ratified against them."""
        try:
            tools, cursor = [], None
            while True:
                page = self.up.call("tools/list", {"cursor": cursor} if cursor else {}, timeout=60) or {}
                tools += page.get("tools") or []
                cursor = page.get("nextCursor")
                if not cursor:
                    break
            self._register(tools)
        except Exception as exc:                     # noqa: BLE001 -- refused below, never allowed
            self.unratified = f"could not list the server's tools: {exc}"
            self.log(self.unratified)
        finally:
            self._listed.set()

    def _register(self, tools: Iterable[dict]) -> None:
        with self._tools_lock:
            new = [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)
                   and self.registry.spec(self.prefix + t["name"]) is None]
            for t in new:
                name = self.prefix + t["name"]
                effects = infer_effects_detailed(_tool(t)).effects
                self.registry.register(
                    name, self._forwarder(t["name"]), effects={e.value for e in effects},
                    classification=Classification.parse(self.classify.get(name, "public")),
                    description=t.get("description") or "",
                    untrusted=Effect.NETWORK in effects or (t.get("annotations") or {}).get("openWorldHint") is True)
            if new or self.unratified:
                self._ratify()

    def _ratify(self) -> None:
        from ..constitution import default_constitution
        try:
            (self.constitution or default_constitution()).ratify(self.policy, self.registry)
        except Exception as exc:                     # noqa: BLE001 -- PolicyError and friends: fail closed
            self.unratified = f"the policy does not ratify against this server's tools: {exc}"
            self.log(self.unratified)
            return
        self.unratified = None

    def _forwarder(self, server_name: str) -> Callable[..., Any]:
        def forward(**arguments):
            params = {"name": server_name, "arguments": arguments}
            meta = getattr(self._local, "meta", None)
            if meta:
                params["_meta"] = meta
            return self.up.call("tools/call", params)
        forward.__name__ = f"mcp:{server_name}"
        return forward

    def _call(self, msg: dict) -> None:
        cid = msg["id"]
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        try:
            if not isinstance(name, str) or not isinstance(args, dict):
                return self.write({"jsonrpc": "2.0", "id": cid, "error": {
                    "code": -32602, "message": "tools/call needs a name and an arguments object"}})
            self._listed.wait(60)
            if self.unratified:
                return self._refuse(cid, name, "gateway.not_ratified", self.unratified)
            self._local.meta = params.get("_meta")
            try:
                result = self.kernel.invoke(self.grant, self.prefix + name, **args)
            finally:
                self._local.meta = None
            self.write({"jsonrpc": "2.0", "id": cid, "result": result})
        except PolicyViolation as v:
            self._refuse(cid, name, v.verdict.rule, v.verdict.reason)
        except UpstreamError as e:
            self.write({"jsonrpc": "2.0", "id": cid, "error": e.error})
        except Exception as exc:                     # noqa: BLE001 -- the client must get an answer
            self.write({"jsonrpc": "2.0", "id": cid, "error": {"code": INTERNAL, "message": f"aegis gateway: {exc}"}})

    def _refuse(self, cid: Any, name: Any, rule: str, reason: str) -> None:
        self.log(f"refused {name} ({rule}): {reason}")
        self.write({"jsonrpc": "2.0", "id": cid, "result": {
            "content": [{"type": "text", "text": f"Refused by Aegis ({rule}): {reason}"}], "isError": True}})

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        self.up.stop()


def run(policy: Policy, upstream_argv: list[str], *, stdin=None, stdout=None, **kw) -> int:
    """Serve one client on stdin/stdout until it hangs up (or the server exits). Returns an exit code."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    lock = threading.Lock()

    def write(msg: dict) -> None:
        data = (json.dumps(msg) + "\n").encode("utf-8")
        with lock:
            try:
                stdout.write(data)
                stdout.flush()
            except (OSError, ValueError):
                pass                                 # the client is gone

    gw = Gateway(policy, upstream_argv, write, env=dict(os.environ), **kw)
    stop = threading.Event()
    threading.Thread(target=lambda: (gw.up.closed.wait(), stop.set()), daemon=True).start()

    def pump():
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            for m in msg if isinstance(msg, list) else [msg]:
                if isinstance(m, dict):
                    gw.handle(m)
        stop.set()
    threading.Thread(target=pump, name="aegis-client", daemon=True).start()
    stop.wait()
    gw.close()
    return 0
