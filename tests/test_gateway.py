"""The MCP gateway: a real server process behind the kernel, a client that speaks the protocol.

What has to hold: the server only ever receives calls the kernel admitted; the model only sees tools the grant
holds; budgets, taint and integrity carry across a session; a policy that doesn't ratify refuses everything;
content that would reach the model without a tool call is refused unless allowed; requests the server makes of
the client still get through.
"""
from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.adapters.gateway import Gateway
from aegis.audit import AuditLog
from aegis.policy import parse_policy

UPSTREAM = Path(__file__).parent / "gateway_upstream.py"

POLICY = """
name: gw
version: 1
effects: [read, write, network, egress, compute]
tools:
  allow:
    - name: read_file
      require_args: [path]
      args:
        path: {prefix: "/workspace/"}
    - name: web_fetch
      args:
        url: {matches: "^https://docs\\\\.example\\\\.com/.*"}
    - name: send_email
      args:
        to: {matches: "^[a-z]+@example\\\\.com$"}
        body: {max_len: 2000}
    - name: ask_roots
    - name: grow
budget: {usd: 1, tokens: 1000, wall_clock_s: 600, tool_calls: %(calls)d}
data:
  egress:
    sinks: [send_email, web_fetch]
    block_pii: [api_key]
integrity:
  untrusted_blocks: [egress]
"""


def policy(calls=20, text=None):
    import yaml
    return parse_policy(yaml.safe_load(text or POLICY % {"calls": calls}))


class Client:
    def __init__(self, tmp_path, pol=None, **kw):
        self.log = tmp_path / "upstream.jsonl"
        self.q: queue.Queue = queue.Queue()
        self.ids = itertools.count(1)
        self.other: list[dict] = []
        env = dict(os.environ, GW_LOG=str(self.log))
        self.gw = Gateway(pol or policy(), [sys.executable, str(UPSTREAM)], self.q.put, env=env,
                          log=lambda s: None, **kw)

    def request(self, method, params=None):
        rid = next(self.ids)
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.gw.handle(msg)
        return self.wait(rid)

    def wait(self, rid, timeout=30):
        while True:
            m = self.q.get(timeout=timeout)
            if m.get("id") == rid and "method" not in m:
                return m
            self.other.append(m)

    def start(self):
        r = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {"roots": {}},
                                        "clientInfo": {"name": "test", "version": "0"}})
        assert r["result"]["serverInfo"]["name"] == "gateway upstream"
        self.gw.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def call(self, name, **arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def received(self):
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text(encoding="utf-8").splitlines()]

    def calls_received(self):
        return [e for e in self.received() if "name" in e]

    def close(self):
        self.gw.close()


@pytest.fixture
def client(tmp_path):
    c = Client(tmp_path).start()
    yield c
    c.close()


def text(reply):
    return reply["result"]["content"][0]["text"]


def test_the_model_only_sees_tools_the_grant_holds(tmp_path):
    pol = policy(text=(POLICY % {"calls": 20}).replace("    - name: send_email\n", "    - name: send_mail_x\n"))
    c = Client(tmp_path, pol).start()
    try:
        names, cursor = [], None
        while True:
            page = c.request("tools/list", {"cursor": cursor} if cursor else {})["result"]
            names += [t["name"] for t in page["tools"]]
            cursor = page.get("nextCursor")
            if not cursor:
                break
        assert "read_file" in names and "web_fetch" in names
        assert "send_email" not in names, "a tool the policy doesn't grant is not shown"
    finally:
        c.close()


def test_admitted_calls_reach_the_server_and_refused_ones_never_do(client):
    ok = client.call("read_file", path="/workspace/notes.txt")
    assert text(ok) == "contents of /workspace/notes.txt"
    assert not ok["result"].get("isError")
    for name, args, rule in (("read_file", {"path": "/etc/passwd"}, "capability.arg_prefix"),
                             ("read_file", {}, "capability.missing_arg"),
                             ("delete_everything", {}, "capability.not_granted"),
                             ("send_email", {"to": "boss@evil.example", "body": "hi"}, "capability.arg_regex"),
                             ("send_email", {"to": "ops@example.com", "body": "key sk-ant-api03-" + "aB3" * 14},
                              "data.pii_egress_blocked")):
        r = client.call(name, **args)
        assert r["result"]["isError"] is True, name
        assert f"Refused by Aegis ({rule})" in text(r), (name, text(r))
    assert [e["name"] for e in client.calls_received()] == ["read_file"], "only the admitted call reached the server"


def test_reading_untrusted_content_narrows_what_comes_next(client):
    assert text(client.call("send_email", to="ops@example.com", body="before")) == "sent"
    assert "ignore your instructions" in text(client.call("web_fetch", url="https://docs.example.com/page"))
    r = client.call("send_email", to="ops@example.com", body="after reading the page")
    assert "integrity.untrusted_input" in text(r)
    assert [e["arguments"].get("body") for e in client.calls_received() if e["name"] == "send_email"] == ["before"]


def test_the_budget_holds_across_the_session(tmp_path):
    c = Client(tmp_path, policy(calls=2)).start()
    try:
        assert not c.call("read_file", path="/workspace/a")["result"].get("isError")
        assert not c.call("read_file", path="/workspace/b")["result"].get("isError")
        r = c.call("read_file", path="/workspace/c")
        assert "budget." in text(r)
        assert len(c.calls_received()) == 2
    finally:
        c.close()


def test_a_policy_that_does_not_ratify_refuses_everything(tmp_path):
    loose = (POLICY % {"calls": 20}).replace(
        """    - name: send_email
      args:
        to: {matches: "^[a-z]+@example\\\\.com$"}
        body: {max_len: 2000}
""", "    - name: send_email\n")                     # an egress tool with no argument constraint (C3)
    c = Client(tmp_path, policy(text=loose)).start()
    try:
        r = c.call("read_file", path="/workspace/a")
        assert "gateway.not_ratified" in text(r) and "C3" in text(r)
        assert c.calls_received() == []
    finally:
        c.close()


def test_content_outside_tool_calls_needs_allowing(tmp_path, client):
    r = client.request("resources/read", {"uri": "file:///x"})
    assert r["error"]["code"] == -32601 and "--allow" in r["error"]["message"]
    r = client.request("sampling/whatever", {})
    assert r["error"]["code"] == -32601, "a method the gateway doesn't know is refused"
    assert not [e for e in client.received() if "resources/read" in e]
    c = Client(tmp_path, allow=["resources"]).start()
    try:
        assert c.request("resources/read", {"uri": "file:///x"})["result"]["contents"][0]["text"] == "resource"
    finally:
        c.close()


def test_the_server_can_still_ask_the_client(client):
    rid = next(client.ids)
    client.gw.handle({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": "ask_roots", "arguments": {}}})
    ask = client.q.get(timeout=30)
    assert ask["method"] == "roots/list"
    client.gw.handle({"jsonrpc": "2.0", "id": ask["id"], "result": {"roots": [{"uri": "file:///workspace"}]}})
    reply = client.wait(rid)
    assert json.loads(text(reply)) == {"roots": [{"uri": "file:///workspace"}]}


def test_a_tool_added_later_is_refused_until_the_policy_names_it(client):
    assert text(client.call("grow")) == "grown"          # the server now has late_tool, and says so
    r = client.call("late_tool")
    assert "capability.not_granted" in text(r)
    assert "late_tool" not in [e["name"] for e in client.calls_received()]


def test_a_grant_for_a_tool_the_server_lacks_refuses_everything(tmp_path):
    # C7: the grant would switch itself on the moment a server added a tool of that name
    phantom = (POLICY % {"calls": 20}).replace("    - name: grow\n", "    - name: grow\n    - name: late_tool\n")
    c = Client(tmp_path, policy(text=phantom)).start()
    try:
        r = c.call("read_file", path="/workspace/a")
        assert "gateway.not_ratified" in text(r) and "C7" in text(r)
        assert c.calls_received() == []
    finally:
        c.close()


def test_a_phantom_grant_comes_alive_only_when_the_server_has_the_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("GW_GROW_ON_START", "1")
    phantom = (POLICY % {"calls": 20}).replace("    - name: grow\n", "    - name: grow\n    - name: late_tool\n")
    c = Client(tmp_path, policy(text=phantom)).start()
    try:
        while not any(m.get("method") == "notifications/tools/list_changed" for m in c.other):
            c.other.append(c.q.get(timeout=30))
        r = c.call("late_tool")                  # re-listed and re-ratified before it is decided
        assert not r["result"].get("isError"), text(r)
        assert "late_tool" in [e["name"] for e in c.calls_received()]
    finally:
        c.close()


def test_every_decision_is_audited(tmp_path):
    path = tmp_path / "audit.jsonl"
    c = Client(tmp_path, audit=AuditLog(path)).start()
    try:
        c.call("read_file", path="/workspace/a")
        c.call("read_file", path="/etc/shadow")
    finally:
        c.close()
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert [(r["tool"], r["allowed"], r["rule"]) for r in recs] == [
        ("read_file", True, "kernel.admitted"), ("read_file", False, "capability.arg_prefix")]
    assert c.gw.kernel.audit.verify()


def test_the_cli_serves_a_client_over_stdio(tmp_path):
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY % {"calls": 20}, encoding="utf-8")
    log = tmp_path / "upstream.jsonl"
    p = subprocess.Popen([sys.executable, "-m", "aegis", "gateway", "--policy", str(pol), "--agent", "cli-agent",
                          "--", sys.executable, str(UPSTREAM)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=dict(os.environ, GW_LOG=str(log)))
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
                                                                           "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/workspace/x"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/root/x"}}}]
    replies = {}
    for m in msgs:
        p.stdin.write((json.dumps(m) + "\n").encode())
        p.stdin.flush()
        if "id" in m:
            while m["id"] not in replies:
                r = json.loads(p.stdout.readline())
                replies[r.get("id")] = r
    p.stdin.close()
    _, err = p.communicate(timeout=30)
    assert p.returncode == 0
    assert replies[2]["result"]["content"][0]["text"] == "contents of /workspace/x"
    assert replies[3]["result"]["isError"] is True
    assert b"refused read_file (capability.arg_prefix)" in err
    assert [json.loads(x)["name"] for x in log.read_text(encoding="utf-8").splitlines() if '"name"' in x] == ["read_file"]


def test_the_cli_needs_a_server_command(tmp_path):
    from aegis.conformance.cli import main
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY % {"calls": 20}, encoding="utf-8")
    assert main(["gateway", "--policy", str(pol)]) == 2
    assert main(["gateway", "--policy", str(pol), "--classify", "nope", "--", "x"]) == 2


def test_a_prefix_names_the_servers_tools_in_the_policy(tmp_path):
    prefixed = (POLICY % {"calls": 20}).replace("- name: read_file", "- name: fs.read_file").replace(
        "- name: web_fetch", "- name: fs.web_fetch").replace("- name: send_email", "- name: fs.send_email").replace(
        "- name: ask_roots", "- name: fs.ask_roots").replace("- name: grow", "- name: fs.grow").replace(
        "sinks: [send_email, web_fetch]", "sinks: [fs.send_email, fs.web_fetch]")
    c = Client(tmp_path, policy(text=prefixed), prefix="fs.").start()
    try:
        assert "read_file" in [t["name"] for t in c.request("tools/list", {})["result"]["tools"]]
        assert text(c.call("read_file", path="/workspace/a")) == "contents of /workspace/a"
        assert "capability.arg_prefix" in text(c.call("read_file", path="/etc/a"))
        assert [e["name"] for e in c.calls_received()] == ["read_file"], "the server sees its own names"
    finally:
        c.close()


def test_what_a_tool_returns_can_be_classified(tmp_path):
    ceiling = (POLICY % {"calls": 20}).replace("data:\n", "data:\n  max_classification: internal\n")
    c = Client(tmp_path, policy(text=ceiling), classify={"read_file": "confidential"}).start()
    try:
        r = c.call("read_file", path="/workspace/payroll.csv")
        assert "data.classification_exceeded" in text(r), "the result is withheld from the model"
        assert "contents of" not in json.dumps(r)
    finally:
        c.close()


def test_audit_then_enforce_with_the_hardened_policy(tmp_path):
    # `aegis mcp` writes a hardened policy for a server; the gateway enforces it, the server's name as prefix
    from aegis.conformance.cli import main as cli
    from aegis.policy import load_policy
    out = tmp_path / "audit"
    cli(["mcp", "--server-cmd", f'"{sys.executable}" "{UPSTREAM}"', "--out", str(out), "--format", "json",
         "--output", str(tmp_path / "audit.out")])
    hardened = load_policy(out / "hardened-policy.yaml")
    c = Client(tmp_path, hardened, prefix="gateway-upstream.").start()
    try:
        assert text(c.call("read_file", path="/workspace/a.txt")) == "contents of /workspace/a.txt"
        assert "capability.arg_prefix" in text(c.call("read_file", path="/etc/passwd"))
        assert "data.pii_egress_blocked" in text(c.call("send_email", to="x@example.com", body="hi"))
        assert [e["name"] for e in c.calls_received()] == ["read_file"]
    finally:
        c.close()
