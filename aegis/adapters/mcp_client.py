"""Live MCP ingest: fetch a server's tool surface over the wire.

`load_servers` needs someone to export a manifest first. This module removes
that step: point it at a URL (Streamable HTTP) or a command (stdio) and it
performs the real handshake -- `initialize`, `notifications/initialized`, then
paginated `tools/list` -- and returns the same `McpServer` the file loader does.

Two properties matter more than completeness:

* **It can never call a tool.** The session refuses to send any method outside
  `_ALLOWED_METHODS`. An audit that executes the thing it is auditing is not an
  audit, and on a server with a destructive tool it is an incident. This is
  enforced here, in code, not left to the caller's discipline.
* **Auth is observed, not guessed.** For a remote server we record whether it
  answered `tools/list` without any credential. That turns
  "unauthenticated_transport" from a heuristic about a config file into a
  finding with a witness.

Standard library only: `aegis/` stays vendorable.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from typing import Any, Iterable
from urllib.parse import urlparse

from .mcp import McpServer, _tool

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "aegis-audit", "version": "0.1"}

# The whole reason this module is safe to point at a production server.
_ALLOWED_METHODS = frozenset({"initialize", "notifications/initialized", "tools/list"})

MAX_RESPONSE_BYTES = 8 * 1024 * 1024     # a hostile server cannot exhaust memory
MAX_PAGES = 50                           # ...or loop us forever with cursors


class McpClientError(RuntimeError):
    pass


class ForbiddenMethod(McpClientError):
    """Raised if anything asks the audit client to send a non-listing method."""


def _check_method(method: str) -> None:
    if method not in _ALLOWED_METHODS:
        raise ForbiddenMethod(
            f"audit client refuses to send '{method}': only "
            f"{sorted(_ALLOWED_METHODS)} are permitted")


# ----------------------------------------------------------------------
# Transports
# ----------------------------------------------------------------------

class _HttpTransport:
    """MCP Streamable HTTP. Each JSON-RPC message is a POST; the reply is
    either `application/json` or a `text/event-stream` carrying it."""

    def __init__(self, url: str, headers: dict[str, str], timeout: float):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise McpClientError(f"unsupported URL scheme: {parsed.scheme!r}")
        self.url = url
        self.headers = dict(headers)
        self.timeout = timeout
        self.session_id: str | None = None
        self.protocol_version: str | None = None

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None:
        body = json.dumps(message).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                if resp.status == 202 or "id" not in message:
                    return None
                ctype = (resp.headers.get("Content-Type") or "").lower()
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise McpClientError(f"{message.get('method')}: HTTP {exc.code} {exc.reason}"
                                 ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise McpClientError(f"{message.get('method')}: {exc}") from exc

        if len(raw) > MAX_RESPONSE_BYTES:
            raise McpClientError("response exceeds size cap")
        text = raw.decode("utf-8", errors="replace")
        if "text/event-stream" in ctype:
            return _from_sse(text, message["id"])
        return json.loads(text)

    def close(self) -> None:
        if not self.session_id:
            return
        # Polite session teardown. Failure here is irrelevant to the audit.
        req = urllib.request.Request(
            self.url, method="DELETE",
            headers={**self.headers, "Mcp-Session-Id": self.session_id})
        try:
            urllib.request.urlopen(req, timeout=self.timeout).close()
        except Exception:
            pass


def _from_sse(text: str, want_id: Any) -> dict[str, Any]:
    """Pick the JSON-RPC response with our id out of an SSE body. Servers may
    interleave notifications or requests before it; skip those."""
    for event in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip() for line in event.split("\n")
                         if line.startswith("data:"))
        if not data:
            continue
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id and (
                "result" in msg or "error" in msg):
            return msg
    raise McpClientError("event stream ended without a response")


class _StdioTransport:
    """Newline-delimited JSON-RPC over a child process's stdin/stdout.

    This *runs* the server command on the auditor's machine. That is the
    caller's explicit choice (`--server-cmd`); nothing selects it implicitly.
    """

    def __init__(self, argv: list[str], env: dict[str, str] | None, timeout: float):
        self.timeout = timeout
        try:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={**os.environ, **(env or {})}, text=True, encoding="utf-8",
                bufsize=1)
        except OSError as exc:
            raise McpClientError(f"could not start {argv[0]!r}: {exc}") from exc

    def send(self, message: dict[str, Any]) -> dict[str, Any] | None:
        assert self.proc.stdin and self.proc.stdout
        try:
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()
        except OSError as exc:
            raise McpClientError(f"server exited: {exc}") from exc
        if "id" not in message:
            return None
        while True:
            line = self._readline()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue                    # stray log output on stdout
            if isinstance(msg, dict) and msg.get("id") == message["id"] and (
                    "result" in msg or "error" in msg):
                return msg

    def _readline(self) -> str:
        out: list[str] = []
        t = threading.Thread(target=lambda: out.append(self.proc.stdout.readline()),
                             daemon=True)
        t.start()
        t.join(self.timeout)
        if t.is_alive():
            raise McpClientError(f"no response within {self.timeout}s")
        if not out or not out[0]:
            raise McpClientError("server closed stdout")
        if len(out[0]) > MAX_RESPONSE_BYTES:
            raise McpClientError("response exceeds size cap")
        return out[0]

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


# ----------------------------------------------------------------------
# Session
# ----------------------------------------------------------------------

class _Session:
    def __init__(self, transport):
        self.t = transport
        self._next_id = 0

    def request(self, method: str, params: dict | None = None) -> dict[str, Any]:
        _check_method(method)
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            msg["params"] = params
        reply = self.t.send(msg)
        if reply is None:
            raise McpClientError(f"{method}: no response")
        if "error" in reply:
            err = reply["error"] or {}
            raise McpClientError(f"{method}: {err.get('code')} {err.get('message')}")
        return reply.get("result") or {}

    def notify(self, method: str) -> None:
        _check_method(method)
        self.t.send({"jsonrpc": "2.0", "method": method})


def _handshake(transport) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    s = _Session(transport)
    init = s.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": CLIENT_INFO,
    })
    if isinstance(transport, _HttpTransport):
        transport.protocol_version = init.get("protocolVersion") or PROTOCOL_VERSION
    s.notify("notifications/initialized")

    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        page = s.request("tools/list", {"cursor": cursor} if cursor else {})
        tools.extend(t for t in page.get("tools") or [] if isinstance(t, dict) and "name" in t)
        cursor = page.get("nextCursor")
        if not cursor:
            break
    else:
        raise McpClientError(f"tools/list did not terminate within {MAX_PAGES} pages")
    return init, tools


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------

def fetch_http(url: str, *, headers: dict[str, str] | None = None,
               name: str | None = None, timeout: float = 15.0) -> McpServer:
    """Handshake with a Streamable HTTP server and return its tool surface."""
    headers = dict(headers or {})
    t = _HttpTransport(url, headers, timeout)
    try:
        init, tools = _handshake(t)
    finally:
        t.close()
    sent_credentials = any(k.lower() in ("authorization", "cookie", "x-api-key")
                           for k in headers)
    return McpServer(
        name=name or _server_name(init, urlparse(url).hostname or "server"),
        tools=tuple(_tool(x) for x in tools),
        transport="http",
        command=url,
        live=True,
        answered_without_credentials=not sent_credentials,
    )


def fetch_stdio(command: str | list[str], *, env: dict[str, str] | None = None,
                name: str | None = None, timeout: float = 30.0) -> McpServer:
    """Launch a stdio server, handshake, and return its tool surface."""
    argv = shlex.split(command, posix=os.name != "nt") if isinstance(command, str) \
        else list(command)
    if not argv:
        raise McpClientError("empty server command")
    t = _StdioTransport(argv, env, timeout)
    try:
        init, tools = _handshake(t)
    finally:
        t.close()
    return McpServer(
        name=name or _server_name(init, os.path.basename(argv[0])),
        tools=tuple(_tool(x) for x in tools),
        env=dict(env or {}),
        command=argv[0],
        args=tuple(argv[1:]),
        transport="stdio",
        live=True,
    )


def dump_manifest(servers: Iterable[McpServer]) -> dict[str, Any]:
    """Round-trippable bundle, so a live audit can be replayed from disk and
    baselined like any other."""
    return {"servers": [
        {
            "name": s.name,
            "transport": s.transport,
            "command": s.command,
            "live": s.live,
            "answered_without_credentials": s.answered_without_credentials,
            "args": list(s.args),
            # Never persist env values: they are frequently credentials.
            "env": {k: "REDACTED" for k in s.env},
            "tools": [
                {"name": t.name, "description": t.description,
                 "inputSchema": t.input_schema,
                 **({"annotations": t.annotations} if t.annotations else {})}
                for t in s.tools
            ],
        }
        for s in servers
    ]}


def _server_name(init: dict[str, Any], fallback: str) -> str:
    info = init.get("serverInfo") or {}
    raw = str(info.get("name") or fallback)
    # Tool names are qualified as "<server>.<tool>"; keep the prefix clean.
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in raw).strip("-") or "server"


def dedupe_names(servers: list[McpServer]) -> list[McpServer]:
    """Two live servers that report the same serverInfo.name would collide in
    qualified tool names; suffix them."""
    seen: dict[str, int] = {}
    out = []
    for s in servers:
        n = seen.get(s.name, 0)
        seen[s.name] = n + 1
        out.append(s if n == 0 else replace(s, name=f"{s.name}-{n + 1}"))
    return out
