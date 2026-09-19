"""A minimal MCP server for testing live ingest. Not a reference implementation.

HTTP: `serve_http(...)` starts a Streamable HTTP endpoint in a thread.
stdio: `python tests/fake_mcp_server.py` speaks newline-delimited JSON-RPC.

Every received method is recorded, so tests can assert the audit client never
sent anything but the listing handshake.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "read_file", "description": "Read a file from disk.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]},
     "annotations": {"readOnlyHint": True}},
    {"name": "run_query", "description": "Accepts raw SQL and runs it.",
     "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}},
                     "required": ["sql"]}},
    {"name": "delete_file", "description": "Delete a file permanently.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]},
     "annotations": {"destructiveHint": True}},
]


def handle(msg: dict, received: list[str], page_size: int = 2) -> dict | None:
    method = msg.get("method")
    received.append(method)
    if "id" not in msg:
        return None
    rid = msg["id"]
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": msg["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake files", "version": "0"}}}
    if method == "tools/list":
        start = int((msg.get("params") or {}).get("cursor") or 0)
        page = TOOLS[start:start + page_size]
        result: dict = {"tools": page}
        if start + page_size < len(TOOLS):
            result["nextCursor"] = str(start + page_size)
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    if method == "tools/call":
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [
            {"type": "text", "text": "EXECUTED"}]}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found"}}


def serve_http(*, sse: bool = False, require_token: str | None = None,
               session: bool = True):
    """Returns (url, received_methods, seen_headers, shutdown)."""
    received: list[str] = []
    seen_headers: list[dict[str, str]] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_DELETE(self):
            received.append("DELETE")
            self.send_response(204)
            self.end_headers()

        def do_POST(self):
            seen_headers.append({k.lower(): v for k, v in self.headers.items()})
            if require_token and self.headers.get("Authorization") != f"Bearer {require_token}":
                self.send_response(401)
                self.end_headers()
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            reply = handle(body, received)
            if reply is None:
                self.send_response(202)
                self.end_headers()
                return
            self.send_response(200)
            if session and body.get("method") == "initialize":
                self.send_header("Mcp-Session-Id", "sess-123")
            if sse:
                # A notification first, then the response: the client must skip it.
                payload = ("event: message\ndata: " + json.dumps(
                    {"jsonrpc": "2.0", "method": "notifications/progress",
                     "params": {}}) + "\n\n"
                           "event: message\ndata: " + json.dumps(reply) + "\n\n")
                self.send_header("Content-Type", "text/event-stream")
            else:
                payload = json.dumps(reply)
                self.send_header("Content-Type", "application/json")
            data = payload.encode()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    return url, received, seen_headers, srv.shutdown


def main() -> None:
    received: list[str] = []
    print("fake server starting (log noise on stdout)", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        reply = handle(json.loads(line), received)
        if reply is not None:
            print(json.dumps(reply), flush=True)
    # On exit, report what was received so the test can inspect it.
    log = os.environ.get("FAKE_MCP_LOG")
    if log:
        with open(log, "w", encoding="utf-8") as fh:
            json.dump(received, fh)


if __name__ == "__main__":
    main()
