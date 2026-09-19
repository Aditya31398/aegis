"""Live MCP ingest: handshake over HTTP and stdio against a local fake."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aegis.adapters import mcp_client
from aegis.adapters.mcp import load_servers
from aegis.adapters.mcp_client import (ForbiddenMethod, McpClientError, _Session,
                                       dump_manifest, fetch_http, fetch_stdio)
from aegis.conformance.cli import main as cli
from aegis.conformance.mcp_checks import mcp_findings

sys.path.insert(0, str(Path(__file__).parent))
from fake_mcp_server import TOOLS, serve_http  # noqa: E402

FAKE = Path(__file__).parent / "fake_mcp_server.py"
LISTING_ONLY = {"initialize", "notifications/initialized", "tools/list", "DELETE"}


@pytest.fixture
def http_server(request):
    kw = getattr(request, "param", {})
    url, received, headers, stop = serve_http(**kw)
    yield url, received, headers
    stop()


# ----------------------------------------------------------------------
# Handshake
# ----------------------------------------------------------------------
@pytest.mark.parametrize("http_server", [{"sse": False}, {"sse": True}],
                         indirect=True, ids=["json", "sse"])
def test_http_handshake_collects_every_page(http_server):
    url, received, headers = http_server
    server = fetch_http(url)
    assert [t.name for t in server.tools] == [t["name"] for t in TOOLS]
    assert server.name == "fake-files"                 # from serverInfo, sanitised
    assert server.live and server.transport == "http"
    # 3 tools at page size 2 -> two tools/list calls, cursor followed.
    assert received.count("tools/list") == 2
    assert set(received) <= LISTING_ONLY


def test_http_session_and_protocol_headers_are_echoed(http_server):
    url, received, headers = http_server
    fetch_http(url)
    after_init = headers[1:]
    assert after_init and all(h.get("mcp-session-id") == "sess-123" for h in after_init)
    assert all(h.get("mcp-protocol-version") == mcp_client.PROTOCOL_VERSION
               for h in after_init)
    assert "application/json" in headers[0]["accept"]
    assert "text/event-stream" in headers[0]["accept"]
    assert "DELETE" in received                        # session torn down


def test_annotations_survive_ingest_and_round_trip(http_server, tmp_path):
    url, *_ = http_server
    server = fetch_http(url)
    by = {t.name: t for t in server.tools}
    assert by["delete_file"].annotations == {"destructiveHint": True}
    path = tmp_path / "m.json"
    path.write_text(json.dumps(dump_manifest([server])), encoding="utf-8")
    replayed = load_servers(path)[0]
    assert {t.name: t.annotations for t in replayed.tools} == \
        {t.name: t.annotations for t in server.tools}


def test_stdio_handshake_ignores_stdout_noise(tmp_path):
    log = tmp_path / "recv.json"
    server = fetch_stdio([sys.executable, str(FAKE)], env={"FAKE_MCP_LOG": str(log)},
                         timeout=20)
    assert [t.name for t in server.tools] == [t["name"] for t in TOOLS]
    assert server.transport == "stdio" and server.live
    assert set(json.loads(log.read_text(encoding="utf-8"))) <= LISTING_ONLY


def test_dump_manifest_never_persists_env_values(tmp_path):
    server = fetch_stdio([sys.executable, str(FAKE)],
                         env={"API_KEY": "sk-live-abcdef"}, timeout=20)
    dumped = json.dumps(dump_manifest([server]))
    assert "sk-live-abcdef" not in dumped
    assert "REDACTED" in dumped


# ----------------------------------------------------------------------
# The audit must never execute a tool
# ----------------------------------------------------------------------
@pytest.mark.parametrize("method", ["tools/call", "resources/read",
                                    "prompts/get", "sampling/createMessage"])
def test_session_refuses_anything_but_listing(method):
    class Boom:
        def send(self, msg):
            raise AssertionError(f"{msg['method']} reached the wire")
    with pytest.raises(ForbiddenMethod):
        _Session(Boom()).request(method, {})


def test_nothing_but_listing_reaches_a_real_server(http_server):
    """Against a real socket, only the listing handshake is sent, even though
    the server exposes a destructive tool. (The CLI test repeats this for a
    full audit run.)"""
    url, received, _ = http_server
    fetch_http(url)
    assert "tools/call" not in received
    assert set(received) <= LISTING_ONLY


# ----------------------------------------------------------------------
# Auth: observed, not inferred
# ----------------------------------------------------------------------
def _auth_findings(server):
    return [f for f in mcp_findings([server])
            if f.category == "unauthenticated_transport"]


def test_anonymous_listing_is_a_witnessed_critical(http_server):
    url, *_ = http_server
    [f] = _auth_findings(fetch_http(url))
    assert f.severity == "critical"
    assert f.witness


@pytest.mark.parametrize("http_server", [{"require_token": "t0k"}], indirect=True)
def test_authenticated_server_is_not_flagged(http_server):
    """Negative control: supplying a credential the server demands must not
    produce the finding the old env-var heuristic would have raised."""
    url, *_ = http_server
    with pytest.raises(McpClientError, match="401"):
        fetch_http(url)                                 # refused without it
    server = fetch_http(url, headers={"Authorization": "Bearer t0k"})
    assert len(server.tools) == 3
    assert _auth_findings(server) == []


# ----------------------------------------------------------------------
# Failure modes
# ----------------------------------------------------------------------
def test_unreachable_server_is_a_clean_error():
    with pytest.raises(McpClientError):
        fetch_http("http://127.0.0.1:9/mcp", timeout=2)


def test_non_http_scheme_rejected():
    with pytest.raises(McpClientError, match="scheme"):
        fetch_http("file:///etc/passwd")


def test_endless_pagination_is_bounded(monkeypatch):
    class Loop:
        def send(self, msg):
            if "id" not in msg:
                return None
            if msg["method"] == "initialize":
                return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
            return {"jsonrpc": "2.0", "id": msg["id"],
                    "result": {"tools": [], "nextCursor": "again"}}
    with pytest.raises(McpClientError, match="did not terminate"):
        mcp_client._handshake(Loop())


def test_sse_without_matching_response_is_an_error():
    body = 'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
    with pytest.raises(McpClientError):
        mcp_client._from_sse(body, 1)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def test_cli_audits_a_live_server_and_saves_replayable_manifest(http_server, tmp_path,
                                                                 capsys):
    url, received, _ = http_server
    out = tmp_path / "out"
    code = cli(["mcp", "--server", url, "--out", str(out), "--fail-on", "critical"])
    assert code == 1                                   # anonymous listing is critical
    assert (out / "audit-report.md").exists()
    assert (out / "hardened-policy.yaml").exists()
    manifest = out / "manifest.json"
    replayed = load_servers(manifest)
    assert len(replayed[0].tools) == 3
    # Replay must reproduce the live findings exactly, or baselines drift.
    live_fp = {f.fingerprint for f in mcp_findings([fetch_http(url)])}
    assert {f.fingerprint for f in mcp_findings(replayed)} == live_fp
    assert "tools/call" not in received
    report = (out / "audit-report.md").read_text(encoding="utf-8")
    assert "unauthenticated_transport" in report or "anonymous" in report


@pytest.mark.parametrize("http_server", [{"require_token": "s3cret"}], indirect=True)
def test_cli_bearer_env_keeps_token_out_of_argv(http_server, tmp_path, monkeypatch):
    url, *_ = http_server
    monkeypatch.setenv("MCP_TOKEN", "s3cret")
    out = tmp_path / "out"
    cli(["mcp", "--server", url, "--bearer-env", "MCP_TOKEN", "--out", str(out)])
    assert "s3cret" not in (out / "manifest.json").read_text(encoding="utf-8")
    assert "s3cret" not in (out / "audit-report.md").read_text(encoding="utf-8")


def test_cli_requires_some_input(tmp_path):
    assert cli(["mcp", "--out", str(tmp_path)]) == 2
